package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ECSVersion is the Elastic Common Schema version the "ecs" format follows.
const ECSVersion = "8.11.0"

// ecsFieldNames maps the attribute keys used across the code base to their
// ECS field. Keys not listed here go under "openconsole.<key>", so they can
// never collide with ECS objects or with the kubernetes.* / container.*
// metadata a shipper adds (the namespace / pod / container in our records
// are the ones acted on, not the pod that wrote the log line). Keys that
// already contain a dot are taken as deliberate ECS paths.
var ecsFieldNames = map[string]string{
	"service":        "service.name",
	"version":        "service.version",
	"env":            "service.environment",
	"user":           "user.name",
	"user_agent":     "user_agent.original",
	"error":          "error.message",
	"err":            "error.message", // klog / logr
	"event":          "event.action",
	"reason":         "event.reason",
	"method":         "http.request.method",
	"status":         "http.response.status_code",
	"path":           "url.path",
	"remote_ip":      "source.ip",
	"request_id":     "http.request.id",
	"trace_id":       "trace.id",
	"duration_ns":    "event.duration",
	"response_bytes": "http.response.body.bytes",
}

// ecsHandler writes one JSON object per record with nested ECS objects, in a
// stable order: @timestamp, log, message, service, ecs, event, then the rest.
// HTTP request and audit records also get event.* (kind, category, type,
// outcome, dataset) and a readable message, like other ECS-logging services.
type ecsHandler struct {
	mu        *sync.Mutex
	w         io.Writer
	level     slog.Leveler
	addSource bool
	attrs     []slog.Attr // from WithAttrs, applied before the record's own
	prefix    string      // from WithGroup
}

// NewECSHandler returns the handler behind LOG_FORMAT=ecs, writing to w.
func NewECSHandler(w io.Writer, opts *slog.HandlerOptions) slog.Handler {
	return newECSHandler(w, opts)
}

func newECSHandler(w io.Writer, opts *slog.HandlerOptions) *ecsHandler {
	h := &ecsHandler{mu: &sync.Mutex{}, w: w, level: slog.LevelInfo}
	if opts != nil {
		if opts.Level != nil {
			h.level = opts.Level
		}
		h.addSource = opts.AddSource
	}
	return h
}

func (h *ecsHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level.Level() }

func (h *ecsHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := *h
	c.attrs = append(append([]slog.Attr{}, h.attrs...), prefixed(h.prefix, attrs)...)
	return &c
}

func (h *ecsHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	c := *h
	c.prefix = h.prefix + name + "."
	return &c
}

func prefixed(prefix string, attrs []slog.Attr) []slog.Attr {
	if prefix == "" {
		return attrs
	}
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		out[i] = slog.Attr{Key: prefix + a.Key, Value: a.Value}
	}
	return out
}

func (h *ecsHandler) Handle(_ context.Context, r slog.Record) error {
	doc := newObject()
	doc.set("@timestamp", r.Time.UTC().Format("2006-01-02T15:04:05.000000Z"))
	doc.set("log.level", strings.ToLower(r.Level.String()))
	doc.set("message", r.Message)
	if h.addSource && r.PC != 0 {
		frame, _ := runtime.CallersFrames([]uintptr{r.PC}).Next()
		doc.set("log.origin.function", frame.Function)
		doc.set("log.origin.file.name", frame.File)
		doc.set("log.origin.file.line", frame.Line)
	}

	raw := map[string]any{} // the record's own attributes by original key
	add := func(a slog.Attr) {
		v := plain(a.Value)
		if a.Key == "" || v == nil {
			return
		}
		path := ecsPath(a.Key)
		if !doc.set(path, v) {
			doc.set("openconsole."+strings.ReplaceAll(a.Key, ".", "_"), v)
		}
	}
	for _, a := range h.attrs {
		add(a)
	}
	doc.set("ecs.version", ECSVersion)
	r.Attrs(func(a slog.Attr) bool {
		a = slog.Attr{Key: h.prefix + a.Key, Value: a.Value}
		raw[a.Key] = plain(a.Value)
		add(a)
		return true
	})
	enrich(doc, r.Message, raw)

	var buf bytes.Buffer
	doc.encode(&buf)
	buf.WriteByte('\n')
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.w.Write(buf.Bytes())
	return err
}

func ecsPath(key string) string {
	if name, ok := ecsFieldNames[key]; ok {
		return name
	}
	if strings.Contains(key, ".") {
		return key
	}
	return "openconsole." + key
}

// enrich adds the event.* fields and the readable message for the two record
// kinds dashboards care about.
func enrich(doc *object, msg string, raw map[string]any) {
	switch msg {
	case "http.request":
		status, _ := raw["status"].(int64)
		doc.set("message", fmt.Sprintf("%v %v %d", raw["method"], raw["path"], status))
		doc.set("log.logger", "http")
		doc.set("event.kind", "event")
		doc.set("event.category", []string{"web"})
		doc.set("event.type", []string{"access"})
		if status >= 400 {
			doc.set("event.outcome", "failure")
		} else {
			doc.set("event.outcome", "success")
		}
		doc.set("event.dataset", "openconsole.app")
	case "audit":
		action, _ := raw["event"].(string)
		verb, _ := raw["verb"].(string)
		kind, _ := raw["resource_type"].(string)
		doc.set("message", auditMessage(raw))
		doc.set("log.logger", "audit")
		doc.set("event.kind", "event")
		if c := auditCategory(action, kind, verb); c != "" {
			doc.set("event.category", []string{c})
		}
		phase, _ := raw["phase"].(string)
		if t := AuditEventType(verb, phase); t != "" {
			doc.set("event.type", []string{t})
		}
		switch raw["outcome"] {
		case "success":
			doc.set("event.outcome", "success")
		case nil, "":
		default:
			doc.set("event.outcome", "failure")
		}
		doc.set("event.dataset", "openconsole.audit")
	default:
		doc.set("event.dataset", "openconsole.app")
	}
}

// auditEventTypes maps an audit verb to ECS event.type.
var auditEventTypes = map[string]string{
	"list": "access", "get": "access", "logs": "access", "view_yaml": "access",
	"reveal": "access", "view": "access", "view_overview": "access", "download": "access", "export": "access",
	"restart": "change", "scale": "change", "apply": "change", "update": "change",
	"share": "change", "select": "change", "activate": "change", "deactivate": "change",
	"change_password": "change", "reset_password": "change",
	"create": "creation", "import": "creation",
	"delete": "deletion", "evict": "deletion", "purge": "deletion", "revoke": "deletion",
	"login": "start",
}

// AuditEventType returns the ECS event.type for an audit verb; a shell
// (exec) is start or end by its phase. "" for an unknown verb.
func AuditEventType(verb, phase string) string {
	if verb == "exec" {
		if phase == "end" {
			return "end"
		}
		return "start"
	}
	return auditEventTypes[verb]
}

// auditCategory returns the ECS event.category of an audit event.
func auditCategory(action, kind, verb string) string {
	switch {
	case action == "user.login":
		return "authentication"
	case kind == "session":
		return "session"
	case action == "pod.exec":
		return "process"
	case kind == "user" || kind == "group" || kind == "role" || kind == "permission":
		return "iam"
	}
	switch auditEventTypes[verb] {
	case "change", "creation", "deletion":
		return "configuration"
	}
	return ""
}

// auditMessage reads like
// "admin: deployment.restart success boh-cy/boh on Zenia-NonProd". It is for
// people; filters use the fields.
func auditMessage(raw map[string]any) string {
	str := func(k string) string { s, _ := raw[k].(string); return s }
	target := str("resource_name")
	if ns := str("namespace"); ns != "" && ns != "-" {
		target = ns + "/" + target
	}
	parts := []string{str("event")}
	if o := str("outcome"); o != "" {
		parts = append(parts, o)
	}
	if target != "" {
		parts = append(parts, target)
	}
	if c := str("cluster"); c != "" {
		parts = append(parts, "on "+c)
	}
	if r := str("reason"); r != "" {
		parts = append(parts, "("+r+")")
	}
	return str("user") + ": " + strings.Join(parts, " ")
}

// plain converts a slog value to something encoding/json writes as ECS
// expects: durations in nanoseconds, times in RFC 3339, errors as text.
func plain(v slog.Value) any {
	v = v.Resolve()
	switch v.Kind() {
	case slog.KindString:
		return v.String()
	case slog.KindInt64:
		return v.Int64()
	case slog.KindUint64:
		return v.Uint64()
	case slog.KindFloat64:
		return v.Float64()
	case slog.KindBool:
		return v.Bool()
	case slog.KindDuration:
		return v.Duration().Nanoseconds()
	case slog.KindTime:
		return v.Time().UTC().Format(time.RFC3339Nano)
	case slog.KindGroup:
		o := newObject()
		for _, a := range v.Group() {
			if pv := plain(a.Value); pv != nil {
				o.set(a.Key, pv)
			}
		}
		return o
	}
	switch x := v.Any().(type) {
	case nil:
		return nil
	case error:
		return x.Error()
	case fmt.Stringer:
		return x.String()
	default:
		return x
	}
}

// object is a JSON object that keeps insertion order.
type object struct {
	keys []string
	vals map[string]any
}

func newObject() *object { return &object{vals: map[string]any{}} }

// set stores v at a dotted path, creating nested objects. It returns false
// when the path runs into an existing non-object value.
func (o *object) set(path string, v any) bool {
	head, rest, nested := strings.Cut(path, ".")
	if !nested {
		if _, exists := o.vals[head]; !exists {
			o.keys = append(o.keys, head)
		} else if _, isObj := o.vals[head].(*object); isObj {
			if _, newObj := v.(*object); !newObj {
				return false
			}
		}
		o.vals[head] = v
		return true
	}
	child, exists := o.vals[head]
	if !exists {
		c := newObject()
		o.keys = append(o.keys, head)
		o.vals[head] = c
		return c.set(rest, v)
	}
	c, ok := child.(*object)
	if !ok {
		return false
	}
	return c.set(rest, v)
}

func (o *object) encode(buf *bytes.Buffer) {
	buf.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		buf.Write(kb)
		buf.WriteByte(':')
		switch v := o.vals[k].(type) {
		case *object:
			v.encode(buf)
		default:
			b, err := json.Marshal(v)
			if err != nil {
				b, _ = json.Marshal(fmt.Sprint(v))
			}
			buf.Write(b)
		}
	}
	buf.WriteByte('}')
}
