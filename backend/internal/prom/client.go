// Package prom queries a Prometheus-compatible HTTP API (Prometheus, Thanos,
// Mimir, VictoriaMetrics, managed services) for pod CPU / memory history,
// either through the Kubernetes API server's service proxy or directly.
package prom

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"k8s.io/client-go/kubernetes"

	"k8s-dashboard/backend/internal/auth"
	"k8s-dashboard/backend/internal/models"
)

const (
	queryTimeout = 20 * time.Second
	maxBody      = 8 << 20 // a range query for one pod is a few KB; refuse runaway answers
)

// Client is one cluster's Prometheus.
type Client struct {
	cfg  models.PrometheusConfig
	kube kubernetes.Interface
	http *http.Client

	tokenMu  sync.Mutex
	token    string
	tokenExp time.Time
}

var labelName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// New builds a client; kube is the cluster's client (used in proxy mode).
func New(cfg models.PrometheusConfig, kube kubernetes.Interface) (*Client, error) {
	c := &Client{cfg: cfg, kube: kube}
	// The label name goes into PromQL as is (values are quoted), so it must be a label name.
	if cfg.ClusterLabel != "" && !labelName.MatchString(cfg.ClusterLabel) {
		return nil, errors.New("cluster label is not a valid Prometheus label name")
	}
	switch cfg.Mode {
	case "proxy":
		if cfg.Namespace == "" || cfg.Service == "" || cfg.Port == "" {
			return nil, errors.New("namespace, service and port are required")
		}
	case "url":
		u, err := url.Parse(cfg.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, errors.New("url must be an http(s) address")
		}
		tlsCfg := &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify} //nolint:gosec // opt-in, per cluster
		if cfg.CACert != "" {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM([]byte(cfg.CACert)) {
				return nil, errors.New("CA certificate is not valid PEM")
			}
			tlsCfg.RootCAs = pool
		}
		if cfg.Auth == "mtls" {
			cert, err := tls.X509KeyPair([]byte(cfg.ClientCert), []byte(cfg.ClientKey))
			if err != nil {
				return nil, fmt.Errorf("client certificate: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
		c.http = &http.Client{Timeout: queryTimeout, Transport: &http.Transport{TLSClientConfig: tlsCfg, Proxy: http.ProxyFromEnvironment}}
	default:
		return nil, errors.New("prometheus is not configured")
	}
	return c, nil
}

// StatusError is a non-2xx answer from Prometheus (or the proxy in front of it).
type StatusError struct {
	Code int
	Body string
}

func (e *StatusError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.Code, e.Body) }

func (c *Client) get(ctx context.Context, path string, params url.Values) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	if c.cfg.Mode == "proxy" {
		if c.kube == nil {
			return nil, errors.New("cluster not connected")
		}
		flat := map[string]string{}
		for k := range params {
			flat[k] = params.Get(k)
		}
		scheme := c.cfg.Scheme
		if scheme == "" {
			scheme = "http"
		}
		raw, err := c.kube.CoreV1().Services(c.cfg.Namespace).ProxyGet(scheme, c.cfg.Service, c.cfg.Port, path, flat).DoRaw(ctx)
		if err != nil {
			return nil, err
		}
		if len(raw) > maxBody {
			return nil, errors.New("answer too large")
		}
		return raw, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.cfg.URL, "/")+path+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	if err := c.authorize(ctx, req); err != nil {
		return nil, err
	}
	for _, h := range c.cfg.Headers {
		if h.Name != "" {
			req.Header.Set(h.Name, h.Value)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBody {
		return nil, errors.New("answer too large")
	}
	if resp.StatusCode/100 != 2 {
		return nil, &StatusError{Code: resp.StatusCode, Body: strings.TrimSpace(string(body[:min(len(body), 200)]))}
	}
	return body, nil
}

func (c *Client) authorize(ctx context.Context, req *http.Request) error {
	switch c.cfg.Auth {
	case "basic":
		req.SetBasicAuth(c.cfg.Username, c.cfg.Password)
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	case "azure":
		tok, err := c.azureToken(ctx)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	return nil
}

// azureToken: client credentials for Azure Monitor managed Prometheus, cached
// until a minute before it expires.
func (c *Client) azureToken(ctx context.Context) (string, error) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.token != "" && time.Now().Before(c.tokenExp) {
		return c.token, nil
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.cfg.AzureClientID},
		"client_secret": {c.cfg.AzureClientSecret},
		"scope":         {"https://prometheus.monitor.azure.com/.default"},
	}
	endpoint := strings.TrimRight(auth.AzureAuthority, "/") + "/" + url.PathEscape(c.cfg.AzureTenantID) + "/oauth2/v2.0/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("azure token: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil || out.AccessToken == "" {
		return "", &StatusError{Code: http.StatusUnauthorized, Body: "azure token: " + firstNonEmpty(out.Error, resp.Status)}
	}
	c.token = out.AccessToken
	c.tokenExp = time.Now().Add(time.Duration(out.ExpiresIn)*time.Second - time.Minute)
	return c.token, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

type apiResponse struct {
	Status    string          `json:"status"`
	Data      json.RawMessage `json:"data"`
	ErrorType string          `json:"errorType"`
	Error     string          `json:"error"`
}

func decode(raw []byte, into any) error {
	var r apiResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return ErrNotPrometheus
	}
	if r.Status != "success" {
		return fmt.Errorf("prometheus: %s %s", r.ErrorType, r.Error)
	}
	return json.Unmarshal(r.Data, into)
}

// ErrNotPrometheus: the address answered, but not with the Prometheus API.
var ErrNotPrometheus = errors.New("not a Prometheus API answer")

// Sample is one value at one time.
type Sample struct {
	T int64
	V float64
}

// QueryRange runs a range query and returns each series' samples.
func (c *Client) QueryRange(ctx context.Context, q string, start, end time.Time, step time.Duration) ([][]Sample, error) {
	raw, err := c.get(ctx, "/api/v1/query_range", url.Values{
		"query": {q},
		"start": {strconv.FormatInt(start.Unix(), 10)},
		"end":   {strconv.FormatInt(end.Unix(), 10)},
		"step":  {strconv.FormatInt(int64(step/time.Second), 10)},
	})
	if err != nil {
		return nil, err
	}
	var data struct {
		Result []struct {
			Values [][2]any `json:"values"`
		} `json:"result"`
	}
	if err := decode(raw, &data); err != nil {
		return nil, err
	}
	out := make([][]Sample, 0, len(data.Result))
	for _, r := range data.Result {
		out = append(out, samples(r.Values))
	}
	return out, nil
}

// Query runs an instant query and returns the first series' value (0 when empty).
func (c *Client) Query(ctx context.Context, q string) (float64, bool, error) {
	raw, err := c.get(ctx, "/api/v1/query", url.Values{"query": {q}})
	if err != nil {
		return 0, false, err
	}
	var data struct {
		Result []struct {
			Value [2]any `json:"value"`
		} `json:"result"`
	}
	if err := decode(raw, &data); err != nil {
		return 0, false, err
	}
	if len(data.Result) == 0 {
		return 0, false, nil
	}
	s := samples([][2]any{data.Result[0].Value})
	if len(s) == 0 {
		return 0, false, nil
	}
	return s[0].V, true, nil
}

// LabelValues lists the values of a label (e.g. "cluster").
func (c *Client) LabelValues(ctx context.Context, label string) ([]string, error) {
	raw, err := c.get(ctx, "/api/v1/label/"+url.PathEscape(label)+"/values", url.Values{})
	if err != nil {
		return nil, err
	}
	var out []string
	return out, decode(raw, &out)
}

func samples(values [][2]any) []Sample {
	out := make([]Sample, 0, len(values))
	for _, v := range values {
		ts, _ := v[0].(float64)
		s, _ := v[1].(string)
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			continue
		}
		out = append(out, Sample{T: int64(ts), V: f})
	}
	return out
}
