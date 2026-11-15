package kube

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"

	"k8s-dashboard/backend/internal/models"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Manager struct {
	mu         sync.RWMutex
	client     kubernetes.Interface
	restConfig *rest.Config
	ready      bool
	lastError  string
	bus        *EventBus
	informers  *InformerCache
	metrics    *MetricsSampler
	// onTermination receives container exits seen by the pod informer (restart history).
	onTermination func(models.ContainerTermination)
}

func NewManager() *Manager {
	return &Manager{bus: NewEventBus()}
}

// NewManagerWithClient returns a ready Manager around an existing client and
// no informer cache, so every read goes straight to the client. Used by tests
// with client-go's fake clientset.
func NewManagerWithClient(client kubernetes.Interface) *Manager {
	return &Manager{bus: NewEventBus(), client: client, ready: true}
}

// EventBus exposes the shared bus so API handlers can subscribe clients to
// informer-driven events without reaching into informer internals.
func (m *Manager) EventBus() *EventBus {
	return m.bus
}

// Informers returns the active informer cache or nil when no cluster is
// configured. Callers must check Usable(kind) before trusting lister results.
func (m *Manager) Informers() *InformerCache {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.informers
}

func (m *Manager) ApplyCredentials(creds models.KubeCredentials) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Stop any prior informer factory so a credential swap doesn't leak
	// goroutines bound to the previous cluster.
	if m.informers != nil {
		m.informers.stopAll()
		m.informers = nil
	}
	m.stopMetrics()

	config, err := buildConfig(creds)
	if err != nil {
		m.lastError = err.Error()
		return err
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		m.lastError = err.Error()
		return fmt.Errorf("client: %w", err)
	}

	m.client = client
	m.restConfig = config
	m.ready = true
	m.lastError = ""

	// Only start informers when the credentials actually point somewhere.
	// Deactivate uses an empty token-method payload, which we treat as "no
	// cluster" and leave the cache nil.
	if creds.Method == "" || (creds.Method == "token" && creds.Server == "") {
		m.ready = false
		return nil
	}
	ic := newInformerCache(client, m.bus, m.onTermination)
	go ic.start(context.Background())
	m.informers = ic
	m.metrics = newMetricsServerSampler(client)
	m.metrics.nodeOf = ic.PodNode
	go m.metrics.run()

	return nil
}

// Metrics is the cluster's pod usage sampler; nil when not connected.
func (m *Manager) Metrics() *MetricsSampler {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.metrics
}

// UseMetrics installs a sampler (tests: one fed by a stub instead of metrics-server).
func (m *Manager) UseMetrics(s *MetricsSampler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metrics = s
}

func (m *Manager) stopMetrics() {
	if m.metrics != nil {
		m.metrics.close()
		m.metrics = nil
	}
}

// RESTConfig returns the underlying *rest.Config for low-level operations such
// as SPDY exec/attach streams. The returned value is nil when no cluster is
// configured.
func (m *Manager) RESTConfig() (*rest.Config, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.restConfig == nil {
		return nil, false
	}
	return m.restConfig, true
}

func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.client == nil {
		m.lastError = "kubernetes credentials not configured"
		return fmt.Errorf("kubernetes credentials not configured")
	}
	m.ready = true
	m.lastError = ""
	return nil
}

func (m *Manager) StartAsync() {
	go func() {
		_ = m.Start(context.Background())
	}()
}

func (m *Manager) Client() (kubernetes.Interface, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.client == nil {
		return nil, false
	}
	return m.client, true
}

func (m *Manager) Ready() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.client != nil && m.ready
}

// Connected is what openconsole_cluster_connected reports: a client, and an
// informer cache that has listed something and isn't failing (see
// InformerCache.Connected). A Manager without a cache (tests) is connected
// when it has a client.
func (m *Manager) Connected() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.client == nil || !m.ready {
		return false
	}
	return m.informers == nil || m.informers.Connected()
}

// Check makes one real call (list namespaces, limit 1) with the Manager's
// client: connecting builds a client but asks the cluster nothing, so a
// refused token or an unreachable server shows only here.
func (m *Manager) Check(ctx context.Context) error {
	client, ok := m.Client()
	if !ok {
		return ErrNotReady
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{Limit: 1})
	return err
}

func (m *Manager) LastError() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastError
}

func (m *Manager) ValidateCredentials(creds models.KubeCredentials) error {
	return ValidateCredentials(creds)
}

// ValidateCredentials builds a client from creds and makes one real call
// (list namespaces, limit 1): that proves the API server is reachable, the
// CA matches and the identity can at least list namespaces — which every
// OpenConsole tab needs. Building a client alone checks none of that.
func ValidateCredentials(creds models.KubeCredentials) error {
	config, err := buildConfig(creds)
	if err != nil {
		return err
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{Limit: 1}); err != nil {
		return fmt.Errorf("cannot list namespaces with these credentials: %w", err)
	}
	return nil
}

// Stop drops the client and stops the informer cache (cluster deleted or
// its credentials replaced).
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.informers != nil {
		m.informers.stopAll()
		m.informers = nil
	}
	m.stopMetrics()
	m.client = nil
	m.restConfig = nil
	m.ready = false
	// Live Events sockets on this cluster end, so the panels reconnect to the
	// new connection instead of waiting on a bus nothing publishes to anymore.
	m.bus.CloseAll()
}

func buildConfig(creds models.KubeCredentials) (*rest.Config, error) {
	cfg, err := buildConfigRaw(creds)
	if err != nil {
		return nil, err
	}
	// Kubernetes API calls become child spans of the request that made them
	// (no-op when tracing is off). Background informer list/watch traffic
	// has no parent span and is not traced.
	cfg.Wrap(func(rt http.RoundTripper) http.RoundTripper {
		return otelhttp.NewTransport(rt, otelhttp.WithFilter(func(r *http.Request) bool {
			return trace.SpanFromContext(r.Context()).SpanContext().IsValid()
		}))
	})
	return cfg, nil
}

func buildConfigRaw(creds models.KubeCredentials) (*rest.Config, error) {
	switch creds.Method {
	case "kubeconfig":
		if err := checkInlineKubeconfig(creds.Kubeconfig); err != nil {
			return nil, err
		}
		return clientcmd.RESTConfigFromKubeConfig(creds.Kubeconfig)
	case "token":
		if creds.Server == "" || len(creds.Token) == 0 {
			return nil, fmt.Errorf("token config missing server or token")
		}
		return &rest.Config{
			Host:        creds.Server,
			BearerToken: string(creds.Token),
			TLSClientConfig: rest.TLSClientConfig{
				CAData: creds.CACert,
			},
			Timeout: 30 * time.Second,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported credentials method")
	}
}

// ErrKubeconfigUnsupported: the kubeconfig runs a program or reads a file.
var ErrKubeconfigUnsupported = errors.New("kubeconfig_unsupported")

// checkInlineKubeconfig refuses a kubeconfig that would run a program (exec,
// auth-provider) or read a file (token / certificate / key paths) in the
// console's pod: an admin, or an admin-scoped API key, could otherwise run
// code there or send its files (the DB, the ServiceAccount token) to a server
// of their choice. Only inline data is accepted.
func checkInlineKubeconfig(raw []byte) error {
	cfg, err := clientcmd.Load(raw)
	if err != nil {
		return err
	}
	for name, u := range cfg.AuthInfos {
		bad := ""
		switch {
		case u.Exec != nil:
			bad = "exec"
		case u.AuthProvider != nil:
			bad = "auth-provider"
		case u.TokenFile != "":
			bad = "tokenFile"
		case u.ClientCertificate != "":
			bad = "client-certificate"
		case u.ClientKey != "":
			bad = "client-key"
		}
		if bad != "" {
			return fmt.Errorf("%w: user %q uses %s; use inline credentials (token, client-certificate-data, client-key-data)", ErrKubeconfigUnsupported, name, bad)
		}
	}
	for name, c := range cfg.Clusters {
		if c.CertificateAuthority != "" {
			return fmt.Errorf("%w: cluster %q uses certificate-authority (a file); use certificate-authority-data", ErrKubeconfigUnsupported, name)
		}
	}
	return nil
}
