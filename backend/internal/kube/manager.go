package kube

import (
	"context"
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
// configured. Callers must check Synced() before trusting lister results.
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
	ic := newInformerCache(client, m.bus)
	go ic.start(context.Background())
	m.informers = ic

	return nil
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
	m.client = nil
	m.restConfig = nil
	m.ready = false
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
