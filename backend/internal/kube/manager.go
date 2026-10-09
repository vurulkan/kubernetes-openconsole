package kube

import (
	"context"
	"fmt"
	"sync"
	"time"

	"k8s-dashboard/backend/internal/models"
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
	config, err := buildConfig(creds)
	if err != nil {
		return err
	}
	_, err = kubernetes.NewForConfig(config)
	return err
}

func buildConfig(creds models.KubeCredentials) (*rest.Config, error) {
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
