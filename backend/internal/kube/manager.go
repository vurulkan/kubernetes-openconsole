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
	mu       sync.RWMutex
	client   *kubernetes.Clientset
	ready    bool
	lastError string
}

func NewManager() *Manager {
	return &Manager{}
}

func (m *Manager) ApplyCredentials(creds models.KubeCredentials) error {
	m.mu.Lock()
	defer m.mu.Unlock()

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
	m.ready = true
	m.lastError = ""

	return nil
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

func (m *Manager) Client() (*kubernetes.Clientset, bool) {
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
