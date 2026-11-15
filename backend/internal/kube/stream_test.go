package kube

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	"k8s-dashboard/backend/internal/models"
)

// A followed log outlives the API timeout of a token cluster: only ordinary
// calls are bounded by it. (Before, every live log of a token cluster was cut
// after 30 s and the viewer had to reconnect.)
func TestFollowedLogOutlivesAPITimeout(t *testing.T) {
	old := apiTimeout
	apiTimeout = 200 * time.Millisecond
	defer func() { apiTimeout = old }()
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 6; i++ { // 600 ms of log, a line every 100 ms
			fmt.Fprintf(w, "line %d\n", i)
			w.(http.Flusher).Flush()
			time.Sleep(100 * time.Millisecond)
		}
	}))
	defer hs.Close()
	cfg, err := buildConfigRaw(models.KubeCredentials{Method: "token", Server: hs.URL, Token: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	client, stream, err := newClients(cfg)
	if err != nil {
		t.Fatal(err)
	}
	count := func(useStream bool) int {
		c := client
		if useStream {
			c = stream
		}
		body, err := c.CoreV1().Pods("app").GetLogs("web", &corev1.PodLogOptions{Follow: true}).Stream(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer body.Close()
		n := 0
		for sc := bufio.NewScanner(body); sc.Scan(); n++ {
		}
		return n
	}
	if n := count(false); n >= 6 {
		t.Fatalf("the ordinary client read %d lines; the test server is not slower than the timeout", n)
	}
	if n := count(true); n != 6 {
		t.Fatalf("the stream client read %d of 6 lines: cut by the API timeout", n)
	}
}
