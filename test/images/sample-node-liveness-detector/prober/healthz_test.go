/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package prober

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func nodeWithIP(name, ip string) *corev1.Node {
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if ip != "" {
		node.Status.Addresses = []corev1.NodeAddress{
			{Type: corev1.NodeInternalIP, Address: ip},
		}
	}
	return node
}

func splitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi(%q): %v", portStr, err)
	}
	return host, port
}

func TestKubeletHealthzProberHTTPResponses(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        string
		wantHealthy bool
		wantErr     bool
	}{
		{
			name:        "200 ok returns healthy",
			status:      http.StatusOK,
			body:        "ok",
			wantHealthy: true,
			wantErr:     false,
		},
		{
			name:        "500 syncloop check failure returns unhealthy without error",
			status:      http.StatusInternalServerError,
			body:        "[+]ping ok\n[-]syncloop failed: reason withheld\nhealthz check failed\n",
			wantHealthy: false,
			wantErr:     false,
		},
		{
			name:        "500 SubjectAccessReview webhook failure returns inconclusive error",
			status:      http.StatusInternalServerError,
			body:        "Authorization error (user=system:serviceaccount:kube-system:detector, verb=get, resource=nodes, subresource=healthz)",
			wantHealthy: false,
			wantErr:     true,
		},
		{
			name:        "401 unauthorized returns inconclusive error",
			status:      http.StatusUnauthorized,
			body:        "Unauthorized",
			wantHealthy: false,
			wantErr:     true,
		},
		{
			name:        "403 forbidden returns inconclusive error",
			status:      http.StatusForbidden,
			body:        "Forbidden (user=detector, verb=get, resource=nodes, subresource=healthz)",
			wantHealthy: false,
			wantErr:     true,
		},
		{
			name:        "404 not found returns inconclusive error",
			status:      http.StatusNotFound,
			body:        "404 page not found",
			wantHealthy: false,
			wantErr:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/healthz" {
					t.Errorf("unexpected request path %q", r.URL.Path)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			host, port := splitHostPort(t, srv.Listener.Addr().String())
			p, err := NewKubeletHealthzProber(KubeletHealthzConfig{
				Port:       port,
				HTTPClient: srv.Client(),
			})
			if err != nil {
				t.Fatalf("NewKubeletHealthzProber() error: %v", err)
			}

			healthy, err := p.Probe(context.Background(), nodeWithIP("node-1", host))
			if healthy != tc.wantHealthy || (err != nil) != tc.wantErr {
				t.Fatalf("Probe() = (%v, %v), want (%v, wantErr=%v)", healthy, err, tc.wantHealthy, tc.wantErr)
			}
		})
	}
}

func TestKubeletHealthzProberTransportAndTLSErrors(t *testing.T) {
	t.Run("missing NodeInternalIP returns inconclusive error", func(t *testing.T) {
		p, err := NewKubeletHealthzProber(KubeletHealthzConfig{InsecureTLS: true})
		if err != nil {
			t.Fatalf("NewKubeletHealthzProber() error: %v", err)
		}
		healthy, err := p.Probe(context.Background(), nodeWithIP("node-no-ip", ""))
		if healthy || err == nil {
			t.Fatalf("expected (false, err) for missing NodeInternalIP, got (%v, %v)", healthy, err)
		}
	})

	t.Run("untrusted TLS serving certificate returns inconclusive error", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		host, port := splitHostPort(t, srv.Listener.Addr().String())
		// Default client does not trust srv's self-signed test certificate.
		p, err := NewKubeletHealthzProber(KubeletHealthzConfig{Port: port})
		if err != nil {
			t.Fatalf("NewKubeletHealthzProber() error: %v", err)
		}
		healthy, err := p.Probe(context.Background(), nodeWithIP("node-bad-ca", host))
		if healthy || err == nil {
			t.Fatalf("expected TLS verification failure to return inconclusive (false, err), got (%v, %v)", healthy, err)
		}
	})

	t.Run("mTLS client certificate rejection returns inconclusive error", func(t *testing.T) {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		srv.TLS = &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
		}
		srv.StartTLS()
		defer srv.Close()

		host, port := splitHostPort(t, srv.Listener.Addr().String())
		p, err := NewKubeletHealthzProber(KubeletHealthzConfig{
			Port:       port,
			HTTPClient: srv.Client(), // Trusts server CA, sends no client cert.
		})
		if err != nil {
			t.Fatalf("NewKubeletHealthzProber() error: %v", err)
		}
		healthy, err := p.Probe(context.Background(), nodeWithIP("node-mtls-reject", host))
		if healthy || err == nil {
			t.Fatalf("expected mTLS rejection to return inconclusive (false, err), got (%v, %v)", healthy, err)
		}
	})

	t.Run("connection refused returns unhealthy (false, nil)", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen: %v", err)
		}
		host, port := splitHostPort(t, ln.Addr().String())
		_ = ln.Close()

		p, err := NewKubeletHealthzProber(KubeletHealthzConfig{
			Port:        port,
			InsecureTLS: true,
		})
		if err != nil {
			t.Fatalf("NewKubeletHealthzProber() error: %v", err)
		}
		healthy, err := p.Probe(context.Background(), nodeWithIP("node-down", host))
		if healthy || err != nil {
			t.Fatalf("expected connection refused to return (false, nil), got (%v, %v)", healthy, err)
		}
	})

	t.Run("probe deadline exceeded returns unhealthy (false, nil)", func(t *testing.T) {
		unblock := make(chan struct{})
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			<-unblock
			w.WriteHeader(http.StatusOK)
		}))
		defer func() {
			close(unblock)
			srv.Close()
		}()

		host, port := splitHostPort(t, srv.Listener.Addr().String())
		p, err := NewKubeletHealthzProber(KubeletHealthzConfig{
			Port:       port,
			HTTPClient: srv.Client(),
		})
		if err != nil {
			t.Fatalf("NewKubeletHealthzProber() error: %v", err)
		}

		probeCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		healthy, err := p.Probe(probeCtx, nodeWithIP("node-hung", host))
		if healthy || err != nil {
			t.Fatalf("expected probe timeout to return (false, nil), got (%v, %v)", healthy, err)
		}
	})

	t.Run("cancelled context returns inconclusive error", func(t *testing.T) {
		p, err := NewKubeletHealthzProber(KubeletHealthzConfig{InsecureTLS: true})
		if err != nil {
			t.Fatalf("NewKubeletHealthzProber() error: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		healthy, err := p.Probe(ctx, nodeWithIP("node-1", "127.0.0.1"))
		if healthy || err == nil {
			t.Fatalf("expected cancelled context to return (false, err), got (%v, %v)", healthy, err)
		}
	})
}
