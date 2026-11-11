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

// Package prober implements out-of-band node health probers for the KEP-6371
// sample external node liveness detector.
package prober

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/transport"
)

const (
	// DefaultKubeletPort is the kubelet authenticated HTTPS serving port.
	DefaultKubeletPort = 10250
	// DefaultHealthzPath is the kubelet health check endpoint authorized via
	// get on nodes/healthz when KubeletFineGrainedAuthz is enabled.
	DefaultHealthzPath = "/healthz"

	maxResponseBodyBytes = 4096

	// kubeletAuthWebhookErrorPrefix matches the HTTP 500 body written by
	// pkg/kubelet/server/server.go when the kubelet's SubjectAccessReview
	// authorizer call fails.
	kubeletAuthWebhookErrorPrefix = "Authorization error"
)

// KubeletHealthzConfig configures the HTTPS kubelet /healthz prober.
type KubeletHealthzConfig struct {
	Port            int
	Path            string
	CAFile          string
	CertFile        string
	KeyFile         string
	BearerToken     string `datapolicy:"token"`
	BearerTokenFile string
	InsecureTLS     bool
	// HTTPClient overrides transport construction when non-nil (primarily for tests).
	HTTPClient *http.Client
}

// KubeletHealthzProber probes https://<NodeInternalIP>:<Port><Path> directly
// over the cluster network without proxying through kube-apiserver.
type KubeletHealthzProber struct {
	port   int
	path   string
	client *http.Client
}

// NewKubeletHealthzProber validates cfg and builds a KubeletHealthzProber.
func NewKubeletHealthzProber(cfg KubeletHealthzConfig) (*KubeletHealthzProber, error) {
	port := cfg.Port
	if port == 0 {
		port = DefaultKubeletPort
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("kubelet port (%d) must be in [1, 65535]", port)
	}

	path := cfg.Path
	if path == "" {
		path = DefaultHealthzPath
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return nil, fmt.Errorf("kubelet client cert (%q) and key (%q) must both be set or both be empty", cfg.CertFile, cfg.KeyFile)
	}
	if cfg.InsecureTLS && cfg.CAFile != "" {
		return nil, fmt.Errorf("kubelet CAFile (%q) cannot be combined with insecure TLS", cfg.CAFile)
	}

	client := cfg.HTTPClient
	if client == nil {
		rt, err := transport.New(&transport.Config{
			UserAgent:       "sample-node-liveness-detector",
			BearerToken:     cfg.BearerToken,
			BearerTokenFile: cfg.BearerTokenFile,
			TLS: transport.TLSConfig{
				CAFile:   cfg.CAFile,
				CertFile: cfg.CertFile,
				KeyFile:  cfg.KeyFile,
				Insecure: cfg.InsecureTLS,
			},
		})
		if err != nil {
			return nil, fmt.Errorf("building kubelet HTTPS transport: %w", err)
		}
		client = &http.Client{Transport: rt}
	}

	return &KubeletHealthzProber{
		port:   port,
		path:   path,
		client: client,
	}, nil
}

// Probe queries the node's kubelet /healthz endpoint and classifies transport,
// TLS, and HTTP responses into healthy (true, nil), unhealthy (false, nil), or
// inconclusive (false, err).
func (p *KubeletHealthzProber) Probe(ctx context.Context, node *corev1.Node) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	ip, ok := nodeInternalIP(node)
	if !ok {
		return false, fmt.Errorf("node %q has no %s address", node.Name, corev1.NodeInternalIP)
	}

	targetURL := (&url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(ip, strconv.Itoa(p.port)),
		Path:   p.path,
	}).String()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return false, fmt.Errorf("constructing healthz request for node %q: %w", node.Name, err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		if isNodeUnreachableError(err) {
			return false, nil
		}
		return false, fmt.Errorf("probing %s: %w", targetURL, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if readErr != nil {
		if isNodeUnreachableError(readErr) {
			return false, nil
		}
		return false, fmt.Errorf("reading %s response body: %w", targetURL, readErr)
	}
	body := strings.TrimSpace(string(bodyBytes))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return true, nil

	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return false, fmt.Errorf("kubelet healthz authorization rejected (%d): %s", resp.StatusCode, body)

	case resp.StatusCode == http.StatusInternalServerError && strings.HasPrefix(body, kubeletAuthWebhookErrorPrefix):
		// When kubelet's Webhook SubjectAccessReview authorizer cannot reach
		// kube-apiserver after its 5m cache TTL expires, kubelet returns HTTP 500
		// with "Authorization error (...)". Treat this as inconclusive rather than
		// a node failure.
		return false, fmt.Errorf("kubelet healthz authorization webhook error: %s", body)

	case resp.StatusCode >= 500:
		return false, nil

	default:
		return false, fmt.Errorf("unexpected kubelet healthz HTTP status %d: %s", resp.StatusCode, body)
	}
}

func nodeInternalIP(node *corev1.Node) (string, bool) {
	if node == nil {
		return "", false
	}
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP && strings.TrimSpace(addr.Address) != "" {
			return strings.TrimSpace(addr.Address), true
		}
	}
	return "", false
}

// isNodeUnreachableError returns true only for transport-level timeouts and
// TCP/connection failures indicating that the node or kubelet listener is down
// or wedged. Certificate/PKI errors and explicit context cancellations return
// false so they surface as inconclusive (_, err) outcomes.
func isNodeUnreachableError(err error) bool {
	if errors.Is(err, context.Canceled) {
		return false
	}

	if _, ok := errors.AsType[*tls.CertificateVerificationError](err); ok {
		return false
	}
	if _, ok := errors.AsType[x509.UnknownAuthorityError](err); ok {
		return false
	}
	if _, ok := errors.AsType[x509.HostnameError](err); ok {
		return false
	}
	if _, ok := errors.AsType[x509.CertificateInvalidError](err); ok {
		return false
	}
	if _, ok := errors.AsType[tls.RecordHeaderError](err); ok {
		return false
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if netErr, ok := errors.AsType[net.Error](err); ok && netErr.Timeout() {
		return true
	}

	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	for _, errno := range []syscall.Errno{
		syscall.ECONNREFUSED,
		syscall.ECONNRESET,
		syscall.ECONNABORTED,
		syscall.EHOSTUNREACH,
		syscall.ENETUNREACH,
		syscall.ETIMEDOUT,
		syscall.EPIPE,
	} {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}
