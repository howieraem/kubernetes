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

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection"
)

func TestOptionsValidate(t *testing.T) {
	t.Run("defaults are valid", func(t *testing.T) {
		opts := defaultOptions()
		if err := opts.validate(); err != nil {
			t.Fatalf("defaultOptions().validate() unexpected error: %v", err)
		}
	})

	t.Run("mismatched client cert and key rejected", func(t *testing.T) {
		opts := defaultOptions()
		opts.kubeletCertFile = "/etc/certs/tls.crt"
		if err := opts.validate(); err == nil {
			t.Fatal("expected error when --kubelet-client-key is missing")
		}
	})

	t.Run("CA file with insecure skip verify rejected", func(t *testing.T) {
		opts := defaultOptions()
		opts.kubeletCAFile = "/etc/certs/ca.crt"
		opts.kubeletInsecureTLS = true
		if err := opts.validate(); err == nil {
			t.Fatal("expected error when combining CA file with insecure skip verify")
		}
	})

	t.Run("leader election recovery deadline below 1s rejected", func(t *testing.T) {
		opts := defaultOptions()
		opts.leaderElect = true
		opts.leaderElectRecoveryDeadline = 500 * time.Millisecond
		if err := opts.validate(); err == nil {
			t.Fatal("expected error when recovery deadline < 1s")
		}
	})
}

func TestBuildClientsAndElectorWriteGateBlocksBeforeLeading(t *testing.T) {
	getHits := 0
	patchHits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			getHits++
		} else {
			patchHits++
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"kind":"Node","apiVersion":"v1","metadata":{"name":"node-1"}}`))
	}))
	defer srv.Close()

	opts := defaultOptions()
	opts.leaderElect = true
	opts.leaderElectIdentity = "test-holder"

	baseCfg := &rest.Config{Host: srv.URL}
	nodeClient, elector, err := buildClientsAndElector(
		opts,
		baseCfg,
		func(context.Context) {},
		func() {},
	)
	if err != nil {
		t.Fatalf("buildClientsAndElector() error: %v", err)
	}
	if elector == nil {
		t.Fatal("expected non-nil LeaderElector when leaderElect=true")
	}

	ctx := context.Background()
	// Safe GET requests pass through WriteGate even before acquiring the Lease.
	if _, err := nodeClient.CoreV1().Nodes().Get(ctx, "node-1", metav1.GetOptions{}); err != nil {
		t.Fatalf("expected GET to pass closed WriteGate, got error: %v", err)
	}
	if getHits != 1 {
		t.Fatalf("getHits = %d, want 1", getHits)
	}

	// Non-safe PATCH requests on nodes/status are rejected immediately with
	// ErrWriteGateClosed before reaching the API server.
	_, err = nodeClient.CoreV1().Nodes().Patch(
		ctx,
		"node-1",
		types.StrategicMergePatchType,
		[]byte(`{}`),
		metav1.PatchOptions{},
		"status",
	)
	if !errors.Is(err, leaderelection.ErrWriteGateClosed) {
		t.Fatalf("Patch() error = %v, want ErrWriteGateClosed", err)
	}
	if patchHits != 0 {
		t.Fatalf("expected 0 PATCH requests to hit server while WriteGate is closed, got %d", patchHits)
	}
}
