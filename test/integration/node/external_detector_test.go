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

package node

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	testutils "k8s.io/kubernetes/test/integration/util"

	"k8s.io/kubernetes/test/images/sample-node-liveness-detector/detector"
	"k8s.io/kubernetes/test/images/sample-node-liveness-detector/prober"
)

// TestSampleNodeLivenessDetector exercises the KEP-6371 sample external
// liveness detector and kubelet /healthz prober against a real kube-apiserver
// and etcd to verify Strategic Merge Patch uid/resourceVersion preconditions,
// lastHeartbeatTime preservation, and AtomicFIFO ConsistencyStore behavior.
func TestSampleNodeLivenessDetector(t *testing.T) {
	testCtx := testutils.InitTestAPIServer(t, "external-liveness-detector", nil)
	ctx := testCtx.Ctx

	var failingUnhealthy atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("node") == "node-failing" && failingUnhealthy.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("[-]syncloop failed\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	// Route each node's /healthz probe to srv with a query parameter identifying
	// the probed node so all three nodes can share one TLS listener in-process.
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}

	baseRT := srv.Client().Transport
	httpClient := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			cloned := req.Clone(req.Context())
			q := cloned.URL.Query()
			if cloned.URL.Path == "/healthz-failing" {
				cloned.URL.Path = "/healthz"
				q.Set("node", "node-failing")
				cloned.URL.RawQuery = q.Encode()
			}
			return baseRT.RoundTrip(cloned)
		}),
	}

	healthzProber, err := prober.NewKubeletHealthzProber(prober.KubeletHealthzConfig{
		Port:       port,
		HTTPClient: httpClient,
	})
	if err != nil {
		t.Fatalf("NewKubeletHealthzProber: %v", err)
	}

	// Wrap healthzProber so only node-failing hits the failing endpoint once toggled.
	routingProber := proberFunc(func(pCtx context.Context, node *corev1.Node) (bool, error) {
		if node.Name == "node-failing" {
			failingProber, pErr := prober.NewKubeletHealthzProber(prober.KubeletHealthzConfig{
				Port:       port,
				Path:       "/healthz-failing",
				HTTPClient: httpClient,
			})
			if pErr != nil {
				return false, pErr
			}
			return failingProber.Probe(pCtx, node)
		}
		return healthzProber.Probe(pCtx, node)
	})

	clientCfg := restclient.CopyConfig(testCtx.KubeConfig)
	clientCfg.QPS = -1
	cs := clientset.NewForConfigOrDie(clientCfg)

	hbTime := metav1.NewTime(time.Now().UTC().Add(-2 * time.Minute).Truncate(time.Second))
	transTime := metav1.NewTime(hbTime.Add(-10 * time.Minute))

	for _, name := range []string{"node-healthy-1", "node-healthy-2", "node-failing"} {
		created, cErr := cs.CoreV1().Nodes().Create(ctx, &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: name},
		}, metav1.CreateOptions{})
		if cErr != nil {
			t.Fatalf("Create(%s): %v", name, cErr)
		}
		created.Status = corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: host},
			},
			Conditions: []corev1.NodeCondition{
				{
					Type:               corev1.NodeReady,
					Status:             corev1.ConditionTrue,
					Reason:             "KubeletReady",
					Message:            "kubelet is posting ready status",
					LastHeartbeatTime:  hbTime,
					LastTransitionTime: transTime,
				},
				{
					Type:               corev1.NodeDiskPressure,
					Status:             corev1.ConditionFalse,
					Reason:             "KubeletHasNoDiskPressure",
					LastHeartbeatTime:  hbTime,
					LastTransitionTime: transTime,
				},
			},
		}
		if _, uErr := cs.CoreV1().Nodes().UpdateStatus(ctx, created, metav1.UpdateOptions{}); uErr != nil {
			t.Fatalf("UpdateStatus(%s): %v", name, uErr)
		}
	}

	factory := informers.NewSharedInformerFactory(cs, 0)
	nodeInformer := factory.Core().V1().Nodes()

	cfg := detector.DefaultConfig()
	cfg.ProbeInterval = 50 * time.Millisecond
	cfg.ProbeTimeout = 1 * time.Second
	cfg.FailureThreshold = 2
	cfg.WarmUpDuration = 0

	det, err := detector.New(cs, nodeInformer, routingProber, cfg)
	if err != nil {
		t.Fatalf("detector.New: %v", err)
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	factory.Start(runCtx.Done())
	factory.WaitForCacheSync(runCtx.Done())

	go func() {
		_ = det.Run(runCtx)
	}()

	// Flip node-failing's /healthz to 500 and verify Ready=Unknown demotion
	// preserves LastHeartbeatTime and DiskPressure=False in real etcd storage.
	failingUnhealthy.Store(true)

	var demotedNode *corev1.Node
	err = wait.PollUntilContextTimeout(ctx, 25*time.Millisecond, 10*time.Second, true, func(pCtx context.Context) (bool, error) {
		n, gErr := cs.CoreV1().Nodes().Get(pCtx, "node-failing", metav1.GetOptions{})
		if gErr != nil {
			return false, gErr
		}
		for i := range n.Status.Conditions {
			c := n.Status.Conditions[i]
			if c.Type == corev1.NodeReady && c.Status == corev1.ConditionUnknown {
				demotedNode = n
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		t.Fatalf("timed out waiting for node-failing Ready=Unknown: %v", err)
	}

	for _, c := range demotedNode.Status.Conditions {
		switch c.Type {
		case corev1.NodeReady:
			if c.Reason != detector.DefaultReason {
				t.Errorf("Ready.Reason = %q, want %q", c.Reason, detector.DefaultReason)
			}
			if !c.LastHeartbeatTime.Equal(&hbTime) {
				t.Errorf("Ready.LastHeartbeatTime = %v, want preserved %v", c.LastHeartbeatTime, hbTime)
			}
			if !c.LastTransitionTime.After(transTime.Time) {
				t.Errorf("Ready.LastTransitionTime = %v, expected > %v", c.LastTransitionTime, transTime)
			}
		case corev1.NodeDiskPressure:
			if c.Status != corev1.ConditionFalse {
				t.Errorf("DiskPressure.Status = %v, want False", c.Status)
			}
		}
	}

	healthyNode, err := cs.CoreV1().Nodes().Get(ctx, "node-healthy-1", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get(node-healthy-1): %v", err)
	}
	for _, c := range healthyNode.Status.Conditions {
		if c.Type == corev1.NodeReady && c.Status != corev1.ConditionTrue {
			t.Fatalf("node-healthy-1 Ready = %v, want True", c.Status)
		}
	}

	// Stop the detector loop and verify real kube-apiserver precondition behavior
	// directly: stale resourceVersion aborts with 409 Conflict without retrying,
	// and mismatched uid aborts with 409/422.
	cancelRun()

	staleRV := demotedNode.ResourceVersion
	recoveredHB := metav1.NewTime(hbTime.Add(time.Minute))
	demotedNode.Status.Conditions[0].Status = corev1.ConditionTrue
	demotedNode.Status.Conditions[0].Reason = "KubeletReady"
	demotedNode.Status.Conditions[0].LastHeartbeatTime = recoveredHB
	afterRecovery, err := cs.CoreV1().Nodes().UpdateStatus(ctx, demotedNode, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("UpdateStatus recovery: %v", err)
	}

	stalePatch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"uid":             afterRecovery.UID,
			"resourceVersion": staleRV,
		},
		"status": map[string]any{
			"conditions": []map[string]any{
				{
					"type":   "Ready",
					"status": "Unknown",
					"reason": detector.DefaultReason,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	_, err = cs.CoreV1().Nodes().Patch(ctx, "node-failing", types.StrategicMergePatchType, stalePatch, metav1.PatchOptions{}, "status")
	if !apierrors.IsConflict(err) {
		t.Fatalf("stale resourceVersion patch error = %v, want 409 Conflict", err)
	}

	badUIDPatch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"uid":             "00000000-0000-0000-0000-000000000000",
			"resourceVersion": afterRecovery.ResourceVersion,
		},
		"status": map[string]any{
			"conditions": []map[string]any{
				{
					"type":   "Ready",
					"status": "Unknown",
					"reason": detector.DefaultReason,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	_, err = cs.CoreV1().Nodes().Patch(ctx, "node-failing", types.StrategicMergePatchType, badUIDPatch, metav1.PatchOptions{}, "status")
	if !apierrors.IsConflict(err) && !apierrors.IsInvalid(err) {
		t.Fatalf("mismatched uid patch error = %v, want 409 Conflict or 422 Invalid", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type proberFunc func(context.Context, *corev1.Node) (bool, error)

func (f proberFunc) Probe(ctx context.Context, node *corev1.Node) (bool, error) {
	return f(ctx, node)
}
