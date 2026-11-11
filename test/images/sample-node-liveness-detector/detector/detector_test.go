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

package detector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	testingk8s "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/leaderelection"
	consistencyutil "k8s.io/client-go/util/consistency"
	testingclock "k8s.io/utils/clock/testing"
)

type fakeProber struct {
	mu      sync.Mutex
	results map[string]probeOutcome
	calls   map[string]int
}

func newFakeProber() *fakeProber {
	return &fakeProber{
		results: make(map[string]probeOutcome),
		calls:   make(map[string]int),
	}
}

func (f *fakeProber) set(nodeName string, healthy bool, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results[nodeName] = probeOutcome{healthy: healthy, err: err}
}

func (f *fakeProber) callCount(nodeName string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[nodeName]
}

func (f *fakeProber) Probe(_ context.Context, node *corev1.Node) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[node.Name]++
	out, ok := f.results[node.Name]
	if !ok {
		return true, nil
	}
	return out.healthy, out.err
}

type fakeRVStore struct {
	mu sync.Mutex
	rv string
}

func (s *fakeRVStore) setRV(rv string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rv = rv
}

func (s *fakeRVStore) LastStoreSyncResourceVersion() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rv
}

type testHarness struct {
	client   *fake.Clientset
	store    cache.Indexer
	rvStore  *fakeRVStore
	prober   *fakeProber
	clk      *testingclock.FakeClock
	detector *Detector
}

func newTestHarness(t *testing.T, modifyCfg func(*Config), nodes ...*corev1.Node) *testHarness {
	t.Helper()

	objs := make([]runtime.Object, len(nodes))
	for i, n := range nodes {
		objs[i] = n.DeepCopy()
	}
	client := fake.NewClientset(objs...)
	factory := informers.NewSharedInformerFactory(client, 0)
	nodeInformer := factory.Core().V1().Nodes()
	store := nodeInformer.Informer().GetIndexer()
	for _, n := range nodes {
		if err := store.Add(n.DeepCopy()); err != nil {
			t.Fatalf("failed to seed node informer store: %v", err)
		}
	}

	rvStore := &fakeRVStore{rv: "100"}
	clk := testingclock.NewFakeClock(time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC))
	prober := newFakeProber()

	cfg := DefaultConfig()
	cfg.WarmUpDuration = 0
	cfg.Clock = clk
	cfg.ConsistencyStore = consistencyutil.NewConsistencyStore(map[schema.GroupResource]consistencyutil.LastSyncRVGetter{
		nodeGroupResource: rvStore,
	})
	if modifyCfg != nil {
		modifyCfg(&cfg)
	}

	det, err := New(client, nodeInformer, prober, cfg)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	return &testHarness{
		client:   client,
		store:    store,
		rvStore:  rvStore,
		prober:   prober,
		clk:      clk,
		detector: det,
	}
}

func makeReadyNode(name, rv string, hb, trans time.Time) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			UID:             types.UID("uid-" + name),
			ResourceVersion: rv,
		},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{
					Type:               corev1.NodeReady,
					Status:             corev1.ConditionTrue,
					Reason:             "KubeletReady",
					Message:            "kubelet is posting ready status",
					LastHeartbeatTime:  metav1.NewTime(hb),
					LastTransitionTime: metav1.NewTime(trans),
				},
				{
					Type:               corev1.NodeMemoryPressure,
					Status:             corev1.ConditionFalse,
					Reason:             "KubeletHasSufficientMemory",
					LastHeartbeatTime:  metav1.NewTime(hb),
					LastTransitionTime: metav1.NewTime(trans),
				},
			},
		},
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{
			name:    "default config is valid",
			mutate:  func(*Config) {},
			wantErr: false,
		},
		{
			name: "reserved NodeStatusUnknown reason rejected",
			mutate: func(c *Config) {
				c.Reason = ReservedNodeControllerReason
			},
			wantErr: true,
		},
		{
			name: "failureThreshold below 2 rejected",
			mutate: func(c *Config) {
				c.FailureThreshold = 1
			},
			wantErr: true,
		},
		{
			name: "massFailureThreshold above 1 rejected",
			mutate: func(c *Config) {
				c.MassFailureThreshold = 1.1
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestConfirmedFailureDemotesPreservingHeartbeatAndPreconditions(t *testing.T) {
	hb := time.Date(2026, 11, 11, 11, 55, 0, 0, time.UTC)
	trans := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	n1 := makeReadyNode("node-1", "100", hb, trans)

	h := newTestHarness(t, func(c *Config) {
		c.FailureThreshold = 3
	}, n1)
	h.prober.set("node-1", false, nil)

	var rawPatches [][]byte
	h.client.PrependReactor("patch", "nodes", func(action testingk8s.Action) (bool, runtime.Object, error) {
		if action.GetSubresource() != "status" {
			return false, nil, nil
		}
		patchAction := action.(testingk8s.PatchAction)
		rawPatches = append(rawPatches, append([]byte(nil), patchAction.GetPatch()...))
		return false, nil, nil
	})

	ctx := context.Background()

	// Single blip followed by recovery does not demote.
	h.detector.RunOnePass(ctx)
	h.clk.Step(10 * time.Second)
	h.prober.set("node-1", true, nil)
	h.detector.RunOnePass(ctx)
	if len(rawPatches) != 0 {
		t.Fatalf("expected 0 patches after single blip recovery, got %d", len(rawPatches))
	}

	// Inconclusive error does not advance consecutiveFailures.
	h.prober.set("node-1", false, errors.New("Authorization error (user=detector)"))
	for range 4 {
		h.clk.Step(10 * time.Second)
		h.detector.RunOnePass(ctx)
	}
	if len(rawPatches) != 0 {
		t.Fatalf("expected 0 patches on inconclusive prober errors, got %d", len(rawPatches))
	}

	// Three consecutive unhealthy observations trigger exactly one demotion patch.
	h.prober.set("node-1", false, nil)
	for i := range 2 {
		h.clk.Step(10 * time.Second)
		h.detector.RunOnePass(ctx)
		if len(rawPatches) != 0 {
			t.Fatalf("unexpected patch on failure %d before threshold", i+1)
		}
	}

	h.clk.Step(10 * time.Second)
	patchTime := h.clk.Now().UTC()
	h.detector.RunOnePass(ctx)

	if len(rawPatches) != 1 {
		t.Fatalf("expected 1 demotion patch at threshold, got %d", len(rawPatches))
	}

	var decoded map[string]any
	if err := json.Unmarshal(rawPatches[0], &decoded); err != nil {
		t.Fatalf("failed to decode raw patch JSON: %v", err)
	}
	metaMap := decoded["metadata"].(map[string]any)
	if metaMap["uid"] != string(n1.UID) || metaMap["resourceVersion"] != "100" {
		t.Fatalf("unexpected patch metadata preconditions: %#v", metaMap)
	}
	conds := decoded["status"].(map[string]any)["conditions"].([]any)
	if len(conds) != 1 {
		t.Fatalf("expected 1 condition in patch, got %d", len(conds))
	}
	condMap := conds[0].(map[string]any)
	if _, hasHB := condMap["lastHeartbeatTime"]; hasHB {
		t.Fatalf("patch must omit lastHeartbeatTime, got %#v", condMap)
	}
	if condMap["status"] != string(corev1.ConditionUnknown) || condMap["reason"] != DefaultReason {
		t.Fatalf("unexpected condition payload: %#v", condMap)
	}

	updated, err := h.client.CoreV1().Nodes().Get(ctx, "node-1", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get(node-1) failed: %v", err)
	}
	ready := getReadyCondition(updated)
	if ready == nil || ready.Status != corev1.ConditionUnknown {
		t.Fatalf("expected Ready=Unknown after patch, got %#v", ready)
	}
	if !ready.LastHeartbeatTime.Time.Equal(hb) {
		t.Fatalf("LastHeartbeatTime mutated: got %v, want %v", ready.LastHeartbeatTime.Time, hb)
	}
	if !ready.LastTransitionTime.Time.Equal(patchTime) {
		t.Fatalf("LastTransitionTime = %v, want %v", ready.LastTransitionTime.Time, patchTime)
	}
	for _, c := range updated.Status.Conditions {
		if c.Type == corev1.NodeMemoryPressure && c.Status != corev1.ConditionFalse {
			t.Fatalf("MemoryPressure condition should remain untouched, got %#v", c)
		}
	}
}

func TestSkipsNeverReadyAlreadyUnknownAndGracefulShutdown(t *testing.T) {
	base := time.Date(2026, 11, 11, 11, 50, 0, 0, time.UTC)

	neverReady := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "never-ready", UID: "uid-nr", ResourceVersion: "100"},
	}
	alreadyUnknown := makeReadyNode("already-unknown", "100", base, base)
	alreadyUnknown.Status.Conditions[0].Status = corev1.ConditionUnknown
	alreadyUnknown.Status.Conditions[0].Reason = DefaultReason

	shuttingDown := makeReadyNode("shutting-down", "100", base, base)
	shuttingDown.Status.Conditions[0].Status = corev1.ConditionFalse
	shuttingDown.Status.Conditions[0].Reason = "KubeletNotReady"
	shuttingDown.Status.Conditions[0].Message = "node is shutting down, pods will be drained"

	h := newTestHarness(t, func(c *Config) {
		c.FailureThreshold = 2
	}, neverReady, alreadyUnknown, shuttingDown)
	h.prober.set("never-ready", false, nil)
	h.prober.set("already-unknown", false, nil)
	h.prober.set("shutting-down", false, nil)

	ctx := context.Background()
	for range 3 {
		h.detector.RunOnePass(ctx)
		h.clk.Step(10 * time.Second)
	}

	for _, action := range h.client.Actions() {
		if action.GetVerb() == "patch" {
			t.Fatalf("expected zero status patches, got %#v", action)
		}
	}
	if h.prober.callCount("already-unknown") != 0 {
		t.Fatalf("expected already-Unknown node not to be probed, got %d calls", h.prober.callCount("already-unknown"))
	}
}

func TestFresherLiveHeartbeatResetsOnsetAndTripsConsistencyCircuitBreaker(t *testing.T) {
	hb1 := time.Date(2026, 11, 11, 11, 50, 0, 0, time.UTC)
	hb2 := hb1.Add(30 * time.Second)
	trans := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)

	cachedNode := makeReadyNode("node-1", "100", hb1, trans)
	h := newTestHarness(t, func(c *Config) {
		c.FailureThreshold = 2
	}, cachedNode)
	h.prober.set("node-1", false, nil)

	ctx := context.Background()

	// Pass 1 records onset baseline (hb1) with consecutiveFailures = 1.
	h.detector.RunOnePass(ctx)

	// Meanwhile kubelet writes a fresher heartbeat directly to the apiserver (RV 105),
	// while the informer cache is still lagging at RV 100.
	liveNode := makeReadyNode("node-1", "105", hb2, trans)
	if _, err := h.client.CoreV1().Nodes().UpdateStatus(ctx, liveNode, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}
	h.client.ClearActions()

	// Pass 2 reaches threshold=2 on cachedNode, performs live GET, sees fresher hb2
	// at RV 105, skips demotion, resets consecutiveFailures=1, and records WroteAt(105).
	h.clk.Step(10 * time.Second)
	h.detector.RunOnePass(ctx)

	gets, patches := 0, 0
	for _, a := range h.client.Actions() {
		if a.GetVerb() == "get" {
			gets++
		}
		if a.GetVerb() == "patch" {
			patches++
		}
	}
	if gets != 1 || patches != 0 {
		t.Fatalf("expected 1 live GET and 0 patches, got gets=%d patches=%d", gets, patches)
	}

	// Pass 3 while informer RV is still 100 (< 105): circuit breaker short-circuits
	// the pass with zero probes and zero live GETs.
	h.client.ClearActions()
	probeCallsBefore := h.prober.callCount("node-1")
	h.clk.Step(10 * time.Second)
	h.detector.RunOnePass(ctx)
	if len(h.client.Actions()) != 0 {
		t.Fatalf("expected 0 client actions while informer RV lags, got %#v", h.client.Actions())
	}
	if h.prober.callCount("node-1") != probeCallsBefore {
		t.Fatalf("expected 0 probes while informer RV lags")
	}

	// Once informer store catches up to RV 105, the next failed probe advances
	// consecutiveFailures from 1 -> 2 and demotes cleanly.
	if err := h.store.Update(liveNode.DeepCopy()); err != nil {
		t.Fatalf("store.Update failed: %v", err)
	}
	h.rvStore.setRV("105")
	h.clk.Step(10 * time.Second)
	h.detector.RunOnePass(ctx)

	patches = 0
	for _, a := range h.client.Actions() {
		if a.GetVerb() == "patch" {
			patches++
		}
	}
	if patches != 1 {
		t.Fatalf("expected 1 patch once informer caught up and second failure confirmed, got %d", patches)
	}
}

func TestLaggingInformerAfterPatchDoesNotRedemote(t *testing.T) {
	hb := time.Date(2026, 11, 11, 11, 50, 0, 0, time.UTC)
	n1 := makeReadyNode("node-1", "100", hb, hb)

	h := newTestHarness(t, func(c *Config) {
		c.FailureThreshold = 2
	}, n1)
	h.prober.set("node-1", false, nil)

	h.client.PrependReactor("patch", "nodes", func(action testingk8s.Action) (bool, runtime.Object, error) {
		patched := n1.DeepCopy()
		patched.ResourceVersion = "110"
		patched.Status.Conditions[0].Status = corev1.ConditionUnknown
		patched.Status.Conditions[0].Reason = DefaultReason
		return true, patched, nil
	})

	ctx := context.Background()
	h.detector.RunOnePass(ctx)
	h.clk.Step(10 * time.Second)
	h.detector.RunOnePass(ctx)

	// Informer cache still holds Ready=True at RV 100 (< WroteRV 110).
	// Subsequent passes must skip node-1 without issuing another GET or PATCH.
	h.client.ClearActions()
	probeBefore := h.prober.callCount("node-1")
	h.clk.Step(10 * time.Second)
	h.detector.RunOnePass(ctx)

	if len(h.client.Actions()) != 0 {
		t.Fatalf("expected 0 client calls while ReadRV < WroteRV, got %#v", h.client.Actions())
	}
	if h.prober.callCount("node-1") != probeBefore {
		t.Fatalf("expected node-1 not to be re-probed while ReadRV < WroteRV")
	}
}

func TestConflictAndWriteGateClosedDoNotBurnFailedWriteBudget(t *testing.T) {
	hb := time.Date(2026, 11, 11, 11, 50, 0, 0, time.UTC)
	n1 := makeReadyNode("node-1", "100", hb, hb)

	h := newTestHarness(t, func(c *Config) {
		c.FailureThreshold = 2
		c.MaxFailedWrites = 2
	}, n1)
	h.prober.set("node-1", false, nil)

	var patchErr error
	h.client.PrependReactor("patch", "nodes", func(testingk8s.Action) (bool, runtime.Object, error) {
		if patchErr != nil {
			return true, nil, patchErr
		}
		return false, nil, nil
	})

	ctx := context.Background()
	h.detector.RunOnePass(ctx)

	// WriteGate closed rejections must not increment failedWriteAttempts.
	patchErr = fmt.Errorf("wrapped: %w", leaderelection.ErrWriteGateClosed)
	for range 4 {
		h.clk.Step(10 * time.Second)
		h.detector.RunOnePass(ctx)
	}
	if got := h.detector.states["node-1"].failedWriteAttempts; got != 0 {
		t.Fatalf("ErrWriteGateClosed incremented failedWriteAttempts to %d, want 0", got)
	}

	// 409 Conflict rejections must also not burn failedWriteAttempts.
	patchErr = apierrors.NewConflict(nodeGroupResource, "node-1", errors.New("optimistic lock conflict"))
	for range 3 {
		h.clk.Step(10 * time.Second)
		h.detector.RunOnePass(ctx)
	}
	if got := h.detector.states["node-1"].failedWriteAttempts; got != 0 {
		t.Fatalf("409 Conflict incremented failedWriteAttempts to %d, want 0", got)
	}

	// Persistent non-conflict errors park the node once MaxFailedWrites is reached.
	patchErr = apierrors.NewInternalError(errors.New("etcd unavailable"))
	h.clk.Step(10 * time.Second)
	h.detector.RunOnePass(ctx)
	h.clk.Step(10 * time.Second)
	h.detector.RunOnePass(ctx)
	if got := h.detector.states["node-1"].failedWriteAttempts; got != 2 {
		t.Fatalf("failedWriteAttempts = %d, want 2", got)
	}

	// Once parked, subsequent passes skip probing/patching until kubelet heartbeats.
	h.client.ClearActions()
	h.clk.Step(10 * time.Second)
	h.detector.RunOnePass(ctx)
	if len(h.client.Actions()) != 0 {
		t.Fatalf("expected parked node to skip client calls, got %#v", h.client.Actions())
	}
}

func TestWarmUpPauseResetDemotionCapAndMassFailureDeferral(t *testing.T) {
	hb := time.Date(2026, 11, 11, 11, 50, 0, 0, time.UTC)
	nodes := []*corev1.Node{
		makeReadyNode("node-1", "100", hb, hb),
		makeReadyNode("node-2", "100", hb, hb),
		makeReadyNode("node-3", "100", hb, hb),
		makeReadyNode("node-4", "100", hb, hb),
	}

	h := newTestHarness(t, func(c *Config) {
		c.ProbeInterval = 10 * time.Second
		c.FailureThreshold = 2
		c.WarmUpDuration = 20 * time.Second
		c.DemotionsPerPass = 1
		c.MassFailureThreshold = 0.55
		c.MaxMassDeferral = 30 * time.Second
	}, nodes...)

	ctx := context.Background()

	// 1. Warm-up: node-1 fails twice during [0s, 10s], deferred because < 20s warm-up.
	h.prober.set("node-1", false, nil)
	h.detector.RunOnePass(ctx) // t=0s, failures=1
	h.clk.Step(10 * time.Second)
	h.detector.RunOnePass(ctx) // t=10s, failures=2, still in warm-up (< 20s)
	for _, a := range h.client.Actions() {
		if a.GetVerb() == "patch" {
			t.Fatalf("unexpected patch during warm-up: %#v", a)
		}
	}

	// 2. Process pause (> 2 * 10s = 20s): advancing 25s resets consecutiveFailures
	// from 2 -> 0 before evaluating the pass, so this single post-pause failure sets
	// consecutiveFailures = 1 rather than demoting immediately.
	h.clk.Step(25 * time.Second) // t=35s (elapsed 25s > 20s), warm-up is now over
	h.detector.RunOnePass(ctx)
	for _, a := range h.client.Actions() {
		if a.GetVerb() == "patch" {
			t.Fatalf("unexpected patch immediately after stalled pass reset: %#v", a)
		}
	}

	// 3. Mass-failure deferral: 3 of 4 nodes failing (75% > 55%) defers demotions
	// until MaxMassDeferral (30s) elapses, then DemotionsPerPass=1 caps writes to 1.
	h.prober.set("node-2", false, nil)
	h.prober.set("node-3", false, nil)

	h.clk.Step(10 * time.Second) // t=45s: node-1=2, node-2=1, node-3=1 -> 3/4 = 75% > 55%, deferral starts at t=45s
	h.detector.RunOnePass(ctx)
	h.clk.Step(10 * time.Second) // t=55s: deferredFor=10s < 30s
	h.detector.RunOnePass(ctx)
	for _, a := range h.client.Actions() {
		if a.GetVerb() == "patch" {
			t.Fatalf("expected mass-failure deferral to hold demotions before maxMassDeferral: %#v", a)
		}
	}

	// At t=75s (deferredFor=30s >= MaxMassDeferral), deferral expires and
	// DemotionsPerPass=1 allows exactly 1 demotion on this pass.
	h.clk.Step(10 * time.Second) // t=65s: deferredFor=20s
	h.detector.RunOnePass(ctx)
	h.clk.Step(10 * time.Second) // t=75s: deferredFor=30s -> cap=1 demotes node-1 only
	h.detector.RunOnePass(ctx)

	patches := 0
	for _, a := range h.client.Actions() {
		if a.GetVerb() == "patch" {
			patches++
		}
	}
	if patches != 1 {
		t.Fatalf("expected exactly 1 demotion (DemotionsPerPass=1) once MaxMassDeferral expired, got %d", patches)
	}
}
