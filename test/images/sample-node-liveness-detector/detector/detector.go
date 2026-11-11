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

// Package detector implements the KEP-6371 external node liveness detector
// reconciliation loop, decoupling out-of-band health probing from Kubernetes
// Node status demotion and safety bounds.
package detector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/runtime"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/leaderelection"
	consistencyutil "k8s.io/client-go/util/consistency"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
)

const (
	// ReservedNodeControllerReason is reserved by kube-controller-manager for
	// lease-based timeouts and must never be written by an external detector.
	ReservedNodeControllerReason = "NodeStatusUnknown"

	// DefaultReason is the Ready=Unknown condition reason written on demotion.
	DefaultReason = "ExternalProbeUnreachable"

	// DefaultMessage is the Ready=Unknown condition message written on demotion.
	DefaultMessage = "External liveness detector lost contact with node."
)

var nodeGroupResource = schema.GroupResource{Group: "", Resource: "nodes"}

// Prober checks whether a single node is reachable and healthy via an
// out-of-band signal.
//
// Implementations must return:
//   - (true, nil) when the node is confirmed healthy;
//   - (false, nil) when the node is observed unhealthy (e.g. dial/TLS/read
//     timeout, connection refusal, or failing health check);
//   - (_, err) when the probe itself could not make a valid determination
//     (e.g. PKI/RBAC misconfiguration, authorization webhook failure, or
//     missing node address). Inconclusive errors do not advance failure counts.
type Prober interface {
	Probe(ctx context.Context, node *corev1.Node) (healthy bool, err error)
}

// Config configures the Detector reconciliation loop and blast-radius bounds.
type Config struct {
	ProbeInterval        time.Duration
	ProbeTimeout         time.Duration
	ProbeConcurrency     int
	FailureThreshold     int
	WarmUpDuration       time.Duration
	DemotionsPerPass     int
	MassFailureThreshold float64
	MaxMassDeferral      time.Duration
	MaxFailedWrites      int
	Reason               string
	Message              string

	// Clock defaults to clock.RealClock{} when nil.
	Clock clock.WithTicker
	// ConsistencyStore defaults to a store backed by the Node informer's
	// cache.Store when nil.
	ConsistencyStore consistencyutil.ConsistencyStore
}

// DefaultConfig returns sensible production defaults aligned with KEP-6371.
func DefaultConfig() Config {
	return Config{
		ProbeInterval:        10 * time.Second,
		ProbeTimeout:         5 * time.Second,
		ProbeConcurrency:     16,
		FailureThreshold:     3,
		WarmUpDuration:       20 * time.Second,
		DemotionsPerPass:     2,
		MassFailureThreshold: 0.55,
		MaxMassDeferral:      15 * time.Minute,
		MaxFailedWrites:      5,
		Reason:               DefaultReason,
		Message:              DefaultMessage,
	}
}

// Validate checks Config invariants.
func (c *Config) Validate() error {
	if c.ProbeInterval <= 0 {
		return fmt.Errorf("probeInterval (%v) must be positive", c.ProbeInterval)
	}
	if c.ProbeTimeout <= 0 {
		return fmt.Errorf("probeTimeout (%v) must be positive", c.ProbeTimeout)
	}
	if c.ProbeConcurrency < 1 {
		return fmt.Errorf("probeConcurrency (%d) must be at least 1", c.ProbeConcurrency)
	}
	if c.FailureThreshold < 2 {
		return fmt.Errorf("failureThreshold (%d) must be at least 2 to confirm persistent failure", c.FailureThreshold)
	}
	if c.WarmUpDuration < 0 {
		return fmt.Errorf("warmUpDuration (%v) must not be negative", c.WarmUpDuration)
	}
	if c.DemotionsPerPass < 1 {
		return fmt.Errorf("demotionsPerPass (%d) must be at least 1", c.DemotionsPerPass)
	}
	if c.MassFailureThreshold <= 0 || c.MassFailureThreshold > 1 {
		return fmt.Errorf("massFailureThreshold (%v) must be in (0, 1]", c.MassFailureThreshold)
	}
	if c.MaxMassDeferral < 0 {
		return fmt.Errorf("maxMassDeferral (%v) must not be negative", c.MaxMassDeferral)
	}
	if c.MaxFailedWrites < 1 {
		return fmt.Errorf("maxFailedWrites (%d) must be at least 1", c.MaxFailedWrites)
	}
	if strings.TrimSpace(c.Reason) == "" {
		return fmt.Errorf("reason must not be empty")
	}
	if c.Reason == ReservedNodeControllerReason {
		return fmt.Errorf("reason %q is reserved for kube-controller-manager", ReservedNodeControllerReason)
	}
	return nil
}

type nodeState struct {
	uid                 types.UID
	consecutiveFailures int
	onsetHeartbeatTime  metav1.Time
	onsetTransitionTime metav1.Time
	demoted             bool
	failedWriteAttempts int
}

// Detector watches cluster Nodes, probes eligible nodes on a fixed interval,
// and patches Ready=Unknown on confirmed node loss while leaving recovery to
// kubelet.
type Detector struct {
	cfg              Config
	client           kubernetes.Interface
	nodeLister       corelisters.NodeLister
	nodeSynced       cache.InformerSynced
	prober           Prober
	clock            clock.WithTicker
	consistencyStore consistencyutil.ConsistencyStore

	startedAt         time.Time
	lastPassAt        time.Time
	massDeferralSince time.Time
	states            map[string]*nodeState
}

// New constructs a Detector after validating cfg.
func New(
	client kubernetes.Interface,
	nodeInformer coreinformers.NodeInformer,
	prober Prober,
	cfg Config,
) (*Detector, error) {
	if client == nil {
		return nil, fmt.Errorf("kubernetes client must not be nil")
	}
	if nodeInformer == nil {
		return nil, fmt.Errorf("nodeInformer must not be nil")
	}
	if prober == nil {
		return nil, fmt.Errorf("prober must not be nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	clk := cfg.Clock
	if clk == nil {
		clk = clock.RealClock{}
	}
	cs := cfg.ConsistencyStore
	if cs == nil {
		cs = consistencyutil.NewConsistencyStore(map[schema.GroupResource]consistencyutil.LastSyncRVGetter{
			nodeGroupResource: nodeInformer.Informer().GetStore(),
		})
	}

	return &Detector{
		cfg:              cfg,
		client:           client,
		nodeLister:       nodeInformer.Lister(),
		nodeSynced:       nodeInformer.Informer().HasSynced,
		prober:           prober,
		clock:            clk,
		consistencyStore: cs,
		states:           make(map[string]*nodeState),
	}, nil
}

// Run waits for the Node informer cache to sync, initializes the warm-up timer,
// and executes periodic probe passes until ctx is cancelled.
func (d *Detector) Run(ctx context.Context) error {
	defer runtime.HandleCrashWithContext(ctx)

	logger := klog.FromContext(ctx)
	logger.Info("Starting external node liveness detector",
		"probeInterval", d.cfg.ProbeInterval,
		"failureThreshold", d.cfg.FailureThreshold,
		"warmUpDuration", d.cfg.WarmUpDuration,
	)

	if !cache.WaitForNamedCacheSyncWithContext(ctx, d.nodeSynced) {
		return fmt.Errorf("failed to sync node informer cache")
	}

	d.startedAt = d.clock.Now()
	d.RunOnePass(ctx)

	ticker := d.clock.NewTicker(d.cfg.ProbeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("Shutting down external node liveness detector")
			return nil
		case <-ticker.C():
			d.RunOnePass(ctx)
		}
	}
}

type probeTarget struct {
	node  *corev1.Node
	ready *corev1.NodeCondition
}

type probeOutcome struct {
	healthy bool
	err     error
}

// RunOnePass executes a single probe-and-evaluate cycle across all cached Nodes.
// Callers must invoke RunOnePass serially (Run enforces this automatically).
func (d *Detector) RunOnePass(ctx context.Context) {
	logger := klog.FromContext(ctx)
	passStart := d.clock.Now()
	if d.startedAt.IsZero() {
		d.startedAt = passStart
	}

	// If the process was paused or starved past 2 intervals, pre-pause failure
	// counts no longer reflect contiguous silence and must be cleared before
	// acting.
	if !d.lastPassAt.IsZero() && passStart.Sub(d.lastPassAt) > 2*d.cfg.ProbeInterval {
		logger.Info("Detected pass stall exceeding 2x probeInterval; resetting consecutive failure counts",
			"elapsed", passStart.Sub(d.lastPassAt),
			"probeInterval", d.cfg.ProbeInterval,
		)
		for _, st := range d.states {
			st.consecutiveFailures = 0
		}
		d.massDeferralSince = time.Time{}
	}
	defer func() {
		d.lastPassAt = d.clock.Now()
	}()

	// Circuit-breaker check: if an earlier live GET observed a newer Node RV
	// than our informer store has synced to, wait for the watch to catch up.
	if err := d.consistencyStore.EnsureReady(types.NamespacedName{}); err != nil {
		logger.V(2).Info("Skipping pass while node informer cache catches up", "err", err)
		return
	}

	nodes, err := d.nodeLister.List(labels.Everything())
	if err != nil {
		logger.Error(err, "Failed to list nodes from informer cache")
		return
	}
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].Name < nodes[j].Name
	})

	present := make(map[string]struct{}, len(nodes))
	targets := make([]probeTarget, 0, len(nodes))
	eligibleNodes := 0

	for _, node := range nodes {
		present[node.Name] = struct{}{}
		st := d.ensureState(node)

		// Per-node read-your-writes check: if we recently patched this node and
		// the informer store has not yet observed that patch's RV, skip it.
		if err := d.consistencyStore.EnsureReady(types.NamespacedName{Name: node.Name}); err != nil {
			logger.V(3).Info("Skipping node until informer observes prior status patch",
				"node", klog.KObj(node),
				"err", err,
			)
			if st.demoted {
				eligibleNodes++
			}
			continue
		}

		ready := getReadyCondition(node)
		if ready == nil {
			// Never-Ready nodes belong to kube-controller-manager's startup grace period.
			st.consecutiveFailures = 0
			st.demoted = false
			st.failedWriteAttempts = 0
			continue
		}

		eligibleNodes++

		if ready.Status == corev1.ConditionUnknown {
			// Already Unknown: never bump lastTransitionTime or re-patch; wait for
			// kubelet to post Ready=True (or False).
			st.consecutiveFailures = 0
			st.demoted = true
			st.failedWriteAttempts = 0
			continue
		}

		if isGracefulShutdown(ready) {
			// Avoid overwriting kubelet's graceful-shutdown Ready=False mid-drain.
			st.consecutiveFailures = 0
			st.demoted = false
			continue
		}

		// If Ready was updated by kubelet after an earlier demotion or parked write
		// episode, clear the parked/demoted flags before evaluating new probes.
		if st.demoted {
			st.demoted = false
			st.failedWriteAttempts = 0
		} else if st.failedWriteAttempts >= d.cfg.MaxFailedWrites &&
			(ready.LastHeartbeatTime != st.onsetHeartbeatTime || ready.LastTransitionTime != st.onsetTransitionTime) {
			st.consecutiveFailures = 0
			st.failedWriteAttempts = 0
		}

		if st.failedWriteAttempts >= d.cfg.MaxFailedWrites {
			continue
		}

		targets = append(targets, probeTarget{node: node, ready: ready})
	}

	for name := range d.states {
		if _, ok := present[name]; !ok {
			delete(d.states, name)
			d.consistencyStore.Clear(types.NamespacedName{Name: name}, "")
		}
	}

	outcomes := d.probeAll(ctx, targets)
	if ctx.Err() != nil {
		return
	}

	candidates := make([]probeTarget, 0)
	for i, target := range targets {
		st := d.states[target.node.Name]
		out := outcomes[i]

		heartbeatAdvanced := st.consecutiveFailures > 0 &&
			(target.ready.LastHeartbeatTime != st.onsetHeartbeatTime ||
				target.ready.LastTransitionTime != st.onsetTransitionTime)

		if out.err != nil {
			if heartbeatAdvanced {
				st.consecutiveFailures = 0
				st.failedWriteAttempts = 0
			}
			logger.Info("Probe returned inconclusive error; keeping failure count unchanged",
				"node", klog.KObj(target.node),
				"consecutiveFailures", st.consecutiveFailures,
				"err", out.err,
			)
			continue
		}

		if out.healthy {
			st.consecutiveFailures = 0
			st.failedWriteAttempts = 0
			st.demoted = false
			continue
		}

		if heartbeatAdvanced || st.consecutiveFailures == 0 {
			st.consecutiveFailures = 1
			st.onsetHeartbeatTime = target.ready.LastHeartbeatTime
			st.onsetTransitionTime = target.ready.LastTransitionTime
			st.failedWriteAttempts = 0
		} else {
			st.consecutiveFailures++
		}

		if st.consecutiveFailures >= d.cfg.FailureThreshold {
			candidates = append(candidates, target)
		}
	}

	if len(candidates) == 0 {
		d.resetMassDeferralIfHealthy(eligibleNodes)
		return
	}

	now := d.clock.Now()
	if now.Sub(d.startedAt) < d.cfg.WarmUpDuration {
		logger.V(2).Info("Deferring node demotions during startup warm-up",
			"candidates", len(candidates),
			"remainingWarmUp", d.cfg.WarmUpDuration-now.Sub(d.startedAt),
		)
		return
	}

	if d.shouldDeferMassFailure(logger, now, eligibleNodes) {
		return
	}

	demotions := 0
	for _, cand := range candidates {
		if demotions >= d.cfg.DemotionsPerPass {
			logger.Info("Reached per-pass demotion cap; deferring remaining candidates to next pass",
				"demotionsPerPass", d.cfg.DemotionsPerPass,
				"remaining", len(candidates)-demotions,
			)
			break
		}
		demoted, abortPass := d.tryDemoteNode(ctx, cand.node)
		if demoted {
			demotions++
		}
		if abortPass {
			break
		}
	}
}

func (d *Detector) ensureState(node *corev1.Node) *nodeState {
	st, ok := d.states[node.Name]
	if !ok || st.uid != node.UID {
		if ok {
			d.consistencyStore.Clear(types.NamespacedName{Name: node.Name}, st.uid)
		}
		st = &nodeState{uid: node.UID}
		d.states[node.Name] = st
	}
	return st
}

func (d *Detector) probeAll(ctx context.Context, targets []probeTarget) []probeOutcome {
	outcomes := make([]probeOutcome, len(targets))
	if len(targets) == 0 {
		return outcomes
	}

	workers := min(d.cfg.ProbeConcurrency, len(targets))

	jobs := make(chan int, len(targets))
	for i := range targets {
		jobs <- i
	}
	close(jobs)

	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if ctx.Err() != nil {
					outcomes[idx] = probeOutcome{err: ctx.Err()}
					continue
				}
				probeCtx, cancel := context.WithTimeout(ctx, d.cfg.ProbeTimeout)
				healthy, err := d.prober.Probe(probeCtx, targets[idx].node)
				cancel()
				// If the parent pass context was cancelled while probing, treat
				// the result as an inconclusive shutdown cancellation rather than
				// a node failure.
				if ctx.Err() != nil {
					outcomes[idx] = probeOutcome{err: ctx.Err()}
					continue
				}
				outcomes[idx] = probeOutcome{healthy: healthy, err: err}
			}
		}()
	}
	wg.Wait()
	return outcomes
}

func (d *Detector) countUnhealthyNodes() int {
	unhealthy := 0
	for _, st := range d.states {
		if st.consecutiveFailures > 0 || st.demoted {
			unhealthy++
		}
	}
	return unhealthy
}

func (d *Detector) resetMassDeferralIfHealthy(eligibleNodes int) {
	if eligibleNodes <= 2 {
		d.massDeferralSince = time.Time{}
		return
	}
	fraction := float64(d.countUnhealthyNodes()) / float64(eligibleNodes)
	if fraction <= d.cfg.MassFailureThreshold {
		d.massDeferralSince = time.Time{}
	}
}

func (d *Detector) shouldDeferMassFailure(logger klog.Logger, now time.Time, eligibleNodes int) bool {
	if eligibleNodes <= 2 {
		d.massDeferralSince = time.Time{}
		return false
	}
	unhealthy := d.countUnhealthyNodes()
	fraction := float64(unhealthy) / float64(eligibleNodes)
	if fraction <= d.cfg.MassFailureThreshold {
		d.massDeferralSince = time.Time{}
		return false
	}

	if d.massDeferralSince.IsZero() {
		d.massDeferralSince = now
	}
	elapsed := now.Sub(d.massDeferralSince)
	if d.cfg.MaxMassDeferral > 0 && elapsed >= d.cfg.MaxMassDeferral {
		logger.Info("Mass-failure deferral exceeded maxMassDeferral; proceeding with capped demotions",
			"unhealthyNodes", unhealthy,
			"eligibleNodes", eligibleNodes,
			"elapsed", elapsed,
		)
		return false
	}

	logger.Info("Deferring node demotions because failing node fraction exceeds massFailureThreshold",
		"unhealthyNodes", unhealthy,
		"eligibleNodes", eligibleNodes,
		"fraction", fraction,
		"threshold", d.cfg.MassFailureThreshold,
		"deferredFor", elapsed,
	)
	return true
}

// nodeStatusPatch omits lastHeartbeatTime intentionally so Strategic Merge Patch
// preserves kubelet's last recorded heartbeat timestamp on the Ready condition.
type nodeStatusPatch struct {
	Metadata patchObjectMeta `json:"metadata"`
	Status   patchNodeStatus `json:"status"`
}

type patchObjectMeta struct {
	UID             types.UID `json:"uid"`
	ResourceVersion string    `json:"resourceVersion"`
}

type patchNodeStatus struct {
	Conditions []patchNodeCondition `json:"conditions"`
}

type patchNodeCondition struct {
	Type               corev1.NodeConditionType `json:"type"`
	Status             corev1.ConditionStatus   `json:"status"`
	Reason             string                   `json:"reason"`
	Message            string                   `json:"message"`
	LastTransitionTime metav1.Time              `json:"lastTransitionTime"`
}

func (d *Detector) tryDemoteNode(ctx context.Context, cachedNode *corev1.Node) (demoted bool, abortPass bool) {
	logger := klog.FromContext(ctx)
	st := d.states[cachedNode.Name]

	liveNode, err := d.client.CoreV1().Nodes().Get(ctx, cachedNode.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			delete(d.states, cachedNode.Name)
			d.consistencyStore.Clear(types.NamespacedName{Name: cachedNode.Name}, cachedNode.UID)
			return false, false
		}
		logger.Error(err, "Failed live Node GET before demotion", "node", klog.KObj(cachedNode))
		return false, false
	}

	if liveNode.UID != cachedNode.UID {
		d.ensureState(liveNode)
		if liveNode.ResourceVersion != cachedNode.ResourceVersion {
			d.consistencyStore.WroteAt(types.NamespacedName{}, "", nodeGroupResource, liveNode.ResourceVersion)
		}
		return false, false
	}

	recordWatchLag := func() {
		if liveNode.ResourceVersion != cachedNode.ResourceVersion {
			d.consistencyStore.WroteAt(types.NamespacedName{}, "", nodeGroupResource, liveNode.ResourceVersion)
		}
	}

	liveReady := getReadyCondition(liveNode)
	if liveReady == nil {
		st.consecutiveFailures = 0
		st.demoted = false
		recordWatchLag()
		return false, false
	}
	if liveReady.Status == corev1.ConditionUnknown {
		st.consecutiveFailures = 0
		st.demoted = true
		st.failedWriteAttempts = 0
		recordWatchLag()
		return false, false
	}
	if isGracefulShutdown(liveReady) {
		st.consecutiveFailures = 0
		st.demoted = false
		recordWatchLag()
		return false, false
	}

	if liveReady.LastHeartbeatTime != st.onsetHeartbeatTime ||
		liveReady.LastTransitionTime != st.onsetTransitionTime {
		logger.Info("Live Node Ready condition advanced since failure onset; resetting confirmation baseline",
			"node", klog.KObj(liveNode),
		)
		st.consecutiveFailures = 1
		st.onsetHeartbeatTime = liveReady.LastHeartbeatTime
		st.onsetTransitionTime = liveReady.LastTransitionTime
		st.failedWriteAttempts = 0
		recordWatchLag()
		return false, false
	}

	patch := nodeStatusPatch{
		Metadata: patchObjectMeta{
			UID:             liveNode.UID,
			ResourceVersion: liveNode.ResourceVersion,
		},
		Status: patchNodeStatus{
			Conditions: []patchNodeCondition{
				{
					Type:               corev1.NodeReady,
					Status:             corev1.ConditionUnknown,
					Reason:             d.cfg.Reason,
					Message:            d.cfg.Message,
					LastTransitionTime: metav1.NewTime(d.clock.Now().UTC()),
				},
			},
		},
	}
	patchBytes, err := json.Marshal(patch)
	if err != nil {
		logger.Error(err, "Failed to marshal Strategic Merge Patch", "node", klog.KObj(liveNode))
		return false, false
	}

	patchedNode, err := d.client.CoreV1().Nodes().Patch(
		ctx,
		liveNode.Name,
		types.StrategicMergePatchType,
		patchBytes,
		metav1.PatchOptions{},
		"status",
	)
	if err != nil {
		if errors.Is(err, leaderelection.ErrWriteGateClosed) {
			logger.V(2).Info("Aborting demotion pass because leader election write gate is closed",
				"node", klog.KObj(liveNode),
			)
			return false, true
		}
		if apierrors.IsNotFound(err) {
			delete(d.states, liveNode.Name)
			d.consistencyStore.Clear(types.NamespacedName{Name: liveNode.Name}, liveNode.UID)
			return false, false
		}
		if apierrors.IsConflict(err) {
			logger.V(2).Info("Aborted node status demotion due to concurrent ResourceVersion conflict",
				"node", klog.KObj(liveNode),
			)
			return false, false
		}
		st.failedWriteAttempts++
		logger.Error(err, "Failed to patch node Ready=Unknown",
			"node", klog.KObj(liveNode),
			"failedWriteAttempts", st.failedWriteAttempts,
		)
		return false, false
	}

	if patchedNode != nil && patchedNode.ResourceVersion != "" {
		d.consistencyStore.WroteAt(
			types.NamespacedName{Name: liveNode.Name},
			liveNode.UID,
			nodeGroupResource,
			patchedNode.ResourceVersion,
		)
	}
	st.consecutiveFailures = 0
	st.demoted = true
	st.failedWriteAttempts = 0
	logger.Info("Demoted unreachable node to Ready=Unknown",
		"node", klog.KObj(liveNode),
		"reason", d.cfg.Reason,
	)
	return true, false
}

func getReadyCondition(node *corev1.Node) *corev1.NodeCondition {
	if node == nil {
		return nil
	}
	for i := range node.Status.Conditions {
		if node.Status.Conditions[i].Type == corev1.NodeReady {
			return &node.Status.Conditions[i]
		}
	}
	return nil
}

func isGracefulShutdown(cond *corev1.NodeCondition) bool {
	if cond == nil {
		return false
	}
	return cond.Status == corev1.ConditionFalse &&
		cond.Reason == "KubeletNotReady" &&
		strings.Contains(cond.Message, "node is shutting down")
}
