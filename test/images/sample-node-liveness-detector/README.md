# Sample Node Liveness Detector (KEP-6371)

Reference external node liveness detector for
[KEP-6371: External Node Liveness Detection](https://github.com/kubernetes/enhancements/tree/master/keps/sig-node/6371-external-node-liveness-detection).

## Architecture

- **`detector`**: Signal-agnostic reconciliation loop over a `Node` informer and
  a single-method `Prober` interface (`Probe(ctx, node) (healthy bool, err error)`).
  - Confirms persistent failure across `--failure-threshold` (`>= 2`) passes.
  - Guards `nodes/status` Strategic Merge Patches with a live `Node` `GET`,
    onset `lastHeartbeatTime`/`lastTransitionTime` checks, `metadata.uid` +
    `metadata.resourceVersion` preconditions (leaving `lastHeartbeatTime` and
    pressure conditions untouched), and `k8s.io/client-go/util/consistency`
    (`ConsistencyStore`) to avoid re-demoting or repeating live `GET`s while the
    informer cache lags.
  - Enforces startup warm-up (`--warmup-duration`), monotonic-clock pause reset
    (`elapsed > 2 * --probe-interval`), per-pass demotion caps
    (`--demotions-per-pass`), and mass-failure deferral (`--mass-failure-threshold`,
    default `0.55` on clusters with `> 2` nodes, bounded by `--max-mass-deferral`).
- **`prober`**: Default HTTPS prober targeting each node's kubelet
  `https://<NodeInternalIP>:10250/healthz` (`get` on `nodes/healthz`), mapping
  dial/TLS-handshake/read timeouts, connection refusals/resets, and failing
  `/healthz` checks (`[-]syncloop failed`) to `(false, nil)` while treating PKI,
  `401`/`403`, `SubjectAccessReview` webhook `500` `"Authorization error"`
  responses, and missing `NodeInternalIP` addresses as inconclusive `(_, err)`.
- **`main`**: CLI entrypoint supporting optional Lease-based leader election
  (`--leader-elect`) with KEP-6361 `Recovery` and `LeaderElector.WriteGate`
  wrapping the `nodes/status` client while keeping the `LeaseLock` client ungated.

## Rollout Order

1. Deploy `sample-node-liveness-detector` (`manifests/rbac.yaml` and
   `manifests/deployment.yaml`).
2. Configure every `kube-controller-manager` replica with
   `--feature-gates=ExternalNodeLivenessDetection=true` and
   `--node-liveness-source=external`.
3. Configure kubelets with `ExternalNodeLivenessDetection: true` and
   `enableNodeLease: false`.

Disable in reverse order (`enableNodeLease: true` on kubelets before switching
`kube-controller-manager` back to `--node-liveness-source=kubelet`).
