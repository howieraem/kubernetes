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

// Command sample-node-liveness-detector is a reference KEP-6371 external node
// liveness detector that probes kubelet /healthz over HTTPS and marks
// unreachable nodes Ready=Unknown.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/klog/v2"

	"k8s.io/kubernetes/test/images/sample-node-liveness-detector/detector"
	"k8s.io/kubernetes/test/images/sample-node-liveness-detector/prober"
)

type options struct {
	kubeconfig   string
	resyncPeriod time.Duration

	detectorCfg detector.Config

	kubeletPort            int
	kubeletHealthzPath     string
	kubeletCAFile          string
	kubeletCertFile        string
	kubeletKeyFile         string
	kubeletBearerTokenFile string
	kubeletInsecureTLS     bool

	leaderElect                 bool
	leaderElectLeaseNamespace   string
	leaderElectLeaseName        string
	leaderElectIdentity         string
	leaderElectLeaseDuration    time.Duration
	leaderElectRenewDeadline    time.Duration
	leaderElectRetryPeriod      time.Duration
	leaderElectRecoveryDeadline time.Duration
}

func defaultOptions() *options {
	return &options{
		detectorCfg:                 detector.DefaultConfig(),
		kubeletPort:                 prober.DefaultKubeletPort,
		kubeletHealthzPath:          prober.DefaultHealthzPath,
		leaderElect:                 false,
		leaderElectLeaseNamespace:   "kube-system",
		leaderElectLeaseName:        "sample-node-liveness-detector",
		leaderElectLeaseDuration:    15 * time.Second,
		leaderElectRenewDeadline:    10 * time.Second,
		leaderElectRetryPeriod:      2 * time.Second,
		leaderElectRecoveryDeadline: 5 * time.Minute,
	}
}

func (o *options) addFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.kubeconfig, "kubeconfig", o.kubeconfig, "Path to a kubeconfig file; uses in-cluster configuration when empty.")
	fs.DurationVar(&o.resyncPeriod, "resync-period", o.resyncPeriod, "Informer resync period (0 disables periodic full resyncs).")

	fs.DurationVar(&o.detectorCfg.ProbeInterval, "probe-interval", o.detectorCfg.ProbeInterval, "Interval between node health probe passes.")
	fs.DurationVar(&o.detectorCfg.ProbeTimeout, "probe-timeout", o.detectorCfg.ProbeTimeout, "Per-node probe timeout.")
	fs.IntVar(&o.detectorCfg.ProbeConcurrency, "probe-concurrency", o.detectorCfg.ProbeConcurrency, "Maximum concurrent node probes per pass.")
	fs.IntVar(&o.detectorCfg.FailureThreshold, "failure-threshold", o.detectorCfg.FailureThreshold, "Consecutive unhealthy probe passes required before demoting a node (>= 2).")
	fs.DurationVar(&o.detectorCfg.WarmUpDuration, "warmup-duration", o.detectorCfg.WarmUpDuration, "Startup warm-up duration during which node demotions are deferred.")
	fs.IntVar(&o.detectorCfg.DemotionsPerPass, "demotions-per-pass", o.detectorCfg.DemotionsPerPass, "Maximum number of nodes demoted to Ready=Unknown in a single pass.")
	fs.Float64Var(&o.detectorCfg.MassFailureThreshold, "mass-failure-threshold", o.detectorCfg.MassFailureThreshold, "Fraction of failing nodes in (0, 1] above which demotions are deferred on clusters with > 2 nodes.")
	fs.DurationVar(&o.detectorCfg.MaxMassDeferral, "max-mass-deferral", o.detectorCfg.MaxMassDeferral, "Maximum duration mass-failure deferral suppresses demotions before capped demotions proceed.")
	fs.IntVar(&o.detectorCfg.MaxFailedWrites, "max-failed-writes", o.detectorCfg.MaxFailedWrites, "Maximum consecutive non-conflict status patch failures before parking writes for a node episode.")
	fs.StringVar(&o.detectorCfg.Reason, "reason", o.detectorCfg.Reason, "Node Ready=Unknown condition reason (must not be NodeStatusUnknown).")
	fs.StringVar(&o.detectorCfg.Message, "message", o.detectorCfg.Message, "Node Ready=Unknown condition message.")

	fs.IntVar(&o.kubeletPort, "kubelet-port", o.kubeletPort, "HTTPS port on each node's kubelet serving /healthz.")
	fs.StringVar(&o.kubeletHealthzPath, "kubelet-healthz-path", o.kubeletHealthzPath, "HTTP path probed on each node's kubelet.")
	fs.StringVar(&o.kubeletCAFile, "kubelet-certificate-authority", o.kubeletCAFile, "CA bundle for verifying kubelet serving certificates (defaults to the cluster CA when --kubelet-insecure-skip-verify is false).")
	fs.StringVar(&o.kubeletCertFile, "kubelet-client-certificate", o.kubeletCertFile, "Client certificate for mTLS authentication to kubelet.")
	fs.StringVar(&o.kubeletKeyFile, "kubelet-client-key", o.kubeletKeyFile, "Client private key for mTLS authentication to kubelet.")
	fs.StringVar(&o.kubeletBearerTokenFile, "kubelet-bearer-token-file", o.kubeletBearerTokenFile, "Bearer token file for kubelet authentication when client certificates are not configured.")
	fs.BoolVar(&o.kubeletInsecureTLS, "kubelet-insecure-skip-verify", o.kubeletInsecureTLS, "Skip TLS certificate verification when probing kubelet /healthz (for development/kind clusters with self-signed kubelet certs).")

	fs.BoolVar(&o.leaderElect, "leader-elect", o.leaderElect, "Enable Lease-based leader election with KEP-6361 WriteGate and Recovery.")
	fs.StringVar(&o.leaderElectLeaseNamespace, "leader-elect-lease-namespace", o.leaderElectLeaseNamespace, "Namespace of the leader election Lease object.")
	fs.StringVar(&o.leaderElectLeaseName, "leader-elect-lease-name", o.leaderElectLeaseName, "Name of the leader election Lease object.")
	fs.StringVar(&o.leaderElectIdentity, "leader-elect-identity", o.leaderElectIdentity, "Unique holder identity for leader election (defaults to $POD_NAME or hostname + UUID).")
	fs.DurationVar(&o.leaderElectLeaseDuration, "leader-elect-lease-duration", o.leaderElectLeaseDuration, "Duration non-leaders wait before acquiring an unrenewed leader Lease.")
	fs.DurationVar(&o.leaderElectRenewDeadline, "leader-elect-renew-deadline", o.leaderElectRenewDeadline, "Duration the acting leader retries Lease renewal before stepping down.")
	fs.DurationVar(&o.leaderElectRetryPeriod, "leader-elect-retry-period", o.leaderElectRetryPeriod, "Interval between leader election Lease acquisition/renewal attempts.")
	fs.DurationVar(&o.leaderElectRecoveryDeadline, "leader-elect-recovery-deadline", o.leaderElectRecoveryDeadline, "Maximum duration to attempt KEP-6361 leader Lease recovery after transient API loss (must be >= 1s when set).")
}

func (o *options) validate() error {
	if err := o.detectorCfg.Validate(); err != nil {
		return err
	}
	if (o.kubeletCertFile == "") != (o.kubeletKeyFile == "") {
		return fmt.Errorf("--kubelet-client-certificate and --kubelet-client-key must both be set or both be empty")
	}
	if o.kubeletInsecureTLS && o.kubeletCAFile != "" {
		return fmt.Errorf("--kubelet-certificate-authority cannot be combined with --kubelet-insecure-skip-verify")
	}
	if o.leaderElect {
		if strings.TrimSpace(o.leaderElectLeaseNamespace) == "" {
			return fmt.Errorf("--leader-elect-lease-namespace must not be empty when --leader-elect is enabled")
		}
		if strings.TrimSpace(o.leaderElectLeaseName) == "" {
			return fmt.Errorf("--leader-elect-lease-name must not be empty when --leader-elect is enabled")
		}
		if o.leaderElectRecoveryDeadline < time.Second {
			return fmt.Errorf("--leader-elect-recovery-deadline (%v) must be at least 1s", o.leaderElectRecoveryDeadline)
		}
	}
	return nil
}

func buildProberConfig(o *options, baseCfg *rest.Config) prober.KubeletHealthzConfig {
	pCfg := prober.KubeletHealthzConfig{
		Port:        o.kubeletPort,
		Path:        o.kubeletHealthzPath,
		CAFile:      o.kubeletCAFile,
		CertFile:    o.kubeletCertFile,
		KeyFile:     o.kubeletKeyFile,
		InsecureTLS: o.kubeletInsecureTLS,
	}
	if !o.kubeletInsecureTLS && pCfg.CAFile == "" && baseCfg != nil {
		pCfg.CAFile = baseCfg.CAFile
	}
	if pCfg.CertFile == "" {
		if o.kubeletBearerTokenFile != "" {
			pCfg.BearerTokenFile = o.kubeletBearerTokenFile
		} else if baseCfg != nil {
			pCfg.BearerToken = baseCfg.BearerToken
			pCfg.BearerTokenFile = baseCfg.BearerTokenFile
		}
	}
	return pCfg
}

func resolveLeaderIdentity(explicit string) (string, error) {
	if id := strings.TrimSpace(explicit); id != "" {
		return id, nil
	}
	if podName := strings.TrimSpace(os.Getenv("POD_NAME")); podName != "" {
		return podName, nil
	}
	host, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("resolving hostname for leader election identity: %w", err)
	}
	return fmt.Sprintf("%s_%s", host, uuid.NewUUID()), nil
}

// buildClientsAndElector wires an ungated LeaseLock client and a WriteGate-wrapped
// Node client when leader election is enabled, so in-flight nodes/status patches
// are immediately rejected with ErrWriteGateClosed if leadership is lost while
// Lease renewal continues over the ungated client.
func buildClientsAndElector(
	o *options,
	baseCfg *rest.Config,
	onStartedLeading func(context.Context),
	onStoppedLeading func(),
) (nodeClient kubernetes.Interface, elector *leaderelection.LeaderElector, err error) {
	if !o.leaderElect {
		client, err := kubernetes.NewForConfig(rest.CopyConfig(baseCfg))
		if err != nil {
			return nil, nil, fmt.Errorf("building kubernetes client: %w", err)
		}
		return client, nil, nil
	}

	identity, err := resolveLeaderIdentity(o.leaderElectIdentity)
	if err != nil {
		return nil, nil, err
	}

	leaseClient, err := kubernetes.NewForConfig(rest.CopyConfig(baseCfg))
	if err != nil {
		return nil, nil, fmt.Errorf("building ungated leader-election client: %w", err)
	}

	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Namespace: o.leaderElectLeaseNamespace,
			Name:      o.leaderElectLeaseName,
		},
		Client: leaseClient.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: identity,
		},
	}

	recoveryDeadline := o.leaderElectRecoveryDeadline
	elector, err = leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock:          lock,
		LeaseDuration: o.leaderElectLeaseDuration,
		RenewDeadline: o.leaderElectRenewDeadline,
		RetryPeriod:   o.leaderElectRetryPeriod,
		Name:          o.leaderElectLeaseName,
		Recovery: &leaderelection.RecoveryConfig{
			RecoveryDeadline: &recoveryDeadline,
		},
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: onStartedLeading,
			OnStoppedLeading: onStoppedLeading,
		},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("building leader elector: %w", err)
	}

	gatedCfg := rest.CopyConfig(baseCfg)
	gatedCfg.Wrap(elector.WriteGate())
	nodeClient, err = kubernetes.NewForConfig(gatedCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("building WriteGate-wrapped node client: %w", err)
	}

	return nodeClient, elector, nil
}

func run(ctx context.Context, o *options) error {
	logger := klog.FromContext(ctx)

	var (
		baseCfg *rest.Config
		err     error
	)
	if o.kubeconfig != "" {
		baseCfg, err = clientcmd.BuildConfigFromFlags("", o.kubeconfig)
	} else {
		baseCfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return fmt.Errorf("loading kubernetes client configuration: %w", err)
	}

	healthzProber, err := prober.NewKubeletHealthzProber(buildProberConfig(o, baseCfg))
	if err != nil {
		return err
	}

	var det *detector.Detector
	runErrCh := make(chan error, 1)

	nodeClient, elector, err := buildClientsAndElector(
		o,
		baseCfg,
		func(leadCtx context.Context) {
			if err := det.Run(leadCtx); err != nil {
				select {
				case runErrCh <- err:
				default:
				}
			}
		},
		func() {
			logger.Info("Leader lease lost or temporarily unrenewed; WriteGate closed for nodes/status writes")
		},
	)
	if err != nil {
		return err
	}

	factory := informers.NewSharedInformerFactory(nodeClient, o.resyncPeriod)
	nodeInformer := factory.Core().V1().Nodes()

	det, err = detector.New(nodeClient, nodeInformer, healthzProber, o.detectorCfg)
	if err != nil {
		return err
	}

	factory.Start(ctx.Done())

	if elector == nil {
		return det.Run(ctx)
	}

	elector.Run(ctx)
	select {
	case err := <-runErrCh:
		return err
	default:
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("leader election exited after losing lease")
	}
}

func main() {
	klog.InitFlags(nil)
	opts := defaultOptions()

	fs := pflag.NewFlagSet("sample-node-liveness-detector", pflag.ExitOnError)
	fs.AddGoFlagSet(flag.CommandLine)
	opts.addFlags(fs)
	_ = fs.Parse(os.Args[1:])

	if err := opts.validate(); err != nil {
		fmt.Fprintf(os.Stderr, "invalid configuration: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, opts); err != nil {
		klog.FromContext(ctx).Error(err, "Detector exited with error")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}
}
