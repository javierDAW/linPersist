// Package k8sstatic implements the linpersist collector for
// Kubernetes static-pod persistence on Linux.
//
// A static pod is a Pod manifest YAML file placed in the kubelet's
// `--pod-manifest-path` directory (default
// /etc/kubernetes/manifests/). The kubelet reads every such file
// at startup AND on file change, then runs the containers
// described inside, with no involvement from the Kubernetes API
// server, scheduler or controllers. The pod restarts automatically
// if its containers exit. From an attacker perspective static pods
// are an extremely quiet persistence vector on any node running
// kubelet (every control-plane node, every worker node in a
// kubeadm cluster, every k3s node) because:
//
//   - they do not appear in `kubectl get pods` unless the node-
//     name selector is used and they are visible under the
//     `kube-system` namespace mirror
//   - they survive cluster RBAC rotation (kubelet enforces no RBAC
//     against itself for these)
//   - they survive control-plane downtime
//
// Site_class emitted:
//
//   - k8s.static-pod   one record per *.yaml or *.yml file under
//     /etc/kubernetes/manifests/ (the default) and
//     any other directory documented as a pod
//     manifest path. The agent extracts the first
//     container image and the first container
//     command (if any) from the YAML; these land
//     in ExecTarget so Q6 / Q12 can cluster them
//     across hosts.
//
// MITRE T1543.005 (Create or Modify System Process: Container
// Service). Documented in matrix.yaml notes.
//
// YAML parsing is intentionally line-oriented — bringing in
// gopkg.in/yaml.v3 here would deserialize the whole Pod spec for
// extracting two strings, and the agent's "pure Go, stdlib first"
// charter (handoff §1.7) keeps optional dependencies to a minimum.
// gopkg.in/yaml.v3 is already pulled in by cmd/matrix-audit, so
// the cost is zero — we use it because hand-rolled YAML parsing
// for this misses indentation edge cases.
package k8sstatic

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jarmidaw/linpersist/internal/core"
)

const (
	mitreContainerService = "T1543.005"
	siteClassStaticPod    = "k8s.static-pod"
)

// manifestDirs are the kubelet-monitored directories. Order is
// load-bearing for determinism. Beyond the kubeadm default, k3s,
// minikube and managed-k8s distros sometimes use
// /var/lib/rancher/k3s/agent/pod-manifests or similar — operators
// extend via Options.Roots in non-default deployments.
var manifestDirs = []string{
	"/etc/kubernetes/manifests",
}

// DefaultMaxFileSize bounds one Pod manifest. Real manifests are
// well under 16 KiB; 1 MiB is the project-wide safety net.
const DefaultMaxFileSize = 1 << 20

// Options configures the k8sstatic module.
type Options struct {
	Root        string
	Roots       []string
	Now         func() time.Time
	MaxFileSize int64
	// Provenance annotates the container image string as the
	// exec_target. Container images are not package-managed in the
	// dpkg/rpm sense, so non_package_path fires unconditionally on
	// every k8s.static-pod record — useful as a contrast indicator
	// against host-side persistence.
	Provenance core.Provenance
	// LiveProcessSet check applies to the container image string,
	// which is virtually never a host binary path. The annotation
	// rarely fires for this module but is wired uniformly for
	// future-proofing (e.g. an attacker who lifts a host binary
	// into a Pod for execution).
	LiveProcessSet core.LiveProcessSet
}

// Module collects Kubernetes static-pod persistence sites.
type Module struct{ opts Options }

// New constructs a k8sstatic Module with default fallbacks.
func New(opts Options) *Module {
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = DefaultMaxFileSize
	}
	if opts.Provenance == nil {
		opts.Provenance = core.NoopProvenance{}
	}
	if opts.LiveProcessSet == nil {
		opts.LiveProcessSet = core.NoopLiveProcessSet{}
	}
	return &Module{opts: opts}
}

// Compile-time interface conformance.
var _ core.Module = (*Module)(nil)

// Name returns the module identifier.
func (m *Module) Name() string { return "k8sstatic" }

// SiteClasses returns the single class this module emits.
func (m *Module) SiteClasses() []string { return []string{siteClassStaticPod} }

// Collect walks every configured manifest dir and emits one record
// per Pod YAML. Missing dirs are silent — most hosts do not run
// kubelet.
func (m *Module) Collect(ctx context.Context, emit func(core.Record)) error {
	roots := m.opts.Roots
	if roots == nil {
		roots = manifestDirs
	}
	var errs []error
	for _, d := range roots {
		if err := m.walkDir(ctx, d, emit); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (m *Module) resolve(logical string) string {
	if m.opts.Root == "" {
		return logical
	}
	return filepath.Join(m.opts.Root, logical)
}

func (m *Module) walkDir(ctx context.Context, logicalDir string, emit func(core.Record)) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	realDir := m.resolve(logicalDir)
	entries, err := os.ReadDir(realDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("readdir %s: %w", logicalDir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if skipName(name) {
			continue
		}
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		logical := filepath.Join(logicalDir, name)
		real := filepath.Join(realDir, name)
		info, err := os.Lstat(real)
		if err != nil {
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		m.processFile(logical, real, info, emit)
	}
	return nil
}

// minimalPod is the slice of the Pod spec the agent actually
// reads. Everything else in the YAML is ignored — we are interested
// in surfacing the persistence target, not validating the spec.
type minimalPod struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Spec struct {
		Containers []struct {
			Name    string   `yaml:"name"`
			Image   string   `yaml:"image"`
			Command []string `yaml:"command"`
		} `yaml:"containers"`
	} `yaml:"spec"`
}

func (m *Module) processFile(logical, real string, info os.FileInfo, emit func(core.Record)) {
	if info.Size() > m.opts.MaxFileSize {
		emit(m.envelopeRecord(logical, info, []core.RecordError{
			{Field: "content_sha256", Code: "SIZE_LIMIT"},
		}))
		return
	}
	raw, err := os.ReadFile(real)
	if err != nil {
		emit(m.envelopeRecord(logical, info, []core.RecordError{
			{Field: "content_sha256", Code: errnoCode(err), Msg: err.Error()},
		}))
		return
	}
	var pod minimalPod
	parseErrs := []core.RecordError{}
	if err := yaml.Unmarshal(raw, &pod); err != nil {
		// Continue with empty pod; the analyst still sees the file
		// existence and a parse error envelope.
		parseErrs = append(parseErrs, core.RecordError{
			Field: "content_norm_sha256", Code: "PARSE_ERROR", Msg: err.Error(),
		})
	}
	canon := canonical(pod)
	rec := core.Record{
		Module:            m.Name(),
		SiteClass:         siteClassStaticPod,
		MITRE:             []string{mitreContainerService},
		Locus:             logical,
		ContentSHA256:     core.HashHex(raw),
		ContentNormSHA256: core.HashHex([]byte(canon)),
		ContentSnippet:    snippet(canon),
	}
	if len(parseErrs) > 0 {
		rec.Errors = parseErrs
	}
	core.FillFileMeta(&rec, info)
	signals := m.baseSignals(info, logical)

	// Persistence target = first container's image + command tuple.
	// In the common Pod-of-one-container case this is unambiguous;
	// for multi-container pods we surface the first because the rest
	// are visible in content_snippet. Multi-container static pods
	// are rare in attacker workflows (kube-apiserver, etcd, scheduler
	// are single-container; an attacker dropping a static pod almost
	// always uses one container for the payload).
	if len(pod.Spec.Containers) > 0 {
		c := pod.Spec.Containers[0]
		if c.Image != "" {
			rec.ExecTarget = c.Image
			if c.Image != "" && !strings.Contains(c.Image, "/") {
				// Bare image name (no registry, no project) is rare
				// in legitimate static pods (those use full refs like
				// registry.k8s.io/kube-apiserver:v1.30.1); flag it as
				// unqualified so the operator notices.
				signals = append(signals, core.SignalUnqualifiedExecTarget)
			}
		}
	}
	rec.Signals = core.DedupSignals(signals)
	core.AnnotateExecTargetProvenance(&rec, m.opts.Provenance, rec.ExecTarget)
	core.AnnotateLiveProcess(&rec, m.opts.LiveProcessSet, rec.ExecTarget)
	emit(rec)
}

// canonical renders the parsed pod into a deterministic byte
// sequence for content_norm_sha256. Only the fields that matter
// for persistence intent are included; resource requests, annota-
// tions, labels and securityContext are intentionally excluded
// because operators tune them per environment without changing
// the implant shape.
func canonical(p minimalPod) string {
	var b strings.Builder
	b.WriteString("kind=")
	b.WriteString(p.Kind)
	b.WriteString("\nnamespace=")
	b.WriteString(p.Metadata.Namespace)
	b.WriteString("\nname=")
	b.WriteString(p.Metadata.Name)
	b.WriteString("\n")
	for _, c := range p.Spec.Containers {
		b.WriteString("container=")
		b.WriteString(c.Name)
		b.WriteString(" image=")
		b.WriteString(c.Image)
		if len(c.Command) > 0 {
			b.WriteString(" command=")
			b.WriteString(strings.Join(c.Command, " "))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func (m *Module) envelopeRecord(logical string, info os.FileInfo, errs []core.RecordError) core.Record {
	rec := core.Record{
		Module:    m.Name(),
		SiteClass: siteClassStaticPod,
		MITRE:     []string{mitreContainerService},
		Locus:     logical,
		Errors:    errs,
	}
	if info != nil {
		core.FillFileMeta(&rec, info)
		rec.Signals = core.DedupSignals(m.baseSignals(info, logical))
	}
	return rec
}

func (m *Module) baseSignals(info os.FileInfo, logical string) []string {
	var out []string
	now := m.opts.Now()
	mt := info.ModTime().UTC()
	delta := now.Sub(mt)
	switch {
	case delta >= 0 && delta < 7*24*time.Hour:
		out = append(out, core.SignalRecentMtime7d)
	case delta >= 7*24*time.Hour && delta < 30*24*time.Hour:
		out = append(out, core.SignalRecentMtime30d)
	}
	if info.Mode().Perm()&0o002 != 0 {
		out = append(out, core.SignalWorldWritable)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		if st.Uid != 0 && strings.HasPrefix(logical, "/etc/") {
			out = append(out, core.SignalNonRootOwner)
		}
	}
	return out
}

func skipName(name string) bool {
	if strings.HasPrefix(name, ".") {
		return true
	}
	if strings.HasSuffix(name, "~") {
		return true
	}
	for _, frag := range []string{".dpkg-", ".rpmsave", ".rpmnew", ".bak"} {
		if strings.Contains(name, frag) {
			return true
		}
	}
	return false
}

func snippet(s string) string {
	const max = 256
	if len(s) <= max {
		return s
	}
	return s[:max]
}

func errnoCode(err error) string {
	if errors.Is(err, fs.ErrNotExist) {
		return "ENOENT"
	}
	if errors.Is(err, fs.ErrPermission) {
		return "EACCES"
	}
	return "IO_ERROR"
}
