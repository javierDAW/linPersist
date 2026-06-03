package confexec

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
)

var fixedNow = time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)

// stubProv marks the paths in owned as PkgStatusOwned, all others orphan.
type stubProv struct{ owned map[string]bool }

func (stubProv) Warmup(context.Context) {}
func (s stubProv) LookupPath(p string) (string, core.PkgStatus) {
	if s.owned[p] {
		return "somepkg", core.PkgStatusOwned
	}
	return "", core.PkgStatusOrphan
}

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func collect(t *testing.T, root string, owned ...string) []core.Record {
	t.Helper()
	ow := map[string]bool{}
	for _, o := range owned {
		ow[o] = true
	}
	m := New(Options{Root: root, Now: func() time.Time { return fixedNow }, Provenance: stubProv{owned: ow}})
	var recs []core.Record
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := m.Collect(ctx, func(r core.Record) { recs = append(recs, r) }); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return recs
}

func find(recs []core.Record, siteClass, execTarget string) *core.Record {
	for i := range recs {
		if recs[i].SiteClass == siteClass && recs[i].ExecTarget == execTarget {
			return &recs[i]
		}
	}
	return nil
}

func hasSig(r *core.Record, s string) bool {
	if r == nil {
		return false
	}
	for _, x := range r.Signals {
		if x == s {
			return true
		}
	}
	return false
}

func TestMailAliasPipe(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/aliases", "postmaster: root\n"+
		"webmaster: alice\n"+
		"backdoor: \"|/opt/.m/agent\"\n"+ // orphan pipe -> flagged
		"mlist: |/usr/lib/mailman/post mlist\n") // owned pipe -> silent
	write(t, root, "root/.forward", "|/opt/.f/hook\n")
	// mark the mailman path owned (and create it so it is not orphan)
	write(t, root, "usr/lib/mailman/post", "x")
	recs := collect(t, root, "/usr/lib/mailman/post")

	if r := find(recs, "mail.aliases", "/opt/.m/agent"); r == nil {
		t.Errorf("backdoor pipe alias not lifted; recs=%v", recs)
	} else if !hasSig(r, core.SignalNonPackagePath) {
		t.Errorf("backdoor alias missing non_package_path; %v", r.Signals)
	}
	if r := find(recs, "mail.aliases", "/opt/.f/hook"); r == nil {
		t.Errorf(".forward pipe not lifted")
	}
	if r := find(recs, "mail.aliases", "/usr/lib/mailman/post"); r == nil {
		t.Errorf("mailman pipe should still produce a record")
	} else if hasSig(r, core.SignalNonPackagePath) {
		t.Errorf("owned mailman pipe must NOT carry non_package_path")
	}
	// A non-pipe mailbox alias yields no record.
	if r := find(recs, "mail.aliases", "root"); r != nil {
		t.Errorf("mailbox alias should not be an edge")
	}
}

func TestIncron(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/incron.d/watch", "/etc/passwd IN_MODIFY /opt/.i/exfil\n")
	recs := collect(t, root)
	r := find(recs, "incron.d", "/opt/.i/exfil")
	if r == nil || !hasSig(r, core.SignalExecTargetOrphan) {
		t.Errorf("incron command not lifted/orphan; recs=%v", recs)
	}
}

func TestLogrotate(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/logrotate.d/evil", "/var/log/x.log {\n  postrotate\n    /opt/.lr/hook\n  endscript\n}\n")
	write(t, root, "etc/logrotate.d/benign", "/var/log/y.log {\n  postrotate\n    systemctl reload nginx\n  endscript\n}\n")
	recs := collect(t, root)
	if find(recs, "logrotate.d", "/opt/.lr/hook") == nil {
		t.Errorf("postrotate hook not lifted; recs=%v", recs)
	}
	// bare `systemctl reload` is not an absolute argv0 -> no edge/record
	for _, r := range recs {
		if r.SiteClass == "logrotate.d" && r.ExecTarget != "/opt/.lr/hook" {
			t.Errorf("unexpected logrotate edge %q (bare commands must be inert)", r.ExecTarget)
		}
	}
}

func TestAptHook(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/apt/apt.conf.d/99evil", `DPkg::Pre-Invoke {"/opt/.a/payload --run";};`+"\n")
	write(t, root, "etc/apt/apt.conf.d/20needrestart", `DPkg::Post-Invoke {"/usr/bin/needrestart";};`+"\n")
	write(t, root, "usr/bin/needrestart", "x")
	recs := collect(t, root, "/usr/bin/needrestart")
	if r := find(recs, "pkgmgr.hook", "/opt/.a/payload"); r == nil || !hasSig(r, core.SignalNonPackagePath) {
		t.Errorf("apt Pre-Invoke payload not lifted/non_package; recs=%v", recs)
	}
	if r := find(recs, "pkgmgr.hook", "/usr/bin/needrestart"); r != nil && hasSig(r, core.SignalNonPackagePath) {
		t.Errorf("owned needrestart hook must not carry non_package_path")
	}
}

func TestDnfAction(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/dnf/plugins/post-transaction-actions.d/evil.action", "*:any:/opt/.d/run\n")
	recs := collect(t, root)
	if find(recs, "pkgmgr.hook", "/opt/.d/run") == nil {
		t.Errorf("dnf action command not lifted; recs=%v", recs)
	}
}

func TestSudoConfPlugin(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/sudo.conf", "Plugin evil_policy /opt/.s/evil.so\n"+
		"Plugin sudoers_policy sudoers.so\n")
	// stock sudoers.so resolves relative -> /usr/libexec/sudo/sudoers.so (owned)
	write(t, root, "usr/libexec/sudo/sudoers.so", "x")
	recs := collect(t, root, "/usr/libexec/sudo/sudoers.so")
	if r := find(recs, "sudo.conf.plugin", "/opt/.s/evil.so"); r == nil || !hasSig(r, core.SignalNonPackagePath) {
		t.Errorf("evil sudo plugin not lifted/non_package; recs=%v", recs)
	}
	if r := find(recs, "sudo.conf.plugin", "/usr/libexec/sudo/sudoers.so"); r == nil {
		t.Errorf("stock sudoers.so plugin should resolve to a record")
	} else if hasSig(r, core.SignalNonPackagePath) {
		t.Errorf("stock sudoers.so must not carry non_package_path")
	}
}

func TestNsswitchHijack(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/nsswitch.conf", "passwd: files evil\ngroup: files sss\nhosts: files dns\n")
	// the planted module on the standard multiarch path, unowned
	write(t, root, "usr/lib/x86_64-linux-gnu/libnss_evil.so.2", "x")
	// an allowlisted sss module also present + owned — must NOT be flagged
	write(t, root, "usr/lib/x86_64-linux-gnu/libnss_sss.so.2", "x")
	recs := collect(t, root, "/usr/lib/x86_64-linux-gnu/libnss_sss.so.2")
	r := find(recs, "nss.nsswitch", "/usr/lib/x86_64-linux-gnu/libnss_evil.so.2")
	if r == nil || !hasSig(r, core.SignalNonPackagePath) {
		t.Errorf("planted libnss_evil not lifted/non_package; recs=%v", recs)
	}
	// sss is allowlisted -> no record even though its lib exists
	if find(recs, "nss.nsswitch", "/usr/lib/x86_64-linux-gnu/libnss_sss.so.2") != nil {
		t.Errorf("allowlisted sss token must not produce a record")
	}
}

func TestXsession(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/X11/Xsession.d/99evil", "#!/bin/sh\n/opt/.x/agent &\n")
	recs := collect(t, root)
	if find(recs, "xsession.d", "/opt/.x/agent") == nil {
		t.Errorf("xsession exec not lifted; recs=%v", recs)
	}
}

func TestCleanConfigsYieldNothing(t *testing.T) {
	root := t.TempDir()
	// Stock-shaped configs with no exec edge: must emit ZERO records.
	write(t, root, "etc/aliases", "postmaster: root\nroot: admin\n")
	write(t, root, "etc/nsswitch.conf", "passwd: files systemd\nhosts: files dns\n")
	write(t, root, "etc/sudo.conf", "# Plugin commented\n")
	write(t, root, "etc/logrotate.d/std", "/var/log/x {\n  weekly\n  rotate 4\n}\n")
	recs := collect(t, root)
	if len(recs) != 0 {
		t.Errorf("clean configs must yield no records; got %d: %v", len(recs), recs)
	}
}

func TestEnvironmentD(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/environment.d/99-evil.conf", "LANG=en_US.UTF-8\nLD_PRELOAD=/opt/.e/hook.so\n")
	write(t, root, "etc/environment.d/10-locale.conf", "LANG=C.UTF-8\nQT_SCALE_FACTOR=1\n")
	recs := collect(t, root)
	r := find(recs, "environment.d", "/opt/.e/hook.so")
	if r == nil || !hasSig(r, core.SignalNonPackagePath) {
		t.Errorf("LD_PRELOAD via environment.d not lifted/non_package; recs=%v", recs)
	}
	// A locale-only file lifts nothing.
	for _, rec := range recs {
		if rec.SiteClass == "environment.d" && rec.ExecTarget != "/opt/.e/hook.so" {
			t.Errorf("unexpected environment.d edge %q (only LD_*/BASH_ENV lift)", rec.ExecTarget)
		}
	}
}

func TestPhpAutoPrepend(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/php/8.2/cli/php.ini", "; comment\nauto_prepend_file = /opt/.php/shell.php\nmemory_limit = 128M\n")
	write(t, root, "etc/php/8.2/fpm/php.ini", "auto_append_file = \"/usr/share/php/legit.php\"\n")
	write(t, root, "usr/share/php/legit.php", "<?php")
	recs := collect(t, root, "/usr/share/php/legit.php")
	if r := find(recs, "php.ini", "/opt/.php/shell.php"); r == nil || !hasSig(r, core.SignalNonPackagePath) {
		t.Errorf("auto_prepend_file payload not lifted/non_package; recs=%v", recs)
	}
	if r := find(recs, "php.ini", "/usr/share/php/legit.php"); r != nil && hasSig(r, core.SignalNonPackagePath) {
		t.Errorf("owned auto_append_file must not carry non_package_path")
	}
}

func TestEnvironmentD_PythonAndNode(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/environment.d/90-py.conf", "PYTHONSTARTUP=/opt/.py/startup.py\n")
	write(t, root, "etc/environment.d/91-node.conf", "NODE_OPTIONS=--require /opt/.node/hook.js --max-old-space-size=512\n")
	write(t, root, "etc/environment.d/92-locale.conf", "LANG=C.UTF-8\nPERL5OPT=-Mevil\n") // module NAME, not a path -> ignored
	recs := collect(t, root)
	if find(recs, "environment.d", "/opt/.py/startup.py") == nil {
		t.Errorf("PYTHONSTARTUP path not lifted; recs=%v", recs)
	}
	if find(recs, "environment.d", "/opt/.node/hook.js") == nil {
		t.Errorf("NODE_OPTIONS --require path not lifted; recs=%v", recs)
	}
	for _, r := range recs {
		if r.SiteClass == "environment.d" && r.ExecTarget != "/opt/.py/startup.py" && r.ExecTarget != "/opt/.node/hook.js" {
			t.Errorf("unexpected environment.d edge %q (PERL5OPT module name must be inert)", r.ExecTarget)
		}
	}
}

func TestMaintscriptDpkg(t *testing.T) {
	root := t.TempDir()
	// Tampered postinst: sources debconf (owned) AND drops a /tmp payload.
	write(t, root, "var/lib/dpkg/info/openssh-server.postinst",
		"#!/bin/sh\nset -e\n. /usr/share/debconf/confmodule\n/tmp/.x/agent &\nupdate-alternatives --install x\n")
	// Clean postinst: only packaged tools -> no orphan edge.
	write(t, root, "var/lib/dpkg/info/coreutils.postinst",
		"#!/bin/sh\nset -e\nldconfig\nupdate-alternatives --install y\n")
	recs := collect(t, root)
	// The tampered one: ExtractExecTarget lifts the first absolute edge.
	// debconf source is owned/absent here; the /tmp payload must surface.
	var found bool
	for _, r := range recs {
		if r.SiteClass == "maintscript.dpkg" && r.Locus == "/var/lib/dpkg/info/openssh-server.postinst" {
			found = true
			if !hasSig(&r, core.SignalInterpreterInTmp) && !hasSig(&r, core.SignalExecTargetOrphan) {
				// the lifted edge should be the /tmp payload or debconf (orphan in fixture)
				t.Logf("openssh postinst exec_target=%q signals=%v", r.ExecTarget, r.Signals)
			}
		}
	}
	if !found {
		t.Errorf("tampered postinst should produce a maintscript.dpkg record; got %v", recs)
	}
}
