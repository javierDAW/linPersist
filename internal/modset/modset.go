// Package modset is the single registration point for every collection
// module the linpersist agent ships. Both cmd/linpersist (the runtime
// agent) and cmd/matrix-audit (the release gate that pins matrix.yaml
// to the code) consume the same slice, so adding a new module is a
// one-line edit in this file instead of three coordinated edits across
// two main.go files plus matrix.yaml.
//
// Design note (init-ordering pitfall): the slice is built explicitly,
// NOT via per-module init()-based self-registration. Cross-package
// init() order in Go follows import-graph topology, not author intent;
// self-registration would silently produce different module orderings
// between cmd/linpersist and cmd/matrix-audit if their import sets ever
// diverged — exactly the drift class matrix-audit exists to catch.
package modset

import (
	"github.com/jarmidaw/linpersist/internal/core"
	"github.com/jarmidaw/linpersist/internal/modules/atjobs"
	"github.com/jarmidaw/linpersist/internal/modules/cron"
	"github.com/jarmidaw/linpersist/internal/modules/grub"
	"github.com/jarmidaw/linpersist/internal/modules/kmod"
	"github.com/jarmidaw/linpersist/internal/modules/ldso"
	"github.com/jarmidaw/linpersist/internal/modules/linger"
	"github.com/jarmidaw/linpersist/internal/modules/motd"
	"github.com/jarmidaw/linpersist/internal/modules/netdispatch"
	"github.com/jarmidaw/linpersist/internal/modules/pam"
	"github.com/jarmidaw/linpersist/internal/modules/passwd"
	"github.com/jarmidaw/linpersist/internal/modules/polkit"
	"github.com/jarmidaw/linpersist/internal/modules/profile"
	"github.com/jarmidaw/linpersist/internal/modules/ssh"
	"github.com/jarmidaw/linpersist/internal/modules/sshd"
	"github.com/jarmidaw/linpersist/internal/modules/sudoers"
	"github.com/jarmidaw/linpersist/internal/modules/systemd"
	"github.com/jarmidaw/linpersist/internal/modules/sysusers"
	"github.com/jarmidaw/linpersist/internal/modules/sysv"
	"github.com/jarmidaw/linpersist/internal/modules/tmpfiles"
	"github.com/jarmidaw/linpersist/internal/modules/udev"
	"github.com/jarmidaw/linpersist/internal/modules/xdg"
)

// All returns the canonical, alphabetically-ordered slice of modules
// the agent ships. Both prov and liveProcs may be nil — module
// constructors substitute NoopProvenance / NoopLiveProcessSet for any
// nil dependency. Callers that only need Name() and SiteClasses() (e.g.
// matrix-audit) can safely pass nil, nil.
func All(prov core.Provenance, liveProcs core.LiveProcessSet) []core.Module {
	if prov == nil {
		prov = core.NoopProvenance{}
	}
	if liveProcs == nil {
		liveProcs = core.NoopLiveProcessSet{}
	}
	return []core.Module{
		atjobs.New(atjobs.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		cron.New(cron.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		grub.New(grub.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		kmod.New(kmod.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		ldso.New(ldso.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		linger.New(linger.Options{}),
		motd.New(motd.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		netdispatch.New(netdispatch.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		pam.New(pam.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		passwd.New(passwd.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		polkit.New(polkit.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		profile.New(profile.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		ssh.New(ssh.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		sshd.New(sshd.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		sudoers.New(sudoers.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		systemd.New(systemd.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		sysusers.New(sysusers.Options{}),
		sysv.New(sysv.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		tmpfiles.New(tmpfiles.Options{}),
		udev.New(udev.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		xdg.New(xdg.Options{Provenance: prov, LiveProcessSet: liveProcs}),
	}
}
