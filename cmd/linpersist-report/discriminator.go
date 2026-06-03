package main

// discriminator.go implements the per-(module, site_class) collector
// discriminator class from ADR-0017 (the discriminator ladder). It is a
// BACKEND-derived property — a pure function of fields already on every
// record — never anything the agent emits.
//
// The axis is deliberately NOT "open-ended walker vs known-locus".
// suidbits is open-ended yet gates correctly on suid+non_package_path;
// k8s.static-pod / cloudinit / confexec are known-locus yet
// unique-by-design. The right predicate is: "is provenance structurally
// INAPPLICABLE for this site_class, so a content-novelty singleton is the
// ONLY load-bearing signal?" Where that holds (discNoveltyOnly), a bare
// co=0 singleton can never be verdict-grade and is rung-4 informational by
// construction. Everywhere else (discStructural) provenance and/or an
// exec-target tell is at least theoretically applicable, so a co=0
// singleton means the structural gate genuinely found nothing — still
// rung-4 informational on a peerless host, but the analyst knows a tell
// COULD have fired and did not.
//
// The table below is EXHAUSTIVE over matrix.yaml. discriminator_test.go
// fails the build if any matrix site_class is missing here, so adding a
// module is a conscious classification decision, not a silent default.

type discClass int

const (
	// discStructural: provenance ownership and/or an exec-target structural
	// tell applies to this site_class. The default and the vast majority.
	discStructural discClass = iota
	// discNoveltyOnly: provenance is structurally inapplicable (the content
	// is never package-owned and there is no exec-target to resolve), so
	// fleet content-novelty is the ONLY discriminator. Today: the docroot
	// walk. This is the seam by which the next such collector inherits the
	// rung-4 treatment instead of re-discovering the webroot flood.
	discNoveltyOnly
)

// siteClassDisc maps every matrix.yaml site_class to its discriminator
// class. Keep it ordered by module for reviewability. A new site_class
// MUST be added here or discriminator_test.go fails the build.
var siteClassDisc = map[string]discClass{
	// cron
	"cron.d":        discStructural,
	"cron.user":     discStructural,
	"cron.periodic": discStructural,
	"cron.anacron":  discStructural,
	// systemd
	"systemd.unit":      discStructural,
	"systemd.timer":     discStructural,
	"systemd.generator": discStructural,
	"systemd.linger":    discStructural,
	"systemd.tmpfiles":  discStructural,
	"systemd.sysusers":  discStructural,
	// sysv
	"sysv.init": discStructural,
	// ssh / sshd
	"ssh.authkeys": discStructural,
	"ssh.sshrc":    discStructural,
	"sshd.config":  discStructural,
	// pam
	"pam": discStructural,
	// ldso
	"ldso.preload": discStructural,
	"ldso.conf":    discStructural,
	"ldso.confd":   discStructural,
	// sudoers
	"sudoers": discStructural,
	// passwd
	"passwd.user":             discStructural,
	"passwd.shadow":           discStructural,
	"passwd.gshadow":          discStructural,
	"passwd.group":            discStructural,
	"passwd.group.privileged": discStructural,
	// suidbits
	"suid.system": discStructural,
	"sgid.system": discStructural,
	"suid.user":   discStructural,
	"sgid.user":   discStructural,
	"filecap":     discStructural,
	// dbus
	"dbus.system":  discStructural,
	"dbus.session": discStructural,
	// cloudinit
	"cloudinit.config": discStructural,
	"cloudinit.script": discStructural,
	// k8sstatic
	"k8s.static-pod": discStructural,
	// profile
	"profile.system":      discStructural,
	"profile.user":        discStructural,
	"profile.trap.system": discStructural,
	"profile.trap.user":   discStructural,
	// motd
	"motd": discStructural,
	// kmod
	"kmod": discStructural,
	// udev
	"udev": discStructural,
	// atjobs
	"at.jobs": discStructural,
	// polkit
	"polkit.rules": discStructural,
	// netdispatch
	"network.dispatchers": discStructural,
	// grub
	"kernel.grub.config": discStructural,
	"kernel.grub.dropin": discStructural,
	// xdg
	"xdg.autostart": discStructural,
	// initramfs
	"boot.initramfs.hook": discStructural,
	// confexec
	"mail.aliases":     discStructural,
	"incron.d":         discStructural,
	"logrotate.d":      discStructural,
	"pkgmgr.hook":      discStructural,
	"sudo.conf.plugin": discStructural,
	"nss.nsswitch":     discStructural,
	"environment.d":    discStructural,
	"xsession.d":       discStructural,
	"maintscript.dpkg": discStructural,
	"php.ini":          discStructural,
	// runtimeinit
	"runtime.python": discStructural,
	// pkgrepo
	"pkgrepo.apt": discStructural,
	"pkgrepo.yum": discStructural,
	// webroot — the one collector where provenance is structurally
	// inapplicable: web content is never package-owned (WordPress, Drupal,
	// vendored composer/npm, bespoke apps) and there is no exec_target to
	// resolve, so content-novelty is the only signal.
	"webroot.script": discNoveltyOnly,
}

// classifySiteClass returns the discriminator class for a site_class and
// whether it is known. An unknown site_class (ok==false) is a build error
// caught by discriminator_test.go, never a silent runtime default.
func classifySiteClass(siteClass string) (discClass, bool) {
	c, ok := siteClassDisc[siteClass]
	return c, ok
}

// discLabel is the short human label rendered next to an informational
// (rung-4) singleton so an analyst knows the floor on that row.
func discLabel(c discClass) string {
	switch c {
	case discNoveltyOnly:
		return "novelty-only" // provenance structurally inapplicable; no tell was ever possible
	default:
		return "no-tell" // a structural tell could have fired and did not
	}
}
