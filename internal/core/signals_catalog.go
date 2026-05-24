// Catalog of every signal the linpersist agent is allowed to emit.
//
// `signals.go` carries the canonical const declarations and the full
// rationale for each signal. This file is the iterable mirror used at
// runtime by the report binary, the (future) detections.yaml loader,
// and the buildtime audit tests in signals_test.go and
// signals_emission_test.go.
//
// Adding a new signal requires THREE coordinated changes:
//
//  1. A new const in signals.go with full docstring.
//  2. A new `SignalDef` entry in `Signals` below (same order as the
//     const block; one-line description; declared `EmittedBy` listing
//     the modules / core helpers that emit it).
//  3. Implementing the emission in the appropriate module or core
//     helper -- otherwise the emission audit test fails.
//
// `signals_test.go` enforces the const<->catalog and catalog<->emission
// invariants. `signals_emission_test.go` enforces that every name in
// `EmittedBy` actually references the signal in code.
//
// "EmittedBy" tokens are either a module directory name under
// `internal/modules/<name>/` (e.g. "cron", "sshd") or a core helper
// path of the form "core/<file>" (e.g. "core/provenance",
// "core/proclive") for signals applied via shared helpers rather than
// directly from a module.

package core

// SignalDef is one entry in the canonical signals catalog.
type SignalDef struct {
	// Name is the canonical string value emitted in Record.Signals.
	// Always equal to one of the `Signal*` const values in signals.go.
	Name string

	// Description is a one-line summary suitable for report tooltips
	// and detection rule documentation. The full rationale lives in
	// the const's docstring in signals.go.
	Description string

	// EmittedBy lists the modules and core helpers that emit this
	// signal. A signal must have at least one emitter; the buildtime
	// audit test enforces this against the actual source tree.
	EmittedBy []string
}

// Signals is the canonical, ordered catalog of every signal the agent
// is allowed to emit. Order matches the const block in signals.go so
// the catalog reads top-to-bottom the same way the documentation does.
//
// Modules MUST NOT emit a signal whose Name is not in this slice;
// signals_test.go enforces the invariant.
var Signals = []SignalDef{
	// --- File-level cheap signals applied by every module's baseSignals --

	{
		Name:        SignalRecentMtime7d,
		Description: "artifact mtime within the last 7 days (UTC, evaluated against collected_at)",
		EmittedBy: []string{
			"atjobs", "cloudinit", "cron", "dbus", "grub", "k8sstatic", "kmod", "ldso",
			"motd", "netdispatch", "pam", "passwd", "polkit", "profile", "ssh", "sshd",
			"sudoers", "suidbits", "systemd", "sysv", "udev", "xdg",
			"linger", "tmpfiles", "sysusers",
		},
	},
	{
		Name:        SignalRecentMtime30d,
		Description: "artifact mtime within the last 30 days but outside the 7-day window",
		EmittedBy: []string{
			"atjobs", "cloudinit", "cron", "dbus", "grub", "k8sstatic", "kmod", "ldso",
			"motd", "netdispatch", "pam", "passwd", "polkit", "profile", "ssh", "sshd",
			"sudoers", "suidbits", "systemd", "sysv", "udev", "xdg",
			"linger", "tmpfiles", "sysusers",
		},
	},
	{
		Name:        SignalRecentTargetMtime7d,
		Description: "resolved exec_target's mtime is within the last 7 days",
		EmittedBy: []string{
			"cron", "kmod", "ldso", "pam", "passwd", "ssh", "systemd", "udev", "xdg",
		},
	},
	{
		Name:        SignalWorldWritable,
		Description: "artifact has the 0o002 mode bit set",
		EmittedBy: []string{
			"atjobs", "cloudinit", "cron", "dbus", "grub", "k8sstatic", "kmod", "ldso",
			"motd", "netdispatch", "pam", "passwd", "polkit", "profile", "ssh", "sshd",
			"sudoers", "suidbits", "systemd", "sysv", "udev", "xdg",
			"linger", "tmpfiles", "sysusers",
		},
	},

	// --- Core helpers applied cross-cuttingly after exec_target resolves --

	{
		Name:        SignalNonPackagePath,
		Description: "exec_target resolves to a path not owned by any installed dpkg/rpm package",
		EmittedBy:   []string{"core/provenance"},
	},
	{
		Name:        SignalLiveProcessAttached,
		Description: "exec_target matches the resolved executable of a process visible in the /proc snapshot",
		EmittedBy:   []string{"core/proclive"},
	},

	// --- Polkit ---

	{
		Name:        SignalPolkitAdminRule,
		Description: "polkit.rules canonical content contains the addAdminRule( token",
		EmittedBy:   []string{"polkit"},
	},
	{
		Name:        SignalPolkitYesConstant,
		Description: "polkit.rules canonical content contains polkit.Result.YES",
		EmittedBy:   []string{"polkit"},
	},

	// --- Bootloader ---

	{
		Name:        SignalGrubCmdlineInit,
		Description: "GRUB_CMDLINE_LINUX* value contains an init= token overriding pid-1 at next boot",
		EmittedBy:   []string{"grub"},
	},

	// --- Exec-target enrichments applied by every module that resolves a target --

	{
		Name:        SignalInterpreterInTmp,
		Description: "exec_target lives under /tmp, /var/tmp, /dev/shm or /run/shm",
		EmittedBy: []string{
			"cron", "dbus", "grub", "kmod", "ldso", "pam", "passwd", "ssh", "sshd",
			"systemd", "sysv", "udev", "xdg",
		},
	},
	{
		Name:        SignalLDPreloadSet,
		Description: "non-empty line in /etc/ld.so.preload — every record from that file carries it",
		EmittedBy:   []string{"ldso"},
	},
	{
		Name:        SignalExecTargetOrphan,
		Description: "exec_target points to a file that does not exist on disk",
		EmittedBy: []string{
			"cron", "dbus", "grub", "kmod", "ldso", "pam", "passwd", "ssh", "sshd",
			"systemd", "sysv", "udev", "xdg",
		},
	},
	{
		Name:        SignalNonRootOwner,
		Description: "artifact under /etc, /usr, /lib, /bin, /sbin is owned by uid != 0",
		EmittedBy: []string{
			"cloudinit", "cron", "dbus", "grub", "k8sstatic", "kmod", "ldso", "motd",
			"netdispatch", "pam", "passwd", "polkit", "profile", "ssh", "sshd", "sudoers",
			"suidbits", "systemd", "sysv", "udev", "xdg",
			"linger", "tmpfiles", "sysusers",
		},
	},
	{
		Name:        SignalShellIndirect,
		Description: "exec_target is a common shell or interpreter — actual command is inside a -c argument",
		EmittedBy:   []string{"cron", "dbus", "kmod", "systemd", "udev", "xdg"},
	},
	{
		Name:        SignalUnqualifiedExecTarget,
		Description: "exec_target is a bare executable name with no leading slash",
		EmittedBy:   []string{"cron", "dbus", "k8sstatic", "kmod", "systemd", "udev", "xdg"},
	},

	// --- Cron ---

	{
		Name:        SignalCronVarAssignment,
		Description: "record represents a cron variable assignment line (MAILTO=, PATH=, SHELL=, ...)",
		EmittedBy:   []string{"cron"},
	},
	{
		Name:        SignalAtReboot,
		Description: "cron schedule uses the @reboot shorthand",
		EmittedBy:   []string{"cron"},
	},

	// --- Empty-file envelope ---

	{
		Name:        SignalEmptyFile,
		Description: "envelope record emitted for an empty file whose existence matters at this site_class",
		EmittedBy: []string{
			"atjobs", "cron", "grub", "motd", "netdispatch", "polkit", "sysv", "sysusers", "tmpfiles", "xdg",
		},
	},

	// --- SSH authorized_keys ---

	{
		Name:        SignalSSHOptionsPresent,
		Description: "ssh.authkeys line carries an options list (command=, from=, no-pty, environment=, permitopen=, ...)",
		EmittedBy:   []string{"ssh"},
	},
	{
		Name:        SignalSSHForcedCommand,
		Description: "ssh.authkeys options list contains command=\"...\" forcing a specific command on login",
		EmittedBy:   []string{"ssh"},
	},

	// --- Sudoers ---

	{
		Name:        SignalSudoersNoPasswd,
		Description: "sudoers user-spec record carries the NOPASSWD: tag",
		EmittedBy:   []string{"sudoers"},
	},
	{
		Name:        SignalSudoersAllCommands,
		Description: "sudoers user-spec record's command list contains the ALL token",
		EmittedBy:   []string{"sudoers"},
	},
	{
		Name:        SignalSudoersIncludeDirective,
		Description: "sudoers record emitted from a #include or #includedir directive",
		EmittedBy:   []string{"sudoers"},
	},

	// --- sshd_config ---

	{
		Name:        SignalSSHDPermitRootLoginYes,
		Description: "sshd_config PermitRootLogin directive set to literal yes (prohibit-password is NOT flagged)",
		EmittedBy:   []string{"sshd"},
	},
	{
		Name:        SignalSSHDAuthorizedKeysCommand,
		Description: "sshd_config AuthorizedKeysCommand directive present (external authorized_keys helper)",
		EmittedBy:   []string{"sshd"},
	},
	{
		Name:        SignalSSHDMatchBlockDirective,
		Description: "sshd_config record lives inside a Match block (Match line itself or any directive under it)",
		EmittedBy:   []string{"sshd"},
	},

	// --- passwd / shadow ---

	{
		Name:        SignalPasswdUIDZero,
		Description: "passwd.user record has uid 0 and username != root (second uid-zero account)",
		EmittedBy:   []string{"passwd"},
	},
	{
		Name:        SignalPasswdNoPassword,
		Description: "passwd.shadow record has password_status == empty (account accepts logins with no challenge)",
		EmittedBy:   []string{"passwd"},
	},

	// --- systemd unit / timer ---

	{
		Name:        SignalSystemdUserUnit,
		Description: "systemd record's locus lives under a user-mode unit directory",
		EmittedBy:   []string{"systemd"},
	},
	{
		Name:        SignalSystemdDropin,
		Description: "systemd record's locus is a drop-in *.conf under <unit>.<ext>.d/",
		EmittedBy:   []string{"systemd"},
	},
	{
		Name:        SignalSystemdTemplateUnit,
		Description: "systemd record's unit filename matches the <name>@.<ext> template form",
		EmittedBy:   []string{"systemd"},
	},
	{
		Name:        SignalSystemdExternalUnitSymlink,
		Description: "systemd record's locus is a symlink resolving to a target outside the walked loci",
		EmittedBy:   []string{"systemd"},
	},
	{
		Name:        SignalSystemdMultiExecStart,
		Description: "systemd unit declares more than one ExecStart= directive",
		EmittedBy:   []string{"systemd"},
	},
	{
		Name:        SignalSystemdExecUnresolved,
		Description: "systemd unit's first ExecStart= is a bare command that did not resolve against the default PATH",
		EmittedBy:   []string{"systemd"},
	},
	{
		Name:        SignalSystemdInstallAliasExternal,
		Description: "systemd unit's [Install] Alias= lists a target that resolves outside the walked loci",
		EmittedBy:   []string{"systemd"},
	},

	// --- sysv.init ---

	{
		Name:        SignalSysvExternalInitSymlink,
		Description: "sysv.init record's locus is a symlink in rcN.d/ resolving outside init.d/",
		EmittedBy:   []string{"sysv"},
	},

	// --- Kernel modules ---

	{
		Name:        SignalKmodInstallDirective,
		Description: "kmod record's directive verb is install (replaces module load with arbitrary command)",
		EmittedBy:   []string{"kmod"},
	},
	{
		Name:        SignalKmodBlacklistDirective,
		Description: "kmod record's directive verb is blacklist",
		EmittedBy:   []string{"kmod"},
	},

	// --- udev ---

	{
		Name:        SignalUdevRunDirective,
		Description: "udev rule carries a RUN+= or RUN= assignment",
		EmittedBy:   []string{"udev"},
	},
	{
		Name:        SignalUdevProgramDirective,
		Description: "udev rule carries a PROGRAM= assignment",
		EmittedBy:   []string{"udev"},
	},
	{
		Name:        SignalTmpfilesCreatesUnderTmp,
		Description: "systemd.tmpfiles directive creates or modifies a file under a tmp-class path at boot",
		EmittedBy:   []string{"tmpfiles"},
	},
	{
		Name:        SignalSysusersUIDZero,
		Description: "systemd.sysusers directive declares a uid-0 user with a non-root name",
		EmittedBy:   []string{"sysusers"},
	},
	{
		Name:        SignalSystemdLingerNonRoot,
		Description: "systemd.linger record for a non-root account (user-mode units survive logout)",
		EmittedBy:   []string{"linger"},
	},
	{
		Name:        SignalGroupWheelMembership,
		Description: "non-root user is a member of the wheel group (T1098.007)",
		EmittedBy:   []string{"passwd"},
	},
	{
		Name:        SignalGroupSudoMembership,
		Description: "non-root user is a member of the sudo group (T1098.007)",
		EmittedBy:   []string{"passwd"},
	},
	{
		Name:        SignalGroupDockerMembership,
		Description: "non-root user is a member of the docker group — equivalent to uid 0 via the docker socket (T1098.007)",
		EmittedBy:   []string{"passwd"},
	},
	{
		Name:        SignalGroupAdmMembership,
		Description: "non-root user is a member of the adm group — read access to every log file (T1098.007)",
		EmittedBy:   []string{"passwd"},
	},
	{
		Name:        SignalGroupLxdMembership,
		Description: "non-root user is a member of the lxd group — container-mediated host root (T1098.007)",
		EmittedBy:   []string{"passwd"},
	},
	{
		Name:        SignalGroupRootMembership,
		Description: "non-root user is a member of the root group — unlocks numerous setgid binaries (T1098.007)",
		EmittedBy:   []string{"passwd"},
	},
	{
		Name:        SignalSuidBitSet,
		Description: "file has the setuid bit (04000); pair with non_package_path for the T1548.001 implant shape",
		EmittedBy:   []string{"suidbits"},
	},
	{
		Name:        SignalSgidBitSet,
		Description: "file has the setgid bit (02000); pair with non_package_path for the T1548.001 implant shape",
		EmittedBy:   []string{"suidbits"},
	},
}

// signalsByName is a presence-and-lookup index built once from Signals.
// Populated by init() so SignalByName, KnownSignal and KnownSignalSet
// stay O(1).
var signalsByName map[string]SignalDef

func init() {
	signalsByName = make(map[string]SignalDef, len(Signals))
	for _, s := range Signals {
		signalsByName[s.Name] = s
	}
}

// SignalByName returns the canonical definition for name, or false if
// the signal is not in the catalog.
func SignalByName(name string) (SignalDef, bool) {
	d, ok := signalsByName[name]
	return d, ok
}

// KnownSignal reports whether name is in the canonical catalog.
// Convenience wrapper around SignalByName for predicate use.
func KnownSignal(name string) bool {
	_, ok := signalsByName[name]
	return ok
}

// KnownSignalSet returns a presence map of every catalog name. The
// returned map is freshly allocated; callers can mutate it without
// affecting the catalog.
func KnownSignalSet() map[string]struct{} {
	out := make(map[string]struct{}, len(Signals))
	for _, s := range Signals {
		out[s.Name] = struct{}{}
	}
	return out
}
