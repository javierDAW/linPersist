package core

// Signal names emitted in Record.Signals. These are intentionally
// coarse, cheap flags that downstream pipelines combine into scores;
// the agent does NOT compute scores itself.
//
// Keep this list curated. New signals require justification in
// docs/schema-v1.md before being added so the backend schema does not
// silently expand.
const (
	// SignalRecentMtime7d set when the artifact's mtime is within the
	// last 7 days (UTC, evaluated against collected_at).
	SignalRecentMtime7d = "recent_mtime_7d"

	// SignalRecentMtime30d set when mtime is within the last 30 days
	// but outside the 7-day window.
	SignalRecentMtime30d = "recent_mtime_30d"

	// SignalRecentTargetMtime7d set when the artifact's resolved
	// exec_target has an mtime within the last 7 days (UTC, evaluated
	// against collected_at). Complements SignalRecentMtime7d, which
	// covers the locus file. Useful when the locus is a stable config
	// file (e.g. /etc/ld.so.preload) but the library it points to was
	// dropped or updated recently. Modules that compute it MUST set it
	// on the resolved file directly; symlinks should be followed.
	SignalRecentTargetMtime7d = "recent_target_mtime_7d"

	// SignalRecentCtime7d set when the artifact's inode change time
	// (ctime) is within the last 7 days (UTC, evaluated against
	// collected_at). Computed CENTRALLY at the emit sink for every
	// record that carries a ctime, so it needs no per-module wiring
	// (unlike recent_mtime_*, which each module's baseSignals derives).
	// Its purpose is anti-timestomp: `touch -d` and the utimes(2)
	// family back-date mtime/atime but CANNOT move ctime backwards --
	// only the kernel sets ctime, to "now", on any inode change. A
	// record carrying recent_ctime_7d but NOT recent_mtime_7d is the
	// textbook timestomp tell (a freshly planted file wearing an old
	// mtime). Benign on its own -- every package upgrade, chmod and
	// rsync/tar restore touches ctime -- so the backend pairs it with
	// the mtime signals (see the timestomp detection) and LFA stacking.
	SignalRecentCtime7d = "recent_ctime_7d"

	// SignalRecentCtime30d set when ctime is within the last 30 days
	// but outside the 7-day window. Same central computation and
	// anti-timestomp rationale as SignalRecentCtime7d.
	SignalRecentCtime30d = "recent_ctime_30d"

	// SignalImmutableFlag set when the artifact's inode carries the
	// ext/xfs/btrfs FS_IMMUTABLE_FL flag (chattr +i), queried centrally
	// at the emit sink via FS_IOC_GETFLAGS. Dual purpose: (1) anti-
	// remediation -- an immutable persistence locus cannot be `rm`'d or
	// edited until the flag is cleared, so the responder needs to know;
	// (2) anti-forensic -- attackers set +i to lock a planted file.
	// Enrichment only (legitimate +i exists on hardened hosts, e.g.
	// /etc/resolv.conf), so it is recorded for LFA/triage, NOT a
	// standalone detection; it pairs with content-singleton stacking.
	SignalImmutableFlag = "immutable_flag"

	// SignalAppendOnlyFlag set when the inode carries FS_APPEND_FL
	// (chattr +a) -- the file can only be appended to. Same central
	// query and enrichment-only treatment as SignalImmutableFlag.
	SignalAppendOnlyFlag = "append_only_flag"

	// SignalWorldWritable set when the artifact has the 0o002 mode bit.
	SignalWorldWritable = "world_writable"

	// SignalNonPackagePath set when exec_target resolves to a path not
	// owned by any installed package (dpkg/rpm). Requires the provenance
	// helper to have run successfully.
	SignalNonPackagePath = "non_package_path"

	// SignalPackageFileTampered set when a record's locus is a file
	// owned by an installed package whose on-disk content no longer
	// matches the hash the package manager recorded at install time.
	// On dpkg the recorded hash is the MD5 in
	// /var/lib/dpkg/info/<pkg>.md5sums, or -- for a registered
	// conffile such as /etc/crontab -- in the Conffiles: stanza of
	// /var/lib/dpkg/status (the two must BOTH be parsed; conffiles are
	// absent from *.md5sums by design). Catches the "append a line to
	// a package-owned config" persistence shape that emits no orphan /
	// interpreter_in_tmp / non_package_path signal because every path
	// involved is package-managed. Covers all three package managers:
	// dpkg (MD5 from md5sums + Conffiles), rpm (per-file FILEDIGESTS,
	// SHA-256 on RHEL7+/Rocky/Fedora) and apk (Q1 SHA-1 from the
	// installed DB); the digest algorithm is inferred from the recorded
	// hex length. Residual FP class: legitimate admin edits to config
	// files (which `dpkg --verify` / `rpm -V` likewise report); the
	// durable discriminator remains LFA -- the tampered content is a
	// fleet singleton.
	SignalPackageFileTampered = "package_file_tampered"

	// SignalLiveProcessAttached set when exec_target matches the
	// resolved executable path of a process visible to the agent when
	// the /proc snapshot was taken. The signal is informational; pair
	// with non_package_path for the high-precision "unmanaged binary,
	// currently running" pattern. See ADR-0010 for the snapshot
	// semantics (one-shot, hidepid-aware, container-namespace-aware).
	SignalLiveProcessAttached = "live_process_attached"

	// SignalPolkitAdminRule set on polkit.rules records whose canonical
	// content contains the `addAdminRule(` token. Polkit's
	// addAdminRule() callback decides which principals can authenticate
	// as admin for a given action; an attacker who can write a rule
	// granting addAdminRule -> return ["unix-user:victim"] in effect
	// promotes that user. Informational on its own (legitimate rules
	// exist); LFA collapses the legitimate baseline.
	SignalPolkitAdminRule = "polkit_admin_rule"

	// SignalPolkitYesConstant set on polkit.rules records whose
	// canonical content contains the `polkit.Result.YES` token. The
	// constant is the polkit equivalent of "allow unconditionally";
	// returning it from a rule callback grants the action without any
	// further authentication. Informational; the legitimate baseline
	// uses it sparingly (e.g. networkmanager actions on the console).
	SignalPolkitYesConstant = "polkit_yes_constant"

	// SignalGrubCmdlineInit set on kernel.grub.config records whose
	// GRUB_CMDLINE_LINUX* value contains the literal `init=` token.
	// The kernel honors `init=<path>` on its command line as the
	// pid-1 binary -- an attacker who can edit /etc/default/grub can
	// substitute the system init for an arbitrary binary at the next
	// boot. The signal is binary; the analyst pairs it with
	// `non_package_path` on the resolved target for triage.
	SignalGrubCmdlineInit = "grub_cmdline_init"

	// SignalInterpreterInTmp set when exec_target lives under /tmp,
	// /var/tmp, /dev/shm or /run/shm.
	SignalInterpreterInTmp = "interpreter_in_tmp"

	// SignalLDPreloadSet set on every record emitted from
	// /etc/ld.so.preload when the file is non-empty.
	SignalLDPreloadSet = "ld_preload_set"

	// SignalExecTargetOrphan set when exec_target points to a file that
	// does not exist on disk.
	SignalExecTargetOrphan = "exec_target_orphan"

	// SignalNonRootOwner set when an artifact under a system path
	// (/etc, /usr, /lib) is owned by uid != 0.
	SignalNonRootOwner = "non_root_owner"

	// SignalShellIndirect set when exec_target is a common shell or
	// scripting interpreter (bash, sh, dash, zsh, ash, python,
	// python3, perl, ruby, php, node). Indicates the actual command
	// lives inside a -c argument the agent does not parse.
	SignalShellIndirect = "shell_indirect"

	// SignalInterpreterRunsOrphanScript set when a record's command runs
	// a PACKAGED script interpreter (python3, perl, bash, ...) against a
	// script-file argument that resolves to an orphan (package-unowned)
	// path. exec_target only captures the interpreter, which is owned --
	// so non_package_path / exec_target_orphan stay silent even though the
	// actual payload (the script) is unmanaged. Catches the "live off the
	// packaged interpreter, park the payload" shape (a cron job or systemd
	// unit running /usr/bin/python3 /opt/.cache/x.py). Inline `-c <code>`
	// invocations carry no script path and are intentionally NOT flagged
	// (left to LFA). Residual FP class: config-management (Ansible/Salt)
	// drops legitimate `python3 /opt/<co>/maintenance.py` cron jobs whose
	// script is non-package; the durable discriminator is LFA -- a parked
	// payload is a fleet content singleton, a managed script is not.
	SignalInterpreterRunsOrphanScript = "interpreter_runs_orphan_script"

	// SignalUnqualifiedExecTarget set when exec_target is a bare
	// executable name (no leading slash). v0.1.0 does not resolve
	// such names against PATH; the backend can choose to ignore or
	// flag these records.
	SignalUnqualifiedExecTarget = "unqualified_exec_target"

	// SignalCronVarAssignment set on records that represent a cron
	// variable assignment line (MAILTO=, PATH=, SHELL=, RANDOM_DELAY=
	// and similar) rather than a schedule + command entry.
	SignalCronVarAssignment = "cron_var_assignment"

	// SignalAtReboot set when a cron schedule uses the @reboot
	// shorthand. @reboot is a well-known persistence pattern because
	// the command runs every time the host boots.
	SignalAtReboot = "at_reboot"

	// SignalEmptyFile set on envelope records emitted for an empty
	// file when the site_class is one where the file's mere existence
	// matters (e.g. an empty script under cron.daily/).
	SignalEmptyFile = "empty_file"

	// SignalSSHOptionsPresent set on ssh.authkeys records whose source
	// line carries any options list before the keytype (command=,
	// from=, no-pty, environment=, permitopen=, etc.). Indicator is
	// intentionally broad; many legitimate keys use options. Pair with
	// SignalSSHForcedCommand for the tighter "this option forces a
	// specific command" signal.
	SignalSSHOptionsPresent = "ssh_options_present"

	// SignalSSHForcedCommand set on ssh.authkeys records whose options
	// list contains command="..." (case-insensitive). The forced
	// command is a well-known persistence pattern: any key carrying
	// command="/tmp/.h/x" runs that command on every successful
	// authentication regardless of what the user requested. Legitimate
	// uses exist (e.g. command="/usr/bin/git-shell") so this flag is
	// not a verdict; pair with exec_target / non_package_path /
	// interpreter_in_tmp for triage.
	SignalSSHForcedCommand = "ssh_forced_command"

	// SignalSudoersNoPasswd set on sudoers user-spec records whose
	// tags include NOPASSWD:. Combined with sudoers_all_commands and
	// a non-root user/group, this is the textbook sudo-backdoor
	// pattern. Used alone, it surfaces many legitimate config-mgmt
	// patterns (ansible bastion, ci runners) so it is informational
	// rather than a verdict.
	SignalSudoersNoPasswd = "sudoers_nopasswd"

	// SignalSudoersAllCommands set on sudoers user-spec records whose
	// command list contains the ALL token (unrestricted command
	// execution as the target user). On its own benign for admin
	// groups; combined with sudoers_nopasswd and an unexpected
	// principal it surfaces immediately under LFA.
	SignalSudoersAllCommands = "sudoers_all_commands"

	// SignalSudoersNopasswdGtfobin set on a sudoers user-spec that grants
	// NOPASSWD on a command whose basename is a curated shell-escape
	// "GTFOBin" (vi/vim/less/awk/find/sed/python/perl/tar/...). A NOPASSWD
	// grant on one of these is semantically equivalent to NOPASSWD:ALL --
	// `sudo vi` -> `:!sh`, `sudo find . -exec sh \;`, `sudo awk 'BEGIN{system(...)}'`
	// -- so it is a password-less root shell hiding behind a
	// single-command rule that sudoers_all_commands never matches. The
	// curated set deliberately EXCLUDES commonly-scoped-legit binaries
	// (systemctl, service, docker, git, package managers): those are real
	// GTFOBins too but NOPASSWD grants on them are everywhere on managed
	// fleets, so they are left to LFA singleton stacking rather than a
	// Q7 row. Residual FP class: ops/CI accounts legitimately granted
	// NOPASSWD on tar/find for backups -- pair with LFA (a fleet-common
	// grant is not a singleton; an attacker's fresh-account grant is).
	SignalSudoersNopasswdGtfobin = "sudoers_nopasswd_gtfobin"

	// SignalSudoersIncludeDirective set on records emitted from a
	// #include or #includedir line in sudoers. Lets backends filter
	// "real rules vs structural directives" without keyword-matching
	// content_snippet.
	SignalSudoersIncludeDirective = "sudoers_include_directive"

	// SignalSSHDPermitRootLoginYes set on sshd.config records whose
	// directive is PermitRootLogin and whose value is yes (or
	// without-password / prohibit-password mapped to yes in practice).
	// Persistence-relevant because an attacker who has root locally
	// can flip this to re-enable root SSH login.
	SignalSSHDPermitRootLoginYes = "sshd_permit_root_login_yes"

	// SignalSSHDAuthorizedKeysCommand set on sshd.config records
	// whose directive is AuthorizedKeysCommand. The directive points
	// to an external program that sshd runs on each login attempt to
	// produce authorized_keys content. A backdoor binary planted at
	// the path it points to runs with whatever privileges sshd
	// invoked it under.
	SignalSSHDAuthorizedKeysCommand = "sshd_authorized_keys_command"

	// SignalSSHDMatchBlockDirective set on sshd.config records that
	// live inside a Match block (the Match line itself AND every
	// directive after it until the next Match or end of file). See
	// ADR-0004 for the canonical-form scoping rule.
	SignalSSHDMatchBlockDirective = "sshd_match_block_directive"

	// SignalPasswdUIDZero set on passwd.user records whose uid is 0
	// AND whose username is NOT "root". The textbook local-account
	// privilege-escalation backdoor: any uid-0 account other than
	// root is, by construction, suspicious.
	SignalPasswdUIDZero = "passwd_uid_zero"

	// SignalPasswdNoPassword set on passwd.shadow records whose
	// password_status field is "empty" (the source line had an empty
	// hash field). An account with no password set accepts logins
	// without any authentication challenge -- a strong anti-pattern
	// and a documented persistence vector.
	SignalPasswdNoPassword = "passwd_no_password"

	// SignalSystemdUserUnit set on systemd records whose locus lives
	// under a user-mode locus (/etc/systemd/user/,
	// /usr/lib/systemd/user/, /home/*/.config/systemd/user/,
	// /root/.config/systemd/user/). User units survive reboot iff
	// `loginctl enable-linger <user>` has been set, which is itself
	// a documented persistence step; the signal lets the backend
	// stack user-mode records separately from system-mode ones.
	SignalSystemdUserUnit = "systemd_user_unit"

	// SignalSystemdDropin set on systemd records whose locus is a
	// drop-in `.conf` under `<unit>.<ext>.d/`. Per ADR-0007 the agent
	// does NOT merge drop-ins with the base unit; the backend
	// correlates them by locus prefix. The signal lets a downstream
	// query distinguish base units from override fragments without
	// regex-parsing the locus.
	SignalSystemdDropin = "systemd_dropin"

	// SignalSystemdTemplateUnit set on systemd records whose unit
	// filename matches `<name>@.<ext>` (the template form). The
	// agent emits one record per template file; runtime instances
	// (`<name>@<instance>.<ext>`) are systemd-managed state and not
	// inspected here.
	SignalSystemdTemplateUnit = "systemd_template_unit"

	// SignalSystemdExternalUnitSymlink set on systemd records whose
	// locus is a symlink resolving to a target file outside the
	// walked loci. Captures the offensive pattern of dropping a
	// `.wants/` or `.requires/` symlink that points at a payload
	// kept under `/opt`, `/tmp`, `/var/tmp`, or similar.
	SignalSystemdExternalUnitSymlink = "systemd_external_unit_symlink"

	// SignalSystemdMultiExecStart set when a single unit declares
	// more than one ExecStart= directive. Legal under Type=oneshot;
	// noteworthy because exec_target only captures the first command
	// and the additional ones are recoverable only from the content
	// hashes.
	SignalSystemdMultiExecStart = "systemd_multi_execstart"

	// SignalSystemdGenerator set on every record emitted from a systemd
	// GENERATOR -- an executable under /etc|/usr/lib|/run/systemd/system-
	// generators/. Generators run as root at EARLY boot on every boot,
	// with no unit file, no ExecStart and no enable step, so they are a
	// first-class persistence primitive that the unit walker (which keys
	// on .service/.timer extensions in the four unit loci) never saw.
	// Structural marker; pair with non_package_path / exec_target_orphan
	// (a planted generator is unowned, the ~half-dozen vendor generators
	// like systemd-fstab-generator are package-shipped) for the verdict.
	SignalSystemdGenerator = "systemd_generator"

	// SignalSystemdAuxExecUnmanaged set when a unit (or, classically, a
	// drop-in injected into a legitimate vendor unit) carries an
	// ExecStartPre / ExecStartPost / ExecStopPost / ExecStop / ExecReload
	// / ExecCondition directive whose first token resolves to a path that
	// is orphan (missing), package-unowned, or under a tmp-class dir. The
	// systemd module historically resolved only the first ExecStart=, so
	// these auxiliary exec hooks were a behavior-injection blind spot
	// (Turla-style: a `<vendor>.service.d/10-hook.conf` drop-in that adds
	// ExecStartPre=/opt/payload runs as root before the real daemon every
	// boot, carrying no ExecStart= of its own). Gated on the orphan/
	// non_package/tmp co-indicator so the ubiquitous legitimate
	// ExecStartPre=/usr/bin/<packaged> and ExecStartPre=-/bin/sh -c '...'
	// vendor shapes stay silent.
	SignalSystemdAuxExecUnmanaged = "systemd_aux_exec_unmanaged"

	// SignalSystemdExecUnresolved set when a unit's first ExecStart=
	// is a bare command (no leading slash) that did not resolve
	// against systemd's documented default PATH
	// (/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin).
	// Either the command is provided by a non-standard PATH set via
	// `Environment=PATH=...` in the same unit, or the binary is
	// missing on the host.
	SignalSystemdExecUnresolved = "systemd_exec_unresolved"

	// SignalSystemdInstallAliasExternal set when a unit's
	// `[Install] Alias=` directive lists an alias path that resolves
	// outside the walked loci. Alias= creates symlinks at
	// `systemctl enable` time; an external target is the symmetric
	// pattern to SignalSystemdExternalUnitSymlink.
	SignalSystemdInstallAliasExternal = "systemd_install_alias_external"

	// SignalSysvExternalInitSymlink set on sysv.init records whose
	// locus is a symlink in /etc/rc[0-6].d/ (or the RHEL alternative
	// /etc/rc.d/rc[0-6].d/) resolving to a target file outside the
	// walked init.d locus prefixes. Captures the offensive pattern
	// of enabling a payload kept under /tmp, /var/tmp, /opt, etc.
	// without touching the canonical /etc/init.d/ directory.
	// Symmetric to SignalSystemdExternalUnitSymlink for systemd
	// .wants/.requires links.
	SignalSysvExternalInitSymlink = "sysv_external_init_symlink"

	// SignalKmodInstallDirective set on kmod records whose directive
	// verb is `install`. The install directive replaces the load
	// command for a given module with an arbitrary shell command
	// (`install foo /bin/sh -c '...'`) -- the textbook modprobe.d
	// persistence vector. Legitimate uses exist (e.g. distro shims
	// that load a helper module first), so the signal is informational
	// rather than a verdict; pair with exec_target / interpreter_in_tmp
	// / non_package_path for triage.
	SignalKmodInstallDirective = "kmod_install_directive"

	// SignalKmodBlacklistDirective set on kmod records whose directive
	// verb is `blacklist`. Far less likely to be a persistence vector
	// in itself, but worth surfacing because attacker-introduced
	// blacklists can disable defensive modules (e.g. blacklisting
	// kernel security modules).
	SignalKmodBlacklistDirective = "kmod_blacklist_directive"

	// SignalUdevRunDirective set on udev records that carry a RUN+=
	// or RUN= assignment. RUN runs the named program when the rule
	// matches; arbitrary command execution under whatever uid udevd
	// invokes (typically root). Documented persistence vector
	// (PANIX, DFIR Report).
	SignalUdevRunDirective = "udev_run_directive"

	// SignalUdevProgramDirective set on udev records that carry a
	// PROGRAM= assignment. PROGRAM is the matcher-side counterpart
	// to RUN: it runs a program during rule matching to use the
	// output as a variable. Same execution surface as RUN.
	SignalUdevProgramDirective = "udev_program_directive"
	// SignalSystemdLingerNonRoot set on systemd.linger records whose
	// username is anything other than "root". The presence of any
	// /var/lib/systemd/linger/<user> file enables user-mode systemd
	// units for that account to survive logout; root is the baseline
	// (no-op), non-root is the documented persistence vector
	// (PANIX, Mandiant Linux IR reports).
	SignalSystemdLingerNonRoot = "systemd_linger_non_root"

	// SignalTmpfilesCreatesUnderTmp set on systemd.tmpfiles records
	// whose directive creates / modifies a file or directory under a
	// tmp-class path (/tmp, /var/tmp, /dev/shm, /run/shm). systemd-
	// tmpfiles runs at boot and on demand, so a "create executable
	// under /tmp" directive effectively restores a payload across
	// reboots without touching any other persistence site -- a
	// documented vector.
	SignalTmpfilesCreatesUnderTmp = "tmpfiles_creates_under_tmp"

	// SignalSysusersUIDZero set on systemd.sysusers records whose
	// directive declares a uid-0 user with a name other than "root".
	// systemd-sysusers creates declared users at boot if absent; a
	// uid-0 non-root entry in a sysusers.d drop-in is the "second
	// root account" implant routed through the declarative path
	// (T1136.001) rather than through direct edits to /etc/passwd.
	SignalSysusersUIDZero = "sysusers_uid_zero"

	// SignalGroupWheelMembership through SignalGroupRootMembership set
	// on passwd.group.privileged records when a non-root user is a
	// member of a privileged Linux group. MITRE T1098.007 (Account
	// Manipulation: Additional Local or Domain Groups): adding a
	// previously-compromised low-privilege account to wheel/sudo/
	// docker/adm/lxd/root is a quiet privilege-escalation pivot that
	// leaves no trace in /etc/passwd or /etc/shadow but grants
	// equivalent capability (docker = root via socket; adm = read
	// every log; root group ≠ uid 0 but unlocks many setgid binaries).
	//
	// One signal per group keeps Q5/Q7 fleet stacking honest: an
	// operator-blessed `docker` group with the engineering team in it
	// is a baseline; a `wheel` group on a debian box where wheel is
	// not normally used is a singleton anomaly. Mixing them under one
	// "group_privileged_membership" signal would lose that resolution.
	SignalGroupWheelMembership  = "group_wheel_membership"
	SignalGroupSudoMembership   = "group_sudo_membership"
	SignalGroupDockerMembership = "group_docker_membership"
	SignalGroupAdmMembership    = "group_adm_membership"
	SignalGroupLxdMembership    = "group_lxd_membership"
	SignalGroupRootMembership   = "group_root_membership"

	// SignalSuidBitSet and SignalSgidBitSet set on suidbits records
	// when the file carries the corresponding mode bit (04000 / 02000).
	// MITRE T1548.001 (Abuse Elevation Control Mechanism: Setuid and
	// Setgid): an attacker who can write a binary and chmod u+s it
	// leaves a privilege-escalation pivot that survives reboot and
	// leaves no trace in /etc/passwd or /etc/sudoers. Both bits CAN
	// be set on the same file; both signals fire in that case. The
	// fleet-wide noise from legitimate package-managed suid binaries
	// (passwd, sudo, mount, ping, ...) is filtered downstream by
	// pairing with non_package_path: a suid binary under /usr/bin
	// shipped by the package manager looks identical across hosts
	// and stacks in Q1; a suid binary under /tmp owned by root is
	// the unmistakable implant shape.
	SignalSuidBitSet = "suid_bit_set"
	SignalSgidBitSet = "sgid_bit_set"

	// SignalFileCapabilitySet set on a suidbits record whose file carries
	// a security.capability xattr (file capabilities). MITRE T1548.001:
	// a 0755 binary with cap_setuid+ep is a privesc primitive that NO
	// suid-bit scan (find -perm -4000) and -- until this -- linpersist's
	// mode-only suidbits walker ever saw. Pair with non_package_path (a
	// packaged binary legitimately carrying caps, e.g. ping/cap_net_raw,
	// is fleet-baseline; a dropped /opt binary with caps is the implant).
	SignalFileCapabilitySet = "file_capability_set"

	// SignalFileCapPrivileged set when the file's permitted capability
	// set includes a directly-privesc-capable capability (cap_setuid,
	// cap_setgid, cap_dac_override, cap_dac_read_search, cap_sys_admin,
	// cap_sys_module, cap_sys_ptrace, cap_sys_rawio, cap_setfcap).
	SignalFileCapPrivileged = "file_cap_privileged"

	// SignalTrapCommand and friends fire on profile.trap.{system,user}
	// records emitted by the profile module's trap walker (v0.4.0).
	// MITRE T1546.005 (Event Triggered Execution: Trap). A `trap CMD
	// SIG…` directive installed in /etc/profile.d/, ~/.bashrc, /etc/
	// zshrc, etc. fires CMD when the shell receives SIG — including
	// SIGEXIT on every shell exit, which is the typical implant shape.
	//   - SignalTrapCommand: any non-noop `trap CMD …` directive seen
	//   - SignalTrapExitHandler: the signal list includes EXIT
	//   - SignalTrapCommandInTmp: the first token of CMD resolves
	//     under /tmp / /var/tmp / /dev/shm
	SignalTrapCommand      = "trap_command"
	SignalTrapExitHandler  = "trap_exit_handler"
	SignalTrapCommandInTmp = "trap_command_in_tmp"
)
