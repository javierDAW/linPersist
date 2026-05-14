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

	// SignalWorldWritable set when the artifact has the 0o002 mode bit.
	SignalWorldWritable = "world_writable"

	// SignalNonPackagePath set when exec_target resolves to a path not
	// owned by any installed package (dpkg/rpm). Requires the provenance
	// helper to have run successfully.
	SignalNonPackagePath = "non_package_path"

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
)
