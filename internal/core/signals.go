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
)
