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
)
