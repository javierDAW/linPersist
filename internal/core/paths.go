package core

// TmpDirs is the canonical set of path prefixes treated as "interpreter
// in temp" loci across collection modules. A persistence directive whose
// ExecTarget or first token starts with any of these prefixes triggers
// the SignalInterpreterInTmp signal.
//
// The set is intentionally small and load-bearing: every module that
// emits SignalInterpreterInTmp must consult this slice so a single
// addition (e.g. a future "/var/run/shm/" variant) lands in one place.
// Trailing slashes are mandatory — callers use strings.HasPrefix.
var TmpDirs = []string{
	"/tmp/",
	"/var/tmp/",
	"/dev/shm/",
	"/run/shm/",
}
