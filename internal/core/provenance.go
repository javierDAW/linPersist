package core

// Provenance lookup helpers (dpkg / rpm) live here. v0.1.0 ships a stub
// that always returns Unknown; the real implementation will land with
// the first module that needs it (cron's exec_target resolution).
//
// Design constraints inherited from the project charter:
//   - No CGO. Both dpkg and rpm provenance MUST be answered by parsing
//     filesystem state (/var/lib/dpkg/info/*.list, rpm DB SQLite or
//     BerkeleyDB depending on distro) in pure Go, or by shelling out
//     to dpkg-query / rpm if available. Shelling out is acceptable
//     because the agent runs read-only and the call is bounded by
//     module timeout.
//   - The package manager is detected once per process from
//     /etc/os-release and /var/lib/{dpkg,rpm} presence.

// PkgStatus describes what an executable's provenance lookup returned.
type PkgStatus string

const (
	// PkgStatusUnknown is returned when provenance has not been queried
	// or the host has no recognized package manager.
	PkgStatusUnknown PkgStatus = "unknown"

	// PkgStatusOwned means the path is owned by an installed package.
	PkgStatusOwned PkgStatus = "owned"

	// PkgStatusOrphan means no installed package claims the path.
	PkgStatusOrphan PkgStatus = "orphan"

	// PkgStatusError means the lookup failed (e.g. package DB
	// unreadable). Distinct from Unknown so downstream can tell a
	// "did not try" from a "tried and failed".
	PkgStatusError PkgStatus = "error"
)

// LookupProvenance returns the package owning path, if any, plus its
// status. The stub implementation always returns ("", PkgStatusUnknown).
// Real implementation lands when a module first needs it.
func LookupProvenance(path string) (pkg string, status PkgStatus) {
	_ = path
	return "", PkgStatusUnknown
}
