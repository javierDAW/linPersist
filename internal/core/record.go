package core

import "time"

// SchemaVersion is the current value of the schema_v field embedded in
// every emitted Record. Bump on any breaking change to field semantics,
// renames, removals, or hash inputs. Adding a new optional field is NOT
// a breaking change and does not require a bump.
const SchemaVersion = 1

// Record is the canonical NDJSON payload emitted by the agent.
//
// Field tags use omitempty for optional fields so that absent values
// disappear from the on-wire JSON rather than being serialized as null.
// This keeps downstream stacking simple: "field missing" and "field null"
// never need to be treated as distinct values.
//
// Required fields (always emitted): SchemaV, HostID, CollectedAt,
// AgentVersion, Module, SiteClass, MITRE, Locus.
type Record struct {
	SchemaV      int       `json:"schema_v"`
	HostID       string    `json:"host_id"`
	HostMeta     HostMeta  `json:"host_meta"`
	CollectedAt  time.Time `json:"collected_at"`
	AgentVersion string    `json:"agent_version"`
	AgentCommit  string    `json:"agent_commit,omitempty"`

	Module    string   `json:"module"`
	SiteClass string   `json:"site_class"`
	MITRE     []string `json:"mitre"`
	Locus     string   `json:"locus"`

	OwnerUID *uint32    `json:"owner_uid,omitempty"`
	OwnerGID *uint32    `json:"owner_gid,omitempty"`
	Mode     string     `json:"mode,omitempty"`
	MTime    *time.Time `json:"mtime,omitempty"`
	CTime    *time.Time `json:"ctime,omitempty"`
	ATime    *time.Time `json:"atime,omitempty"`
	Size     *int64     `json:"size,omitempty"`

	ContentSHA256     string `json:"content_sha256,omitempty"`
	ContentNormSHA256 string `json:"content_norm_sha256,omitempty"`
	ContentSnippet    string `json:"content_snippet,omitempty"`

	ExecTarget          string `json:"exec_target,omitempty"`
	ExecTargetSHA256    string `json:"exec_target_sha256,omitempty"`
	ExecTargetPkg       string `json:"exec_target_pkg,omitempty"`
	ExecTargetPkgStatus string `json:"exec_target_pkg_status,omitempty"`
	ExecTargetSigned    *bool  `json:"exec_target_signed,omitempty"`

	// Relations carries structured trigger/dependency edges this artifact
	// declares to OTHER units or paths, for backend / Q12 chain
	// reconstruction (NOT a Q7 verdict input). Each entry is a
	// "Key=Value" string, e.g. "OnFailure=evil.service",
	// "PathModified=/tmp/.trigger", "Unit=payload.service". Populated by
	// the systemd module; empty (omitted) for every other module. The
	// payload arm of a trigger→payload chain is flagged independently by
	// the exec/orphan rules; this field lets the backend join the
	// innocuous-looking trigger unit to it.
	Relations []string `json:"relations,omitempty"`

	Signals []string      `json:"signals,omitempty"`
	Errors  []RecordError `json:"errors,omitempty"`
}

// RecordError describes a non-fatal collection error scoped to a single
// field of a single Record. Code mirrors a POSIX errno where applicable
// (EACCES, ENOENT, EPERM); for non-errno errors use a short upper-snake
// identifier (e.g. PARSE_ERROR, TIMEOUT).
type RecordError struct {
	Field string `json:"field"`
	Code  string `json:"code"`
	Msg   string `json:"msg,omitempty"`
}

// HostMeta is the per-host envelope appended to every Record.
//
// Hostname is intentionally omitted by default. Operators who control
// the transport channel and want plaintext hostnames must opt in via
// the --include-hostname flag, which sets Hostname in addition to
// HostnameHash.
type HostMeta struct {
	Hostname     string   `json:"hostname,omitempty"`
	HostnameHash string   `json:"hostname_hash"`
	OSID         string   `json:"os_id,omitempty"`
	OSVersion    string   `json:"os_version,omitempty"`
	Kernel       string   `json:"kernel,omitempty"`
	Arch         string   `json:"arch,omitempty"`
	BootID       string   `json:"boot_id,omitempty"`
	Tags         []string `json:"tags,omitempty"`
}
