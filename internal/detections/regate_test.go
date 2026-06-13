package detections

import (
	"testing"

	"github.com/jarmidaw/linpersist/internal/core"
)

func has(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// The re-gated cloud-default rules: settled baselines fire at the demoted
// severity (no recall loss), fresh grants escalate via the _recent variant.
func TestCloudDefaultRegate(t *testing.T) {
	rs := loadRepoYAML(t)

	settledSudo := core.Record{Module: "sudoers", SiteClass: "sudoers.d",
		Signals: []string{"sudoers_nopasswd", "sudoers_all_commands"}}
	freshSudo := core.Record{Module: "sudoers", SiteClass: "sudoers.d",
		Signals: []string{"sudoers_nopasswd", "sudoers_all_commands", "recent_mtime_7d"}}

	if m := rs.Match(settledSudo); !has(m, "sudoers_nopasswd_all_backdoor") || has(m, "sudoers_nopasswd_all_recent") {
		t.Errorf("settled sudoers: want backdoor(high) only, got %v", m)
	}
	if m := rs.Match(freshSudo); !has(m, "sudoers_nopasswd_all_backdoor") || !has(m, "sudoers_nopasswd_all_recent") {
		t.Errorf("fresh sudoers: want BOTH (critical escalation), got %v", m)
	}

	settledSSH := core.Record{Module: "sshd", SiteClass: "sshd.config",
		Signals: []string{"sshd_permit_root_login_yes"}}
	freshSSH := core.Record{Module: "sshd", SiteClass: "sshd.config",
		Signals: []string{"sshd_permit_root_login_yes", "recent_mtime_7d"}}

	if m := rs.Match(settledSSH); !has(m, "sshd_root_login_enabled") || has(m, "sshd_root_login_recent") {
		t.Errorf("settled sshd: want enabled(medium) only, got %v", m)
	}
	if m := rs.Match(freshSSH); !has(m, "sshd_root_login_recent") {
		t.Errorf("fresh sshd: want _recent(high) escalation, got %v", m)
	}
}
