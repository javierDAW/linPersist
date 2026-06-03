package core

import "testing"

func TestExtractExecTarget(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		// Negative cases — common benign profile bodies must NOT
		// produce an exec target.
		{"empty", "", ""},
		{"comment_only", "# nothing here\n# really\n", ""},
		{"exports_and_aliases", "export PATH=/usr/local/bin:$PATH\nalias ll='ls -l'\n", ""},
		{"ps1_tweak", "PS1='\\u@\\h \\w \\$ '\n", ""},
		{"function_def", "myfunc() {\n  echo hi\n}\n", ""},
		{"exec_without_path", "exec 2>&1\n", ""},
		{"relative_path", "./local-helper --start\n", ""},
		// Source patterns
		{"source_keyword", "source /usr/local/bin/sync\n", "/usr/local/bin/sync"},
		{"dot_space", ". /usr/local/bin/sync\n", "/usr/local/bin/sync"},
		{"source_after_export", "export FOO=bar\nsource /opt/vendor/init.sh\n", "/opt/vendor/init.sh"},
		// Exec pattern
		{"exec_path", "exec /usr/local/bin/sync --start\n", "/usr/local/bin/sync"},
		// Absolute-path lead pattern
		{"absolute_lead", "/usr/local/bin/sync --start\n", "/usr/local/bin/sync"},
		{"absolute_lead_after_export", "export PATH=/x:/y\n/opt/agent/run\n", "/opt/agent/run"},
		// Stripping of leading shell control words
		{"then_lead", "if [ -x /usr/local/bin/sync ]; then\n  /usr/local/bin/sync\nfi\n", "/usr/local/bin/sync"},
		// Path token containing shell metacharacters (subshell etc.)
		// is rejected because the resolved path is dynamic.
		{"with_subshell", ". /usr/$(whoami)/init.sh\n", ""},
		// Trailing redirect / pipe on a clean absolute path is fine
		// — the binary itself is still unambiguous, and the point is
		// Q12 clustering by basename, not full-line equality.
		{"with_redirect", "/usr/local/bin/run >>/tmp/out\n", "/usr/local/bin/run"},
		{"with_pipe", "/usr/local/bin/run | tee /tmp/log\n", "/usr/local/bin/run"},
		// First match wins
		{"first_match_wins", ". /usr/local/bin/first\n. /opt/second\n", "/usr/local/bin/first"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if got := ExtractExecTarget([]byte(c.body)); got != c.want {
				t.Errorf("ExtractExecTarget(%q) = %q, want %q", c.body, got, c.want)
			}
		})
	}
}

func TestExtractEnvHookTarget(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		// Negative cases — benign content must NOT produce a hook.
		{"empty", "", ""},
		{"comment_only", "# BASH_ENV=/opt/x (commented)\n", ""},
		{"unrelated_env", "PATH=/usr/local/bin:/usr/bin\nLANG=en_US.UTF-8\n", ""},
		{"no_assignment", "BASH_ENV\n", ""},
		// Key must match exactly — suffix/prefix collisions don't fire.
		{"suffix_collision", "MY_ENV=/opt/x\n", ""},
		{"prefix_collision", "BASH_ENVX=/opt/x\n", ""},
		// Non-absolute / dynamic RHS is left to LFA, not a target.
		{"relative_rhs", "BASH_ENV=hook.sh\n", ""},
		{"home_expanded", "BASH_ENV=$HOME/.hook\n", ""},
		{"quoted_expanded", "export BASH_ENV=\"$HOME/.hook\"\n", ""},
		{"subshell_rhs", "ENV=$(/bin/findhook)\n", ""},
		// Positive cases.
		{"bare_bash_env", "BASH_ENV=/opt/.envhook\n", "/opt/.envhook"},
		{"export_bash_env", "export BASH_ENV=/opt/.envhook\n", "/opt/.envhook"},
		{"double_quoted", "export BASH_ENV=\"/opt/.envhook\"\n", "/opt/.envhook"},
		{"single_quoted", "ENV='/opt/.envhook'\n", "/opt/.envhook"},
		{"posix_env", "ENV=/usr/local/lib/hook.sh\n", "/usr/local/lib/hook.sh"},
		{"env_under_tmp", "BASH_ENV=/tmp/.x/hook\n", "/tmp/.x/hook"},
		{"leading_whitespace", "   BASH_ENV=/opt/.envhook\n", "/opt/.envhook"},
		// Among real /etc/environment KEY=value lines.
		{"in_environment_file", "PATH=\"/usr/local/sbin:/usr/local/bin:/usr/bin\"\nLANG=C.UTF-8\nBASH_ENV=/opt/.envhook\n", "/opt/.envhook"},
		// First match wins.
		{"first_match_wins", "BASH_ENV=/opt/first\nENV=/opt/second\n", "/opt/first"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if got := ExtractEnvHookTarget([]byte(c.body)); got != c.want {
				t.Errorf("ExtractEnvHookTarget(%q) = %q, want %q", c.body, got, c.want)
			}
		})
	}
}
