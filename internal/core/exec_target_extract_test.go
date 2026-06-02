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
