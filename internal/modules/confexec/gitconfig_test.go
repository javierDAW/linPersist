package confexec

import "testing"

func TestParseGitConfigHooksPath(t *testing.T) {
	cases := []struct {
		name string
		cfg  string
		want string // expected lifted target, "" = no edge
	}{
		{"core hooksPath tmp", "[core]\n\thooksPath = /tmp/.h\n", "/tmp/.h"},
		{"case-insensitive key", "[core]\n\tHooksPath=/opt/.git-hooks\n", "/opt/.git-hooks"},
		{"quoted value", "[core]\n\thooksPath = \"/srv/.hooks\"\n", "/srv/.hooks"},
		{"benign no hookspath", "[user]\n\tname = alice\n[core]\n\teditor = vim\n", ""},
		{"hookspath outside core section", "[remote \"x\"]\n\thooksPath = /tmp/.h\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			edges := parseGitConfig([]byte(tc.cfg), "/etc/gitconfig", nil)
			if tc.want == "" {
				if len(edges) != 0 {
					t.Errorf("want no edge, got %+v", edges)
				}
				return
			}
			if len(edges) != 1 || edges[0].Target != tc.want {
				t.Errorf("want target %q, got %+v", tc.want, edges)
			}
		})
	}
}
