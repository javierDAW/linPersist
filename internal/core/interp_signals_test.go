package core

import (
	"context"
	"testing"
)

// lookupStub is a minimal Provenance returning a fixed status for any
// path in orphan, Owned otherwise.
type lookupStub struct{ orphan map[string]bool }

func (lookupStub) Warmup(context.Context) {}
func (s lookupStub) LookupPath(p string) (string, PkgStatus) {
	if s.orphan[p] {
		return "", PkgStatusOrphan
	}
	return "somepkg", PkgStatusOwned
}

func TestInterpreterScriptOrphan(t *testing.T) {
	prov := lookupStub{orphan: map[string]bool{"/opt/.cache/x.py": true}}
	cases := []struct {
		name string
		cmd  []string
		want bool
	}{
		{"python runs orphan script", []string{"/usr/bin/python3", "/opt/.cache/x.py"}, true},
		{"python runs owned script", []string{"/usr/bin/python3", "/usr/share/app/main.py"}, false},
		{"bare interpreter name + orphan", []string{"python3", "/opt/.cache/x.py"}, true},
		{"flags before orphan script", []string{"/usr/bin/python3", "-u", "/opt/.cache/x.py"}, true},
		{"inline -c, no script path", []string{"/usr/bin/python3", "-c", "import os"}, false},
		{"non-interpreter command", []string{"/usr/sbin/cron", "-f"}, false},
		{"interpreter, no args", []string{"/bin/bash"}, false},
		{"relative script arg (not abs) ignored", []string{"/usr/bin/perl", "script.pl"}, false},
		{"nil provenance", []string{"/usr/bin/python3", "/opt/.cache/x.py"}, false}, // exercised below with nil
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var p Provenance = prov
			if tc.name == "nil provenance" {
				p = nil
			}
			if got := InterpreterScriptOrphan(p, tc.cmd); got != tc.want {
				t.Errorf("InterpreterScriptOrphan(%v) = %v; want %v", tc.cmd, got, tc.want)
			}
		})
	}
}
