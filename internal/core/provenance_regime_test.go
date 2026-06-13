package core

import (
	"context"
	"errors"
	"testing"
)

func TestProvenanceRegime(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*Resolver)
		want  string
	}{
		{"owned", func(r *Resolver) { r.pkgMgr = PkgMgrDpkg }, RegimeOwnedDBPresent},
		{"none", func(r *Resolver) { r.pkgMgr = PkgMgrNone }, RegimePkgMgrNone},
		{"build_error", func(r *Resolver) { r.pkgMgr = PkgMgrRpm; r.buildErr = errors.New("boom") }, RegimeBuildError},
		{"timeout", func(r *Resolver) { r.pkgMgr = PkgMgrRpm; r.buildErr = context.DeadlineExceeded }, RegimeTimeoutDegraded},
		{"timeout_wrapped", func(r *Resolver) { r.pkgMgr = PkgMgrRpm; r.buildErr = errors.New("rpm: " + context.DeadlineExceeded.Error()) }, RegimeBuildError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Resolver{}
			tc.setup(r)
			if got := r.Regime(); got != tc.want {
				t.Errorf("Regime() = %q, want %q", got, tc.want)
			}
		})
	}
}
