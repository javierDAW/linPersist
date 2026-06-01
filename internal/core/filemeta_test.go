package core

import (
	"testing"
	"time"
)

// TestRecentCtimeSignals exercises the central anti-timestomp helper:
// the bands mirror recent_mtime_*, are evaluated in UTC, and absent
// inputs yield nil (never a phantom signal).
func TestRecentCtimeSignals(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	ptr := func(d time.Duration) *time.Time { tt := now.Add(-d); return &tt }

	cases := []struct {
		name        string
		ctime       *time.Time
		collectedAt time.Time
		want        []string
	}{
		{"within 7d", ptr(3 * 24 * time.Hour), now, []string{SignalRecentCtime7d}},
		{"exactly now", ptr(0), now, []string{SignalRecentCtime7d}},
		{"7d-30d band", ptr(10 * 24 * time.Hour), now, []string{SignalRecentCtime30d}},
		{"older than 30d", ptr(60 * 24 * time.Hour), now, nil},
		{"7d boundary is 30d band", ptr(7 * 24 * time.Hour), now, []string{SignalRecentCtime30d}},
		{"nil ctime", nil, now, nil},
		{"zero collectedAt", ptr(1 * time.Hour), time.Time{}, nil},
		// ctime in the future (clock skew) is not "recent" in either band.
		{"future ctime", ptr(-2 * time.Hour), now, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RecentCtimeSignals(tc.ctime, tc.collectedAt)
			if !equalStrings(got, tc.want) {
				t.Errorf("RecentCtimeSignals = %v; want %v", got, tc.want)
			}
		})
	}
}

// TestRecentCtimeSignals_TimestompShape documents the intended pairing:
// a back-dated mtime (old, no recent_mtime_*) combined with a fresh
// ctime (recent_ctime_7d present) is the timestomp tell the detection
// rule keys on.
func TestRecentCtimeSignals_TimestompShape(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	// touch -d '2023-...' moved mtime back years, but ctime is "now".
	ctime := now.Add(-1 * time.Hour)
	got := RecentCtimeSignals(&ctime, now)
	if len(got) != 1 || got[0] != SignalRecentCtime7d {
		t.Fatalf("ctime signals = %v; want [%s]", got, SignalRecentCtime7d)
	}
}

func equalStrings(a, b []string) bool {
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
