package main

import (
	"testing"

	"github.com/jarmidaw/linpersist/internal/core"
)

// makeRec builds a synthetic record with the minimum fields Q3
// reads: host_id, host_meta.os_id, host_meta.tags, module,
// site_class, content_norm_sha256, locus. Other fields are zero.
func makeRec(hostID, osID string, tags []string, contentNorm string) core.Record {
	return core.Record{
		HostID: hostID,
		HostMeta: core.HostMeta{
			OSID: osID,
			Tags: tags,
		},
		Module:            "cron",
		SiteClass:         "cron.d",
		Locus:             "/etc/cron.d/test-" + contentNorm,
		ContentNormSHA256: contentNorm,
		ContentSnippet:    "test " + contentNorm,
	}
}

// fleet builds N records sharing (osID, tags), each with the SAME
// contentNorm so they form a single Q3 aggregation bucket. Used
// for the "common across peer-group" half of every test.
func fleet(osID string, tags []string, hostIDs []string, contentNorm string) []core.Record {
	out := make([]core.Record, 0, len(hostIDs))
	for _, hid := range hostIDs {
		out = append(out, makeRec(hid, osID, tags, contentNorm))
	}
	return out
}

// TestQ3_NoTags_BehavesLikeOSIDOnly verifies the migration safety
// net: a fleet where no host has tags must produce exactly the
// rows the os_id-only era produced. The "untagged" peer-group
// is the canonical fallback.
func TestQ3_NoTags_BehavesLikeOSIDOnly(t *testing.T) {
	// 5 ubuntu hosts: 4 share a common cron line, 1 has its own.
	common := fleet("ubuntu", nil,
		[]string{"h1", "h2", "h3", "h4"}, "common-hash")
	singleton := makeRec("h5", "ubuntu", nil, "singleton-hash")
	records := append(common, singleton)

	rows := computeQ3(records, 3)

	if len(rows) != 1 {
		t.Fatalf("expected 1 Q3 row, got %d: %+v", len(rows), rows)
	}
	r := rows[0]
	if r.OSID != "ubuntu" {
		t.Errorf("OSID: got %q, want ubuntu", r.OSID)
	}
	if r.TagKey != "" {
		t.Errorf("TagKey: got %q, want empty (untagged peer-group)", r.TagKey)
	}
	if r.SampleHost != "h5" {
		t.Errorf("SampleHost: got %q, want h5", r.SampleHost)
	}
	if r.PeerSize != 5 {
		t.Errorf("PeerSize: got %d, want 5", r.PeerSize)
	}
}

// TestQ3_SameTags_SamePeerGroup verifies the central invariant:
// hosts with byte-identical canonical tag sets stack to the same
// peer-group. A singleton inside that peer-group surfaces.
func TestQ3_SameTags_SamePeerGroup(t *testing.T) {
	tags := []string{"role=build", "env=prod"}
	common := fleet("ubuntu", tags,
		[]string{"build1", "build2", "build3", "build4"}, "common-hash")
	singleton := makeRec("build5", "ubuntu", tags, "singleton-hash")
	records := append(common, singleton)

	rows := computeQ3(records, 3)

	if len(rows) != 1 {
		t.Fatalf("expected 1 Q3 row, got %d: %+v", len(rows), rows)
	}
	r := rows[0]
	if r.TagKey != "env=prod,role=build" {
		t.Errorf("TagKey: got %q, want %q", r.TagKey, "env=prod,role=build")
	}
	if r.PeerSize != 5 {
		t.Errorf("PeerSize: got %d, want 5", r.PeerSize)
	}
	if r.SampleHost != "build5" {
		t.Errorf("SampleHost: got %q, want build5", r.SampleHost)
	}
}

// TestQ3_DifferentTags_SeparatePeerGroups verifies the splitting
// guarantee: hosts in os_id=ubuntu with role=build form ONE
// peer-group; the same os_id with role=ci forms ANOTHER. A
// record common to all of them surfaces nowhere -- it is
// fleet-wide. A record unique to a role group surfaces ONLY if
// that group is large enough (peer_hosts > 2).
func TestQ3_DifferentTags_SeparatePeerGroups(t *testing.T) {
	build := []string{"role=build"}
	ci := []string{"role=ci"}

	// 4 build hosts sharing a common build-only line.
	buildCommon := fleet("ubuntu", build,
		[]string{"b1", "b2", "b3", "b4"}, "build-common")
	// 4 ci hosts sharing a common ci-only line.
	ciCommon := fleet("ubuntu", ci,
		[]string{"c1", "c2", "c3", "c4"}, "ci-common")

	// b1 ALSO has a unique record. Singleton in the build peer-group.
	buildSingleton := makeRec("b1", "ubuntu", build, "build-singleton")
	// c1 ALSO has a unique record. Singleton in the ci peer-group.
	ciSingleton := makeRec("c1", "ubuntu", ci, "ci-singleton")

	records := append(buildCommon, ciCommon...)
	records = append(records, buildSingleton, ciSingleton)

	rows := computeQ3(records, 3)

	// Expect exactly two Q3 rows: one singleton per peer-group.
	if len(rows) != 2 {
		t.Fatalf("expected 2 Q3 rows, got %d: %+v", len(rows), rows)
	}

	gotKeys := map[string]string{}
	for _, r := range rows {
		gotKeys[r.TagKey] = r.SampleHost
	}
	if gotKeys["role=build"] != "b1" {
		t.Errorf("build singleton: got SampleHost=%q, want b1 (row: %+v)", gotKeys["role=build"], rows)
	}
	if gotKeys["role=ci"] != "c1" {
		t.Errorf("ci singleton: got SampleHost=%q, want c1 (row: %+v)", gotKeys["role=ci"], rows)
	}
}

// TestQ3_TagOrderIndependent verifies that the order in which
// the operator passed --tag flags does not leak into the
// peer-group key. The agent canonicalizes via
// core.CanonicalizeTags before emitting; this test is the
// belt-and-braces for downstream consumers.
func TestQ3_TagOrderIndependent(t *testing.T) {
	// Host A has tags in one order; host B has the same tags in
	// the opposite order. Both must land in the same peer-group.
	orderA := []string{"role=build", "env=prod"}
	orderB := []string{"env=prod", "role=build"}

	common := append(
		fleet("ubuntu", orderA, []string{"h1", "h2"}, "common-hash"),
		fleet("ubuntu", orderB, []string{"h3"}, "common-hash")...,
	)
	singleton := makeRec("h4", "ubuntu", orderA, "singleton-hash")
	records := append(common, singleton)

	rows := computeQ3(records, 3)

	if len(rows) != 1 {
		t.Fatalf("expected 1 Q3 row, got %d: %+v", len(rows), rows)
	}
	if rows[0].PeerSize != 4 {
		t.Errorf("PeerSize: got %d, want 4 (h1, h2, h3, h4 should be in one peer-group)",
			rows[0].PeerSize)
	}
	if rows[0].TagKey != "env=prod,role=build" {
		t.Errorf("TagKey: got %q, want canonical sorted form", rows[0].TagKey)
	}
}

// TestQ3_PeerSizeFloor verifies the default peerFloor=3 behavior.
// A peer-group of two hosts is too small to learn a baseline from
// (n=2, every record is by definition either common-to-both or
// singleton-on-one), so the entire peer-group is suppressed.
func TestQ3_PeerSizeFloor(t *testing.T) {
	// Peer-group of size 2: too small under floor=3.
	records := []core.Record{
		makeRec("h1", "alpine", nil, "common"),
		makeRec("h2", "alpine", nil, "common"),
		makeRec("h1", "alpine", nil, "singleton"),
	}
	rows := computeQ3(records, 3)
	if len(rows) != 0 {
		t.Fatalf("peer-group of 2 must be suppressed under floor=3, got %d rows: %+v",
			len(rows), rows)
	}

	// Peer-group of size 3: floor=3 means peerSize >= 3, so 3 passes.
	records = append(records, makeRec("h3", "alpine", nil, "common"))
	rows = computeQ3(records, 3)
	if len(rows) != 1 {
		t.Fatalf("peer-group of 3 should surface 1 singleton, got %d rows: %+v",
			len(rows), rows)
	}
	if rows[0].PeerSize != 3 {
		t.Errorf("PeerSize: got %d, want 3", rows[0].PeerSize)
	}
}

// TestQ3_PeerFloorTunable verifies that the --peer-floor knob lets
// operators tighten or relax the cohort-size requirement. ADR-0015
// plus the v0.3.3 lab showed that over-tagged fleets collapse Q3 to
// zero rows; the flag is the v0.3.4 escape hatch.
func TestQ3_PeerFloorTunable(t *testing.T) {
	// Peer-group of exactly 2 hosts with one singleton across them.
	records := []core.Record{
		makeRec("h1", "alpine", nil, "common"),
		makeRec("h2", "alpine", nil, "common"),
		makeRec("h1", "alpine", nil, "singleton"),
	}

	// peerFloor=3 -> suppressed (the default).
	if got := len(computeQ3(records, 3)); got != 0 {
		t.Errorf("floor=3 on peer-of-2: want 0 rows, got %d", got)
	}
	// peerFloor=2 -> the same dataset now surfaces.
	if got := len(computeQ3(records, 2)); got != 1 {
		t.Errorf("floor=2 on peer-of-2: want 1 row, got %d", got)
	}
	// peerFloor=1 -> any peer-group qualifies (used for sparse fleets).
	if got := len(computeQ3(records, 1)); got != 1 {
		t.Errorf("floor=1 on peer-of-2: want 1 row, got %d", got)
	}
	// peerFloor=4 -> stricter than the data: nothing surfaces.
	if got := len(computeQ3(records, 4)); got != 0 {
		t.Errorf("floor=4 on peer-of-2: want 0 rows, got %d", got)
	}
}

// TestQ3_UntaggedSeparateFromTagged verifies the fleet-migration
// case: a host without any tags forms the "untagged" peer-group
// even when other hosts share its os_id but DO have tags.
// Operators who tag part of the fleet should not have the
// untagged remainder absorbed into a tagged peer-group.
func TestQ3_UntaggedSeparateFromTagged(t *testing.T) {
	tagged := fleet("rhel", []string{"role=db"},
		[]string{"db1", "db2", "db3"}, "common-tagged")
	untagged := fleet("rhel", nil,
		[]string{"u1", "u2", "u3"}, "common-untagged")

	// One singleton per peer-group.
	taggedSingleton := makeRec("db1", "rhel", []string{"role=db"}, "tagged-sing")
	untaggedSingleton := makeRec("u1", "rhel", nil, "untagged-sing")

	records := append(tagged, untagged...)
	records = append(records, taggedSingleton, untaggedSingleton)

	rows := computeQ3(records, 3)

	if len(rows) != 2 {
		t.Fatalf("expected 2 Q3 rows (one per peer-group), got %d: %+v",
			len(rows), rows)
	}

	var sawTagged, sawUntagged bool
	for _, r := range rows {
		switch r.TagKey {
		case "role=db":
			sawTagged = true
			if r.SampleHost != "db1" || r.PeerSize != 3 {
				t.Errorf("tagged peer-group: got %+v", r)
			}
		case "":
			sawUntagged = true
			if r.SampleHost != "u1" || r.PeerSize != 3 {
				t.Errorf("untagged peer-group: got %+v", r)
			}
		default:
			t.Errorf("unexpected TagKey: %q in row %+v", r.TagKey, r)
		}
	}
	if !sawTagged {
		t.Error("tagged peer-group singleton not surfaced")
	}
	if !sawUntagged {
		t.Error("untagged peer-group singleton not surfaced")
	}
}

// TestQ3_RecordCommonAcrossPeerGroups does NOT fire. A line that
// appears on hosts in MULTIPLE peer-groups is a fleet-wide
// baseline, not a peer-group singleton. Each peer-group sees
// >1 host carrying it -> filter (hosts == 1) excludes.
func TestQ3_RecordCommonAcrossPeerGroups(t *testing.T) {
	tagged := fleet("ubuntu", []string{"role=build"},
		[]string{"b1", "b2", "b3"}, "fleet-wide")
	untagged := fleet("ubuntu", nil,
		[]string{"u1", "u2", "u3"}, "fleet-wide")
	records := append(tagged, untagged...)

	rows := computeQ3(records, 3)
	if len(rows) != 0 {
		t.Fatalf("fleet-wide line must surface in no peer-group, got %d rows: %+v",
			len(rows), rows)
	}
}
