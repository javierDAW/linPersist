package main

import (
	"reflect"
	"testing"

	"github.com/jarmidaw/linpersist/internal/core"
)

func TestReconcileRoster(t *testing.T) {
	recs := []core.Record{
		{HostID: "id-web", HostMeta: core.HostMeta{HostnameHash: core.HashHostname("web-01")}},
		{HostID: "id-db", HostMeta: core.HostMeta{HostnameHash: core.HashHostname("db-01"), Hostname: "db-01"}},
	}
	roster := []string{
		"web-01",          // present via hashed plaintext
		"db-01",           // present via plaintext + hash
		"id-web",          // present via raw host_id
		"WEB-01",          // present (case-insensitive normalization)
		"bastion-99",      // ABSENT
		"web-01",          // duplicate of present -> ignored
		"cache-77",        // ABSENT
	}
	got := reconcileRoster(recs, roster)
	want := []string{"bastion-99", "cache-77"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("reconcileRoster = %v, want %v", got, want)
	}
}

func TestReconcileRosterEmpty(t *testing.T) {
	if got := reconcileRoster(nil, nil); len(got) != 0 {
		t.Errorf("empty roster -> %v, want none", got)
	}
}
