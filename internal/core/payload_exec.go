package core

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"time"
)

// PayloadExecSignals derives the exec-target persistence signals for an
// absolute payload path lifted from a script body (via ExtractExecTarget).
// It returns SignalInterpreterInTmp when the payload is under a TmpDir, and
// exactly one of SignalExecTargetOrphan (missing on disk) or
// SignalRecentTargetMtime7d (present and modified within the last 7 days).
// resolve maps the logical payload path to its on-disk path (honoring a
// test/collection --root); a nil resolve means identity.
//
// This is the script-class sibling of cron.execTargetSignals: cron lifts
// the command from the schedule line, sysv/motd/netdispatch/atjobs lift it
// from the script body, but the target signals must be identical so the
// same detection rules fire regardless of which locus carries the payload.
func PayloadExecSignals(target string, resolve func(string) string, now time.Time) []string {
	if !strings.HasPrefix(target, "/") {
		return nil
	}
	var out []string
	for _, prefix := range TmpDirs {
		if strings.HasPrefix(target, prefix) {
			out = append(out, SignalInterpreterInTmp)
			break
		}
	}
	resolved := target
	if resolve != nil {
		resolved = resolve(target)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			out = append(out, SignalExecTargetOrphan)
		}
		return out
	}
	if d := now.Sub(info.ModTime().UTC()); d >= 0 && d < 7*24*time.Hour {
		out = append(out, SignalRecentTargetMtime7d)
	}
	return out
}

// AnnotatePayloadExec parses a script-class record's body for the external
// command it invokes and, when that payload is *suspicious* (under /tmp or
// orphan), repoints rec.ExecTarget at the payload and appends the matching
// signals. A benign packaged payload — a sysv script sourcing
// /lib/lsb/init-functions, a dispatcher hook calling a daemon that exists —
// leaves ExecTarget on the file and adds nothing, so false-positive
// behavior on the settled baseline is unchanged.
//
// Modules call this AFTER setting the file-self ExecTarget and BEFORE the
// provenance / live-process annotation, so those key off the repointed
// target. Returns true when it promoted.
//
// Why it exists: sysv/motd/netdispatch/atjobs historically recorded a
// script that runs `/tmp/.x` only as a non-package file and never parsed
// the body, so it never fired interpreter_in_tmp + exec_target_orphan and
// never escalated to the payload_under_tmp_via_persistence (Q7) rule the
// way cron and systemd do. Verified empirically as a coverage gap by the
// nspawn lab's per-implant gate (validate-catalog.py).
func AnnotatePayloadExec(rec *Record, body []byte, resolve func(string) string, now time.Time, maxSize int64) bool {
	target := ExtractExecTarget(body)
	if target == "" {
		return false
	}
	sigs := PayloadExecSignals(target, resolve, now)
	// Promote only on the /tmp-payload shape — the documented coverage gap.
	// A non-tmp orphan reference alone is left as-is (ExecTarget stays the
	// file): a benign job/init script may name a binary that is simply
	// absent in a chroot/appliance/test view, and firing exec_target_orphan
	// on every such reference is the FP economics these loci must avoid. The
	// dangling-/tmp case additionally carries exec_target_orphan, which is
	// exactly what payload_under_tmp_via_persistence needs.
	inTmp := false
	for _, s := range sigs {
		if s == SignalInterpreterInTmp {
			inTmp = true
			break
		}
	}
	if !inTmp {
		return false
	}
	rec.ExecTarget = target
	rec.ExecTargetSHA256 = ""
	resolved := target
	if resolve != nil {
		resolved = resolve(target)
	}
	if sum, ok := HashFileCapped(resolved, maxSize); ok {
		rec.ExecTargetSHA256 = sum
	}
	rec.Signals = DedupSignals(append(rec.Signals, sigs...))
	return true
}
