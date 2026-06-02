package core

import (
	"os"
	"syscall"
	"time"
)

// FillFileMeta populates ownership, mode and timestamp fields of rec from
// the provided FileInfo. On Linux the Stat_t syscall struct supplies the
// raw POSIX mode bits, uid/gid and atime/ctime; on any other platform the
// Mode field is derived from FileInfo.Mode().Perm() and the optional
// timestamp pointers are left nil.
//
// Mode is intentionally derived from the raw POSIX bits (mask 0o7777)
// rather than from os.FileMode flags, which mix Go-private bits with
// POSIX bits in a way that does not round-trip to the four-digit octal
// representation the wire schema expects.
//
// The Sec/Nsec fields go through explicit int64 conversions so that 32-bit
// GOARCHes (linux/386, linux/arm/v7) continue to compile — both fields are
// platform-dependent integer types on those targets.
func FillFileMeta(rec *Record, info os.FileInfo) {
	size := info.Size()
	rec.Size = &size
	mt := info.ModTime().UTC()
	rec.MTime = &mt
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		uid := uint32(st.Uid)
		gid := uint32(st.Gid)
		rec.OwnerUID = &uid
		rec.OwnerGID = &gid
		rec.Mode = FormatMode(uint32(st.Mode) & 0o7777)
		atime := time.Unix(int64(st.Atim.Sec), int64(st.Atim.Nsec)).UTC()
		ctime := time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec)).UTC()
		rec.ATime = &atime
		rec.CTime = &ctime
	} else {
		// Non-Linux fallback: loses setuid/setgid/sticky. Acceptable
		// because the agent is Linux-only by charter (ADR-0001).
		rec.Mode = FormatMode(uint32(info.Mode().Perm()))
	}
}

// RecentCtimeSignals returns the recent_ctime_{7d,30d} signal(s) for a
// record's inode change time relative to collectedAt. It is the central
// anti-timestomp counterpart to each module's recent_mtime_* derivation:
// because every Record already carries CTime and CollectedAt by the time
// it reaches the emit sink, the sink computes this once for all modules
// instead of threading a clock through 20+ baseSignals implementations.
//
// Returns nil when ctime is absent (non-Linux fallback, or a record with
// no on-disk locus) or when collectedAt is zero. Windows are evaluated in
// UTC and are mutually exclusive, mirroring the mtime bands so a backend
// can diff the two sets directly: recent_ctime_7d present while
// recent_mtime_7d is absent is the timestomp tell.
func RecentCtimeSignals(ctime *time.Time, collectedAt time.Time) []string {
	if ctime == nil || collectedAt.IsZero() {
		return nil
	}
	delta := collectedAt.UTC().Sub(ctime.UTC())
	switch {
	case delta >= 0 && delta < 7*24*time.Hour:
		return []string{SignalRecentCtime7d}
	case delta >= 7*24*time.Hour && delta < 30*24*time.Hour:
		return []string{SignalRecentCtime30d}
	default:
		return nil
	}
}
