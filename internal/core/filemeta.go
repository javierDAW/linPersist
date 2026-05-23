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
