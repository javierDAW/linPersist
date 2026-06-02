package core

import (
	"os"
	"syscall"
	"unsafe"
)

// Inode flag ioctl + bit values (linux/fs.h). FS_IOC_GETFLAGS reads the
// ext/xfs/btrfs inode attribute word (the chattr flags). The kernel
// writes an int, so a 4-byte int32 destination is correct on every
// linux/<arch> the agent targets (all little-endian).
const (
	fsIocGetflags = 0x80086601
	fsImmutableFl = 0x00000010 // FS_IMMUTABLE_FL (chattr +i)
	fsAppendFl    = 0x00000020 // FS_APPEND_FL (chattr +a)
)

// InodeFlagSignals returns immutable_flag / append_only_flag for the file
// at path by querying FS_IOC_GETFLAGS. Best-effort: returns nil on any
// error (filesystem that does not support the ioctl, EACCES, a FIFO or
// device, a symlink, ENOTTY). Opened O_NONBLOCK so a FIFO/device never
// blocks and O_NOFOLLOW so a symlink is refused (we report on the locus
// inode itself, never its target). The emit sink memoizes per locus.
func InodeFlagSignals(path string) []string {
	f, err := os.OpenFile(path,
		os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil
	}
	defer f.Close()
	var attrs int32
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(),
		uintptr(fsIocGetflags), uintptr(unsafe.Pointer(&attrs)))
	if errno != 0 {
		return nil
	}
	var out []string
	if attrs&fsImmutableFl != 0 {
		out = append(out, SignalImmutableFlag)
	}
	if attrs&fsAppendFl != 0 {
		out = append(out, SignalAppendOnlyFlag)
	}
	return out
}
