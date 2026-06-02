package suidbits

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// vfsCapV2 builds a little-endian vfs_cap_data blob (revision 2) with the
// given permitted[0] capability mask and the effective flag set.
func vfsCapV2(permitted0 uint32) []byte {
	b := make([]byte, 20)
	const vfsCapRevision2 = 0x02000000
	const vfsCapFlagsEffective = 0x000001
	binary.LittleEndian.PutUint32(b[0:4], vfsCapRevision2|vfsCapFlagsEffective)
	binary.LittleEndian.PutUint32(b[4:8], permitted0) // permitted[0]
	binary.LittleEndian.PutUint32(b[8:12], 0)         // inheritable[0]
	binary.LittleEndian.PutUint32(b[12:16], 0)        // permitted[1]
	binary.LittleEndian.PutUint32(b[16:20], 0)        // inheritable[1]
	return b
}

// TestReadFileCaps sets a real security.capability xattr and reads it
// back. Setting this xattr normally needs CAP_SETFCAP; if the test is not
// privileged enough the Setxattr fails and we skip rather than fail.
func TestReadFileCaps(t *testing.T) {
	const capSetuid = 1 << 7
	const capNetRaw = 1 << 13 // not in privilegedCapMask

	cases := []struct {
		name           string
		mask           uint32
		wantPrivileged bool
	}{
		{"cap_setuid -> privileged", capSetuid, true},
		{"cap_net_raw -> present but not privileged", capNetRaw, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := filepath.Join(t.TempDir(), "bin")
			if err := os.WriteFile(f, []byte("\x7fELF stub"), 0o755); err != nil {
				t.Fatalf("write: %v", err)
			}
			if err := syscall.Setxattr(f, "security.capability", vfsCapV2(tc.mask), 0); err != nil {
				t.Skipf("cannot set security.capability (need CAP_SETFCAP): %v", err)
			}
			present, privileged := readFileCaps(f)
			if !present {
				t.Fatal("readFileCaps: present=false, want true")
			}
			if privileged != tc.wantPrivileged {
				t.Errorf("privileged=%v, want %v", privileged, tc.wantPrivileged)
			}
		})
	}
}

// TestReadFileCaps_None: a file with no xattr reports not present.
func TestReadFileCaps_None(t *testing.T) {
	f := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(f, []byte("x"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	if present, _ := readFileCaps(f); present {
		t.Error("readFileCaps on a plain file reported present=true")
	}
}
