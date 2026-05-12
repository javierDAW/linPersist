package core

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
)

// HashHex returns the lowercase hex sha256 of b. It is the canonical
// hashing function used for content_sha256, content_norm_sha256 and
// exec_target_sha256 fields. Keep callers using this function rather
// than rolling their own to avoid drift in the hash representation.
func HashHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// HashHexString is HashHex over the bytes of s.
func HashHexString(s string) string {
	return HashHex([]byte(s))
}

// HashReader streams r through sha256 and returns the hex digest. Use
// this for files large enough that loading them into memory is
// undesirable. Returns the bytes read alongside the digest so callers
// can populate Record.Size in the same pass.
func HashReader(r io.Reader) (digest string, size int64, err error) {
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
