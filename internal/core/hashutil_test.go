package core

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// Known-vector sha256 digests. These are not implementation details
// of linpersist; they are sha256 of the literal inputs. Asserting
// against them protects against accidental drift in the hash format
// (e.g. switching to base64 or dropping the hex encoding).
const (
	// echo -n "" | sha256sum
	sha256Empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	// echo -n "abc" | sha256sum
	sha256ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
)

func TestHashHex_KnownVectors(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"empty", []byte{}, sha256Empty},
		{"nil", nil, sha256Empty},
		{"abc", []byte("abc"), sha256ABC},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := HashHex(tc.in)
			if got != tc.want {
				t.Errorf("HashHex(%q) = %q; want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestHashHex_FormatShape(t *testing.T) {
	// All-lowercase, 64 hex characters, no prefix. The Record fields
	// content_sha256 / content_norm_sha256 carry this format verbatim;
	// schema-v1 contract.
	got := HashHex([]byte("anything"))
	if len(got) != 64 {
		t.Errorf("length = %d; want 64", len(got))
	}
	if got != strings.ToLower(got) {
		t.Errorf("digest %q is not all-lowercase", got)
	}
	for _, r := range got {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			t.Errorf("non-hex character %q in digest %q", r, got)
			break
		}
	}
}

func TestHashHexString_EquivalentToHashHex(t *testing.T) {
	inputs := []string{"", "abc", "linpersist", "/etc/cron.d/backup",
		"line with spaces and\ttabs"}
	for _, s := range inputs {
		want := HashHex([]byte(s))
		got := HashHexString(s)
		if got != want {
			t.Errorf("HashHexString(%q) = %q; HashHex of same bytes = %q",
				s, got, want)
		}
	}
}

func TestHashReader_MatchesHashHex(t *testing.T) {
	// Streaming and one-shot hashing MUST converge on the same digest
	// or downstream consumers see "two hosts" for what is one file.
	payload := []byte("the quick brown fox jumps over the lazy dog\n")
	want := HashHex(payload)

	got, size, err := HashReader(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("HashReader returned error: %v", err)
	}
	if got != want {
		t.Errorf("HashReader digest = %q; HashHex digest = %q", got, want)
	}
	if size != int64(len(payload)) {
		t.Errorf("HashReader size = %d; want %d", size, len(payload))
	}
}

func TestHashReader_Empty(t *testing.T) {
	got, size, err := HashReader(strings.NewReader(""))
	if err != nil {
		t.Fatalf("HashReader on empty: %v", err)
	}
	if got != sha256Empty {
		t.Errorf("empty digest = %q; want %q", got, sha256Empty)
	}
	if size != 0 {
		t.Errorf("empty size = %d; want 0", size)
	}
}

func TestHashReader_LargePayload(t *testing.T) {
	// 1 MiB of zeros. Confirms HashReader handles input that exceeds
	// any sensible single-buffer read. The expected digest is
	// whatever HashHex computes over the same buffer: pinning a
	// hardcoded value would make this test brittle without buying
	// anything KnownVectors does not already cover.
	payload := make([]byte, 1<<20)
	got, size, err := HashReader(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("HashReader on 1MiB: %v", err)
	}
	if size != int64(len(payload)) {
		t.Errorf("size = %d; want %d", size, len(payload))
	}
	if want := HashHex(payload); got != want {
		t.Errorf("1MiB digest = %q; HashHex of same buffer = %q", got, want)
	}
}

// failingReader returns the given bytes then a sentinel error on the
// next Read. Used to confirm HashReader propagates I/O errors.
type failingReader struct {
	data    []byte
	failErr error
	served  bool
}

func (r *failingReader) Read(p []byte) (int, error) {
	if !r.served {
		r.served = true
		n := copy(p, r.data)
		return n, nil
	}
	return 0, r.failErr
}

func TestHashReader_PropagatesError(t *testing.T) {
	sentinel := errors.New("synthetic read failure")
	r := &failingReader{data: []byte("partial"), failErr: sentinel}
	digest, size, err := HashReader(r)
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v; want errors.Is(...) %v", err, sentinel)
	}
	if digest != "" {
		t.Errorf("digest on error = %q; want empty string", digest)
	}
	if size != 0 {
		t.Errorf("size on error = %d; want 0", size)
	}
}

// alwaysErrReader satisfies io.Reader but returns the sentinel on
// every call, no bytes consumed. Confirms an error before any read
// surfaces correctly.
type alwaysErrReader struct{ err error }

func (r alwaysErrReader) Read(p []byte) (int, error) { return 0, r.err }

func TestHashReader_FailsOnFirstRead(t *testing.T) {
	sentinel := errors.New("immediate failure")
	_, _, err := HashReader(alwaysErrReader{err: sentinel})
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v; want errors.Is(...) %v", err, sentinel)
	}
}

// Sanity: io.EOF is NOT propagated as an error (io.Copy treats it as
// the normal end-of-stream condition). The test pins this behavior so
// future refactors of HashReader do not regress to surfacing EOF.
func TestHashReader_EOFIsNotError(t *testing.T) {
	r := bytes.NewReader([]byte("done"))
	digest, size, err := HashReader(r)
	if err != nil {
		t.Errorf("EOF treated as error: %v", err)
	}
	if digest == "" {
		t.Error("digest is empty after successful read")
	}
	if size != 4 {
		t.Errorf("size = %d; want 4", size)
	}
	// Subsequent Read returns EOF; HashReader should already have
	// returned by now.
	_, err = r.Read(make([]byte, 1))
	if !errors.Is(err, io.EOF) {
		t.Errorf("post-read err = %v; want io.EOF", err)
	}
}
