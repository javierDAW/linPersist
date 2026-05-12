# Normalization rules

Normalization is the spine of `linpersist`. Two hosts running the same
malicious cron entry MUST produce the same `content_norm_sha256` even
if one host has trailing tabs, the other has a Windows newline, and a
third has a stale comment above the entry. Without that property,
frequency stacking degenerates into hash noise.

## Contract every module's `Normalize` honors

1. **Deterministic.** Same input always yields the same output. No
   timestamps, no random ordering of map iteration, no locale-dependent
   case folding.
2. **Idempotent.** `Normalize(Normalize(x)) == Normalize(x)`.
3. **Whitespace-insensitive** within the rules of the file format.
   Crontab does not care about extra spaces between fields; the
   normalizer collapses them. systemd.unit's key-value lines do care
   about quoting; the normalizer preserves it.
4. **Comment-stripping** where the file format defines comments.
   `#`-prefixed lines for shell/cron/sshd; `;` for some legacy formats.
   Inline comments are stripped only when the format documents them as
   such (cron does not document inline comments — those stay).
5. **Key-order canonicalization** where the format allows arbitrary
   ordering. systemd `[Section]` blocks are sorted; keys within each
   section sorted; values left verbatim. authorized_keys options
   (`from=`, `command=`, `no-pty`) sorted alphabetically.
6. **Newline-canonical.** All trailing `\r` stripped. Output always
   ends with exactly one `\n`.
7. **Encoding.** Treat input as UTF-8. Invalid UTF-8 byte sequences are
   preserved verbatim; do NOT replace them with U+FFFD (we want the
   bytes' hash to expose the corruption).

## Shared helpers

Two helpers live in `internal/core/normalize.go` and are composed by
most modules:

- `StripLineComments(b, prefix)` — drops everything from `prefix` to
  end-of-line, trims trailing whitespace, drops resulting empty lines,
  guarantees a single trailing newline.
- `CollapseWhitespace(b)` — collapses runs of spaces and tabs into a
  single space; preserves newlines.

Per-module normalizers MUST live in `internal/modules/<name>/normalize.go`
and MUST be exported as `Normalize(raw []byte) []byte` so the test
package can call them directly.

## Test obligation

For each module, at least one test asserts that **two semantically
equivalent inputs** (whitespace, comments, key reorderings) hash to the
same `content_norm_sha256`. Golden NDJSON fixtures are not enough; the
equivalence test is the one that catches drift after refactoring.

Example skeleton:

```go
func TestNormalize_EquivalentInputs(t *testing.T) {
    a := []byte("MAILTO=root\n* * * * * root /bin/true\n")
    b := []byte("# comment\nMAILTO=root\n* * * * *  root   /bin/true   \n\n")
    if HashHex(Normalize(a)) != HashHex(Normalize(b)) {
        t.Fatalf("equivalent inputs hash differently")
    }
}
```

## What normalization does NOT do

- It does **not** resolve `exec_target` paths against `$PATH` (that's
  the module's resolver step, run before computing signals).
- It does **not** strip secrets. authorized_keys lines stay verbatim in
  the normalized form; the module is responsible for never placing the
  raw key blob in `content_snippet`.
- It does **not** rewrite paths (no symlink resolution, no canonical
  case folding on case-sensitive filesystems).
