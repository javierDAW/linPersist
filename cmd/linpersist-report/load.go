package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jarmidaw/linpersist/internal/core"
)

// maxLineBytes bounds a single NDJSON line. A Record line is a few
// hundred bytes; 4 MiB is generous headroom for a fat content_snippet
// plus signals and hashes. A line longer than this is treated as one
// skipped malformed line (see readFile) rather than a fatal error.
const maxLineBytes = 4 * 1024 * 1024

// loadResult is the outcome of reading one or more NDJSON sources.
type loadResult struct {
	Records []core.Record
	// Files holds the list of source paths that contributed records.
	Files []string
	// Skipped counts lines that failed to parse (blank lines do not
	// count). A non-zero value is surfaced in the report header so the
	// analyst sees data-quality issues at a glance.
	Skipped int
}

// load reads NDJSON from `input`. If `input` is a directory, every
// *.ndjson file directly under it is read (non-recursive by default;
// pass a glob via the CLI for recursive). If `input` is a regular file,
// it is read directly.
func load(input string) (*loadResult, error) {
	info, err := os.Stat(input)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", input, err)
	}
	var files []string
	switch {
	case info.IsDir():
		entries, err := os.ReadDir(input)
		if err != nil {
			return nil, fmt.Errorf("readdir %s: %w", input, err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(name, ".ndjson") &&
				!strings.HasSuffix(name, ".json") {
				continue
			}
			files = append(files, filepath.Join(input, name))
		}
		if len(files) == 0 {
			return nil, fmt.Errorf("no *.ndjson files under %s", input)
		}
	case info.Mode().IsRegular():
		files = []string{input}
	default:
		return nil, fmt.Errorf("%s is neither a regular file nor a directory", input)
	}

	res := &loadResult{Files: files}
	for _, p := range files {
		if err := readFile(p, res); err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
	}
	return res, nil
}

// readFile streams one NDJSON file into res.Records. Malformed lines
// are counted into res.Skipped; blank lines are silently dropped.
//
// A line longer than maxLineBytes is counted as a single skipped line
// and the scan resumes at the next line boundary. This is deliberate:
// a fleet report stacks NDJSON from many hosts, and a corrupt — or
// hostile — host emitting one oversized line must not abort the whole
// report and blind the analyst to every other host. (The previous
// bufio.Scanner returned ErrTooLong, which propagated up and failed the
// entire load.)
func readFile(path string, res *loadResult) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, maxLineBytes)
	for {
		line, oversize, rerr := readLine(br, maxLineBytes)
		if oversize {
			res.Skipped++
			fmt.Fprintf(os.Stderr, "linpersist-report: skipped oversized line (>%d bytes) in %s\n", maxLineBytes, path)
		} else if len(bytes.TrimSpace(line)) > 0 {
			var r core.Record
			if jerr := json.Unmarshal(line, &r); jerr != nil {
				res.Skipped++
				fmt.Fprintf(os.Stderr, "linpersist-report: parse error in %s: %v\n", path, jerr)
			} else {
				res.Records = append(res.Records, r)
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return nil
			}
			return rerr
		}
	}
}

// readLine reads one newline-terminated line from br, bounded to max
// bytes. When a line exceeds max, oversize is true and the remainder of
// that line (up to its terminating newline or EOF) is drained and
// discarded so the next call resumes at a clean line boundary; the
// returned line is then nil. The returned line never includes the
// trailing newline. err is io.EOF only once no more data remains.
//
// The returned slice is a fresh copy, not a view into br's buffer, so
// callers may retain it across subsequent reads.
func readLine(br *bufio.Reader, max int) (line []byte, oversize bool, err error) {
	chunk, err := br.ReadSlice('\n')
	if err == bufio.ErrBufferFull {
		// Line is longer than the buffer (max bytes): drain to the next
		// newline (or EOF) and report it as oversize.
		for err == bufio.ErrBufferFull {
			_, err = br.ReadSlice('\n')
		}
		if err == io.EOF {
			// Drained to EOF; surface the oversize skip now, let the
			// next call observe EOF.
			err = nil
		}
		return nil, true, err
	}
	chunk = bytes.TrimSuffix(chunk, []byte("\n"))
	chunk = bytes.TrimSuffix(chunk, []byte("\r"))
	out := make([]byte, len(chunk))
	copy(out, chunk)
	return out, false, err
}
