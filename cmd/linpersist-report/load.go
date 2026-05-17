package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jarmidaw/linpersist/internal/core"
)

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
func readFile(path string, res *loadResult) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	// A single Record snippet can carry a 256-char content_snippet
	// plus signals + hashes; 1 MiB per line is enough headroom.
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var r core.Record
		if err := json.Unmarshal(line, &r); err != nil {
			res.Skipped++
			fmt.Fprintf(os.Stderr, "linpersist-report: parse error in %s: %v\n", path, err)
			continue
		}
		res.Records = append(res.Records, r)
	}
	return sc.Err()
}
