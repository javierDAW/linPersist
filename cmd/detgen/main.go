// Command detgen regenerates the Q7 detection block of
// tools/stack_demo.sql from detections.yaml.
//
// The Go-native matcher (cmd/linpersist-report) and the SQL Q7
// clause have to stay in sync — they're two consumers of the same
// rule set. detgen is the source-of-truth crank: edit
// detections.yaml, run `go run ./cmd/detgen`, commit both files
// together. Drift between the committed SQL and the regenerated
// output is caught by `--verify` (and by `make detgen-verify` in CI).
//
// Modes:
//
//	go run ./cmd/detgen            # rewrite tools/stack_demo.sql
//	go run ./cmd/detgen --verify   # exit 1 if regenerate would diff
//	go run ./cmd/detgen --dry-run  # print the new SQL to stdout, do not write
//
// Flags:
//
//	-yaml   path to detections.yaml      (default: ./detections.yaml)
//	-sql    path to stack_demo.sql       (default: ./tools/stack_demo.sql)
//	-verify exit 1 if the regen would change the file (release gate)
//	-dry-run print the regenerated SQL to stdout without writing
//
// detgen is intentionally narrow. It does NOT validate semantic
// equivalence with the previous SQL block (that's the matcher's
// golden tests). It only mechanically renders the YAML into the
// region between the BEGIN/END GENERATED markers and writes the file.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/jarmidaw/linpersist/internal/detections"
)

const (
	beginMarker = "-- BEGIN GENERATED Q7 detections (from detections.yaml — DO NOT EDIT BY HAND)"
	endMarker   = "-- END GENERATED"
)

func main() {
	var (
		yamlPath string
		sqlPath  string
		verify   bool
		dryRun   bool
	)
	flag.StringVar(&yamlPath, "yaml", "detections.yaml", "path to detections.yaml")
	flag.StringVar(&sqlPath, "sql", "tools/stack_demo.sql", "path to stack_demo.sql")
	flag.BoolVar(&verify, "verify", false, "exit 1 if the file would change (release gate)")
	flag.BoolVar(&dryRun, "dry-run", false, "print regenerated SQL to stdout without writing")
	flag.Parse()

	yamlBytes, err := os.ReadFile(yamlPath)
	if err != nil {
		fatal("read %s: %v", yamlPath, err)
	}
	rs, err := detections.Load(yamlBytes, nil, nil)
	if err != nil {
		fatal("%v", err)
	}

	rendered := renderBlock(rs)

	sqlBytes, err := os.ReadFile(sqlPath)
	if err != nil {
		fatal("read %s: %v", sqlPath, err)
	}
	newSQL, err := substitute(string(sqlBytes), rendered)
	if err != nil {
		fatal("substitute: %v", err)
	}

	if dryRun {
		os.Stdout.WriteString(newSQL)
		return
	}

	if newSQL == string(sqlBytes) {
		if verify {
			fmt.Fprintf(os.Stderr, "detgen: %s is up to date\n", sqlPath)
			return
		}
		fmt.Fprintf(os.Stderr, "detgen: %s unchanged\n", sqlPath)
		return
	}

	if verify {
		fmt.Fprintf(os.Stderr, "detgen: drift detected — %s does not match detections.yaml\n", sqlPath)
		fmt.Fprintln(os.Stderr, "        run `go run ./cmd/detgen` to regenerate, then commit both files")
		os.Exit(1)
	}

	if err := os.WriteFile(sqlPath, []byte(newSQL), 0o644); err != nil {
		fatal("write %s: %v", sqlPath, err)
	}
	fmt.Fprintf(os.Stderr, "detgen: wrote %s (%d detections)\n", sqlPath, len(rs.Detections))
}

// renderBlock produces the body that lives between the BEGIN/END
// markers. The leading helper comments ("Regenerate with: ...",
// "Release gate: ...") are preserved verbatim so a human reading
// the SQL knows how the block is maintained.
func renderBlock(rs *detections.RuleSet) string {
	var b strings.Builder
	b.WriteString("  -- Regenerate with: go run ./cmd/detgen\n")
	b.WriteString("  -- Release gate:    go run ./cmd/detgen --verify  (or: make detgen-verify)\n")
	body := rs.RenderSQL(detections.DefaultSQLOptions)
	b.WriteString("  ")
	b.WriteString(body)
	b.WriteString("\n")
	return b.String()
}

// substitute swaps the contents of the BEGIN..END region in src with
// generated. Both markers must be present exactly once; missing or
// duplicate markers are a hard error.
func substitute(src, generated string) (string, error) {
	begin := strings.Index(src, beginMarker)
	if begin == -1 {
		return "", fmt.Errorf("BEGIN marker %q not found", beginMarker)
	}
	if strings.Count(src, beginMarker) > 1 {
		return "", fmt.Errorf("BEGIN marker appears more than once")
	}
	end := strings.Index(src, endMarker)
	if end == -1 {
		return "", fmt.Errorf("END marker %q not found", endMarker)
	}
	if strings.Count(src, endMarker) > 1 {
		return "", fmt.Errorf("END marker appears more than once")
	}
	if end < begin {
		return "", fmt.Errorf("END marker appears before BEGIN marker")
	}
	// Find the newline that closes the BEGIN line.
	beginLineEnd := strings.IndexByte(src[begin:], '\n')
	if beginLineEnd == -1 {
		return "", fmt.Errorf("BEGIN marker is not followed by a newline")
	}
	beginLineEnd += begin + 1 // first byte after the marker line
	// The END marker line begins at `end` (no leading indent in the
	// SQL formatting we control). We want to keep the END marker
	// intact, so we splice the generated body between beginLineEnd
	// and the start of the END marker's indent.
	endLineStart := strings.LastIndexByte(src[:end], '\n') + 1
	return src[:beginLineEnd] + generated + src[endLineStart:], nil
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "detgen: "+format+"\n", a...)
	os.Exit(1)
}
