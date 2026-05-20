// Cross-source audit of the signals catalog.
//
// signals_test.go checks the catalog's internal consistency.
// This file is the heavier-but-load-bearing test: it walks the actual
// source tree and verifies that, for every catalog entry, the modules
// and core helpers declared in EmittedBy really do reference the
// const, AND that no module references a Signal* identifier that is
// missing from the catalog.
//
// The test is intentionally lo-fi: it greps for `core.Signal<Name>`
// (in module code) and `Signal<Name>` (in core/<file>.go) using a
// regex rather than `go/parser` + `go/ast`. The trade-off:
//
//   - Faster to write, easier to reason about, no AST machinery.
//   - In theory false-positive-prone if a module mentions a Signal*
//     identifier inside a string literal or a comment without
//     actually emitting it. In practice the codebase doesn't do that;
//     and even if it did, the resulting "passes when it shouldn't"
//     is a softer failure mode than "fails to detect drift".
//
// If the regex approach ever fails us, switch to AST scanning.

package core

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// repoRoot finds the module root by walking up from the package
// directory until go.mod appears. The audit needs the absolute path
// so it can scan internal/modules/<name>/ regardless of where the
// test is invoked from.
func repoRoot(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := cwd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not locate go.mod above %s", cwd)
		}
		dir = parent
	}
}

// readGoFiles returns the bytes of every .go file under dir
// (non-recursive for module dirs, recursive only when explicitly
// asked) excluding *_test.go.
func readGoFiles(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatalf("readdir %s: %v", dir, err)
	}
	var b strings.Builder
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		if strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		b.Write(data)
		b.WriteByte('\n')
	}
	return b.String()
}

// signalConstName recovers the Signal<Foo> identifier corresponding
// to a catalog Name. The catalog stores the emitted string value
// (e.g. "recent_mtime_7d"); the source code uses the Signal<Foo>
// identifier (e.g. SignalRecentMtime7d). We index the const block
// once and look up by value.
func loadSignalConstIndex(t *testing.T) map[string]string {
	t.Helper()
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "internal", "core", "signals.go"))
	if err != nil {
		t.Fatalf("read signals.go: %v", err)
	}
	// Match: SignalFoo = "foo_bar_baz"
	re := regexp.MustCompile(`(Signal[A-Z][A-Za-z0-9_]*)\s*=\s*"([^"]+)"`)
	out := map[string]string{}
	for _, m := range re.FindAllStringSubmatch(string(data), -1) {
		out[m[2]] = m[1] // value -> identifier
	}
	if len(out) == 0 {
		t.Fatal("loaded zero Signal* constants from signals.go")
	}
	return out
}

// TestSignalEmissionPerCatalogEntry verifies that for every catalog
// entry, every name in EmittedBy actually references the Signal*
// identifier in code. Failure means the catalog declares a phantom
// emitter -- either the module/helper used to emit it and someone
// dropped the call, or the declaration was wishful thinking.
func TestSignalEmissionPerCatalogEntry(t *testing.T) {
	root := repoRoot(t)
	constByValue := loadSignalConstIndex(t)

	for _, sig := range Signals {
		identifier, ok := constByValue[sig.Name]
		if !ok {
			t.Errorf("catalog entry %q has no matching Signal* const in signals.go", sig.Name)
			continue
		}
		for _, emitter := range sig.EmittedBy {
			var src, label string
			if strings.HasPrefix(emitter, "core/") {
				file := strings.TrimPrefix(emitter, "core/") + ".go"
				src = mustReadFile(t, filepath.Join(root, "internal", "core", file))
				label = filepath.Join("internal/core", file)
			} else {
				src = readGoFiles(t, filepath.Join(root, "internal", "modules", emitter))
				label = filepath.Join("internal/modules", emitter)
			}
			if !strings.Contains(src, identifier) {
				t.Errorf("catalog says %q is emitted by %q, but %s does not reference %s",
					sig.Name, emitter, label, identifier)
			}
		}
	}
}

// TestSignalEmissionInverse verifies that every Signal* identifier
// referenced in module code is listed in the catalog as emitted by
// that module. Failure means the codebase emits a signal whose
// catalog entry is missing or whose EmittedBy is stale (typical
// scenario: someone added the emission in a new module and forgot to
// extend EmittedBy).
func TestSignalEmissionInverse(t *testing.T) {
	root := repoRoot(t)
	constByValue := loadSignalConstIndex(t)

	// Build value lookup from identifier so we can map references
	// back to the catalog Name.
	valueByIdent := make(map[string]string, len(constByValue))
	for v, id := range constByValue {
		valueByIdent[id] = v
	}

	// Build catalog index: Name -> set of EmittedBy.
	declared := make(map[string]map[string]struct{}, len(Signals))
	for _, sig := range Signals {
		set := make(map[string]struct{}, len(sig.EmittedBy))
		for _, e := range sig.EmittedBy {
			set[e] = struct{}{}
		}
		declared[sig.Name] = set
	}

	re := regexp.MustCompile(`core\.(Signal[A-Z][A-Za-z0-9_]*)\b`)

	modulesDir := filepath.Join(root, "internal", "modules")
	mods, err := os.ReadDir(modulesDir)
	if err != nil {
		t.Fatalf("readdir modules: %v", err)
	}
	for _, m := range mods {
		if !m.IsDir() {
			continue
		}
		mod := m.Name()
		src := readGoFiles(t, filepath.Join(modulesDir, mod))
		seen := map[string]struct{}{}
		for _, match := range re.FindAllStringSubmatch(src, -1) {
			seen[match[1]] = struct{}{}
		}
		for ident := range seen {
			value, ok := valueByIdent[ident]
			if !ok {
				t.Errorf("module %s references core.%s but signals.go declares no such const",
					mod, ident)
				continue
			}
			set, ok := declared[value]
			if !ok {
				t.Errorf("module %s emits %q but the signals catalog has no entry for it",
					mod, value)
				continue
			}
			if _, listed := set[mod]; !listed {
				t.Errorf("module %s emits %q but the catalog EmittedBy does not list it",
					mod, value)
			}
		}
	}

	// Same check for the two core helpers that emit signals
	// directly. Hand-rolled list because there are only two and
	// they are explicit by design (ADR-0009 provenance, ADR-0010
	// /proc snapshot).
	for _, helper := range []string{"provenance", "proclive"} {
		path := filepath.Join(root, "internal", "core", helper+".go")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		// In-package references use bare Signal<Foo>, not core.Signal<Foo>.
		reBare := regexp.MustCompile(`\b(Signal[A-Z][A-Za-z0-9_]*)\b`)
		seen := map[string]struct{}{}
		for _, match := range reBare.FindAllStringSubmatch(string(data), -1) {
			seen[match[1]] = struct{}{}
		}
		emitter := "core/" + helper
		for ident := range seen {
			value, ok := valueByIdent[ident]
			if !ok {
				continue
			}
			set, ok := declared[value]
			if !ok {
				t.Errorf("%s references %s but the signals catalog has no entry for %q",
					emitter, ident, value)
				continue
			}
			if _, listed := set[emitter]; !listed {
				t.Errorf("%s emits %q but the catalog EmittedBy does not list it",
					emitter, value)
			}
		}
	}
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
