// Command matrix-audit is the linpersist release gate that pins
// matrix.yaml to the code that actually ships.
//
// It is a deliberately small program that:
//
//  1. Parses matrix.yaml (the source of truth for MITRE ATT&CK Linux
//     persistence coverage).
//  2. Instantiates the same set of core.Module implementations that
//     cmd/linpersist registers at runtime.
//  3. Diffs the (module, site_class) universes from those two
//     sources and reports drift to stderr.
//
// Three classes of drift are fatal (exit 1):
//
//   - code-without-matrix: a module emits a site_class that is not
//     declared in matrix.yaml. A new collector is shipping without
//     being documented in the canonical taxonomy.
//   - matrix-lying: matrix.yaml declares a site_class as status
//     "implemented" (or "tested") but no module emits it. The doc has
//     drifted ahead of reality.
//   - planned-with-code: matrix.yaml declares a site_class as status
//     "planned" but a module already emits it. Someone started the
//     implementation without flipping the status to wip/implemented.
//
// A fourth check, module name mismatch, also fails: matrix.yaml says
// module X owns site_class Y, but the module that actually emits Y is
// named Z.
//
// On the happy path the program prints a one-line summary to stderr
// and exits 0:
//
//	matrix-audit: OK -- 17 implemented, 6 planned, 0 drift
//
// See ADR-0001 for the architectural rationale.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/jarmidaw/linpersist/internal/core"
	"github.com/jarmidaw/linpersist/internal/modules/atjobs"
	"github.com/jarmidaw/linpersist/internal/modules/cron"
	"github.com/jarmidaw/linpersist/internal/modules/grub"
	"github.com/jarmidaw/linpersist/internal/modules/kmod"
	"github.com/jarmidaw/linpersist/internal/modules/ldso"
	"github.com/jarmidaw/linpersist/internal/modules/motd"
	"github.com/jarmidaw/linpersist/internal/modules/netdispatch"
	"github.com/jarmidaw/linpersist/internal/modules/pam"
	"github.com/jarmidaw/linpersist/internal/modules/passwd"
	"github.com/jarmidaw/linpersist/internal/modules/polkit"
	"github.com/jarmidaw/linpersist/internal/modules/profile"
	"github.com/jarmidaw/linpersist/internal/modules/ssh"
	"github.com/jarmidaw/linpersist/internal/modules/sshd"
	"github.com/jarmidaw/linpersist/internal/modules/sudoers"
	"github.com/jarmidaw/linpersist/internal/modules/systemd"
	"github.com/jarmidaw/linpersist/internal/modules/sysv"
	"github.com/jarmidaw/linpersist/internal/modules/udev"
	"github.com/jarmidaw/linpersist/internal/modules/xdg"
)

// matrixEntry is the subset of a matrix.yaml site_class row this tool
// reads. Other keys (mitre, loci, notes, test_coverage) are ignored:
// they are not part of the audit invariants.
type matrixEntry struct {
	SiteClass string `yaml:"site_class"`
	Module    string `yaml:"module"`
	Status    string `yaml:"status"`
}

// matrixFile is the top-level shape of matrix.yaml that matters here.
type matrixFile struct {
	SiteClasses []matrixEntry `yaml:"site_classes"`
}

// coverage represents one (module, site_class) pair that the code
// actually emits at runtime.
type coverage struct {
	Module    string
	SiteClass string
}

// validStatuses is the closed enum from matrix.yaml's header comment.
// matrix-audit refuses unknown values to catch typos.
var validStatuses = map[string]struct{}{
	"planned":     {},
	"wip":         {},
	"implemented": {},
	"tested":      {},
}

func main() {
	matrixPath := flag.String("matrix", "matrix.yaml",
		"Path to matrix.yaml")
	flag.Parse()

	raw, err := os.ReadFile(*matrixPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "matrix-audit: read %s: %v\n", *matrixPath, err)
		os.Exit(2)
	}

	mf, err := parseMatrix(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "matrix-audit: parse %s: %v\n", *matrixPath, err)
		os.Exit(2)
	}

	code := codeCoverage(registeredModules())

	drift := audit(mf.SiteClasses, code)
	if len(drift) > 0 {
		for _, msg := range drift {
			fmt.Fprintln(os.Stderr, msg)
		}
		fmt.Fprintf(os.Stderr, "matrix-audit: FAIL -- %d drift entry/entries\n",
			len(drift))
		os.Exit(1)
	}

	s := summarize(mf.SiteClasses)
	fmt.Fprintf(os.Stderr,
		"matrix-audit: OK -- %d implemented, %d planned, %d wip, %d tested, %d drift\n",
		s.implemented, s.planned, s.wip, s.tested, 0)
}

// registeredModules returns the set of modules that cmd/linpersist
// actually wires into its runner. Keeping this list in sync with the
// linpersist binary is part of what matrix-audit guards against; the
// two lists must be edited together when a new module is added.
func registeredModules() []core.Module {
	return []core.Module{
		atjobs.New(atjobs.Options{}),
		cron.New(cron.Options{}),
		ldso.New(ldso.Options{}),
		ssh.New(ssh.Options{}),
		sudoers.New(sudoers.Options{}),
		sshd.New(sshd.Options{}),
		passwd.New(passwd.Options{}),
		pam.New(pam.Options{}),
		profile.New(profile.Options{}),
		systemd.New(systemd.Options{}),
		sysv.New(sysv.Options{}),
		motd.New(motd.Options{}),
		kmod.New(kmod.Options{}),
		udev.New(udev.Options{}),
		polkit.New(polkit.Options{}),
		netdispatch.New(netdispatch.Options{}),
		grub.New(grub.Options{}),
		xdg.New(xdg.Options{}),
	}
}

// parseMatrix decodes matrix.yaml bytes into a matrixFile.
func parseMatrix(raw []byte) (matrixFile, error) {
	var mf matrixFile
	if err := yaml.Unmarshal(raw, &mf); err != nil {
		return matrixFile{}, err
	}
	return mf, nil
}

// codeCoverage walks the registered modules and returns the set of
// (module, site_class) pairs they emit.
func codeCoverage(modules []core.Module) []coverage {
	var out []coverage
	for _, m := range modules {
		for _, sc := range m.SiteClasses() {
			out = append(out, coverage{Module: m.Name(), SiteClass: sc})
		}
	}
	return out
}

// audit is the load-bearing pure function. Given the matrix entries
// and the runtime coverage, it returns the list of human-readable
// drift messages. An empty return value means the repo is consistent.
//
// audit makes no assumptions about ordering and is safe to call from
// tests with hand-crafted inputs.
func audit(matrix []matrixEntry, code []coverage) []string {
	var msgs []string

	// Index matrix by site_class so we can look up the declared
	// module / status from either side of the diff.
	type matrixInfo struct {
		Module string
		Status string
	}
	byMatrix := make(map[string]matrixInfo, len(matrix))

	// First: catch unknown statuses and duplicated site_classes.
	seenSC := make(map[string]struct{}, len(matrix))
	for _, e := range matrix {
		if _, ok := validStatuses[e.Status]; !ok {
			msgs = append(msgs,
				fmt.Sprintf("matrix-audit: %s: invalid status %q "+
					"(expected one of planned, wip, implemented, tested)",
					e.SiteClass, e.Status))
		}
		if _, dup := seenSC[e.SiteClass]; dup {
			msgs = append(msgs,
				fmt.Sprintf("matrix-audit: %s: duplicate site_class entry in matrix.yaml",
					e.SiteClass))
			continue
		}
		seenSC[e.SiteClass] = struct{}{}
		byMatrix[e.SiteClass] = matrixInfo{Module: e.Module, Status: e.Status}
	}

	// Build the runtime side, also deduplicated.
	byCode := make(map[string]string, len(code)) // site_class -> module
	for _, c := range code {
		if prev, dup := byCode[c.SiteClass]; dup {
			msgs = append(msgs,
				fmt.Sprintf("matrix-audit: %s: emitted by both %q and %q "+
					"(modules MUST own disjoint site_class sets)",
					c.SiteClass, prev, c.Module))
			continue
		}
		byCode[c.SiteClass] = c.Module
	}

	// Rule 1: code-without-matrix.
	for _, c := range sortedCoverage(code) {
		if _, inMatrix := byMatrix[c.SiteClass]; !inMatrix {
			msgs = append(msgs,
				fmt.Sprintf("matrix-audit: %s: module %q emits this site_class "+
					"but matrix.yaml does not list it (code-without-matrix)",
					c.SiteClass, c.Module))
		}
	}

	// Rules 2 and 3 + module-name mismatch: walk matrix in deterministic
	// order so the report is reproducible.
	for _, sc := range sortedSiteClasses(matrix) {
		info := byMatrix[sc]
		codeModule, inCode := byCode[sc]

		switch info.Status {
		case "implemented", "tested":
			if !inCode {
				msgs = append(msgs,
					fmt.Sprintf("matrix-audit: %s: matrix.yaml says %s "+
						"but no module emits it (matrix-lying)",
						sc, info.Status))
				continue
			}
			if codeModule != info.Module {
				msgs = append(msgs,
					fmt.Sprintf("matrix-audit: %s: matrix.yaml says module %q "+
						"but code says module %q (module-name-mismatch)",
						sc, info.Module, codeModule))
			}
		case "planned":
			if inCode {
				msgs = append(msgs,
					fmt.Sprintf("matrix-audit: %s: matrix.yaml says planned "+
						"but module %q already emits it "+
						"(planned-with-code: flip status to wip or implemented)",
						sc, codeModule))
			}
		case "wip":
			// wip MAY or MAY NOT have code emitting it; that is the
			// definition of in-progress. Module-name mismatch is still
			// worth flagging if the code IS emitting it.
			if inCode && codeModule != info.Module {
				msgs = append(msgs,
					fmt.Sprintf("matrix-audit: %s: matrix.yaml says module %q "+
						"but code says module %q (module-name-mismatch)",
						sc, info.Module, codeModule))
			}
		}
	}

	return msgs
}

// matrixSummary aggregates status counts for the happy-path one-liner.
type matrixSummary struct {
	implemented int
	tested      int
	wip         int
	planned     int
}

// summarize counts entries by status. Unknown statuses are ignored
// here because audit already reports them as drift; summarize is for
// the human-readable summary printed when audit returned no messages.
func summarize(matrix []matrixEntry) matrixSummary {
	var s matrixSummary
	for _, e := range matrix {
		switch e.Status {
		case "implemented":
			s.implemented++
		case "tested":
			s.tested++
		case "wip":
			s.wip++
		case "planned":
			s.planned++
		}
	}
	return s
}

// sortedCoverage returns code coverage sorted by (site_class, module)
// for stable reporting.
func sortedCoverage(code []coverage) []coverage {
	out := make([]coverage, len(code))
	copy(out, code)
	sort.Slice(out, func(i, j int) bool {
		if out[i].SiteClass != out[j].SiteClass {
			return out[i].SiteClass < out[j].SiteClass
		}
		return out[i].Module < out[j].Module
	})
	return out
}

// sortedSiteClasses returns the matrix entries' site_class values in
// alphabetical order with duplicates folded out (the dup is reported
// elsewhere; we just want one pass per site_class here).
func sortedSiteClasses(matrix []matrixEntry) []string {
	seen := make(map[string]struct{}, len(matrix))
	out := make([]string, 0, len(matrix))
	for _, e := range matrix {
		if _, ok := seen[e.SiteClass]; ok {
			continue
		}
		seen[e.SiteClass] = struct{}{}
		out = append(out, e.SiteClass)
	}
	sort.Strings(out)
	return out
}
