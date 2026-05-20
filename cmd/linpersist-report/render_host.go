// HTML renderer for the per-host dossier.
//
// Sibling of render.go (which produces the fleet HTML report). The
// two renderers share assets/style.css so the visual idiom (pills,
// tables, dark/light theme) stays consistent. The dossier template
// does NOT load assets/ui.js: there is nothing to navigate (single
// view, no tabs) and the tables are small enough that sort/filter
// would add no value the analyst can't get from Ctrl-F.

package main

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
)

//go:embed host_dossier.tmpl
var hostTmplBlob string

// pctInt is a template helper that computes a percentage with integer
// truncation, mirroring the text renderer's behavior. Returns 0 when
// total <= 0 to avoid divide-by-zero in the template.
func pctInt(part, total int) int {
	if total <= 0 {
		return 0
	}
	return part * 100 / total
}

// renderHost writes the per-host dossier as a self-contained HTML
// document to out. Shares cssBlob with render() so a single edit to
// assets/style.css propagates to both views.
func renderHost(out io.Writer, dossier *HostDossier, title string) error {
	funcs := template.FuncMap{
		"commaInt":     commaInt,
		"signalIsWarn": signalIsWarn,
		"countGaps":    countGaps,
		"pct":          pctInt,
	}
	t, err := template.New("host").Funcs(funcs).Parse(hostTmplBlob)
	if err != nil {
		return fmt.Errorf("parse host template: %w", err)
	}
	data := struct {
		Title   string
		CSS     template.CSS
		Dossier *HostDossier
	}{
		Title:   title,
		CSS:     template.CSS(cssBlob),
		Dossier: dossier,
	}
	return t.Execute(out, data)
}
