package main

import (
	"fmt"
	"html/template"
	"io"
)

// diffHTMLTmpl is the standalone HTML template for diff output.
// Kept separate from report.tmpl so the diff mode does not depend
// on the Q1..Q11 template machinery; the trade-off is some style
// duplication, which we accept because diff is a leaner view by
// design.
//
// The CSS is inlined and self-contained -- mirrors the
// "single-file deliverable" principle of report.tmpl.
const diffHTMLTmpl = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<title>{{.Title}}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         max-width: 1100px; margin: 2em auto; padding: 0 1em;
         color: #222; line-height: 1.5; }
  h1 { border-bottom: 2px solid #333; padding-bottom: 0.3em; }
  h2 { margin-top: 2em; border-bottom: 1px solid #ccc; padding-bottom: 0.2em; }
  .summary { background: #f6f8fa; padding: 1em; border-radius: 6px;
             font-family: ui-monospace, monospace; font-size: 0.95em; }
  table { border-collapse: collapse; width: 100%; margin-top: 1em; font-size: 0.92em; }
  th, td { padding: 0.45em 0.7em; text-align: left;
           border-bottom: 1px solid #eee; }
  th { background: #f6f8fa; }
  td.mark { width: 1.5em; text-align: center; font-weight: bold;
            font-family: ui-monospace, monospace; }
  td.locus { font-family: ui-monospace, monospace; font-size: 0.88em; }
  .mark-add    { color: #1a7f37; }
  .mark-remove { color: #cf222e; }
  .mark-delta  { color: #9a6700; }
  .empty { color: #6e7781; font-style: italic; padding: 1em 0; }
  .hash { font-family: ui-monospace, monospace; font-size: 0.85em; color: #57606a; }
</style></head><body>

<h1>{{.Title}}</h1>

<div class="summary">
  Records: prev={{.PrevTotal}} &nbsp; curr={{.CurrTotal}} &nbsp;
    delta={{.DeltaSigned}}<br>
  Per-record diff: <span class="mark-add">+{{len .Added}}</span> added &nbsp;
    <span class="mark-remove">-{{len .Removed}}</span> removed &nbsp;
    <span class="mark-delta">{{len .Changed}}</span> changed &nbsp;
    {{.UnchangedCount}} unchanged<br>
  Host churn: <span class="mark-add">+{{len .HostsAppeared}}</span> appeared &nbsp;
    <span class="mark-remove">-{{len .HostsDisappeared}}</span> disappeared
</div>

{{if .HostsDisappeared}}
<h2>Hosts disappeared ({{len .HostsDisappeared}})</h2>
<p>Hosts present in prev but absent from curr. Per-record entries
are suppressed; per ADR-0015 this surfaces as a host-level row.</p>
<table>
  <tr><th>mark</th><th>host</th><th>records in prev</th></tr>
  {{range .HostsDisappeared}}
  <tr><td class="mark mark-remove">-</td>
      <td>{{.HostSample}}</td>
      <td>{{.RecordCount}}</td></tr>
  {{end}}
</table>
{{end}}

{{if .HostsAppeared}}
<h2>Hosts appeared ({{len .HostsAppeared}})</h2>
<p>Hosts present in curr but absent from prev. Per-record entries
are suppressed; per ADR-0015 this surfaces as a host-level row.</p>
<table>
  <tr><th>mark</th><th>host</th><th>records in curr</th></tr>
  {{range .HostsAppeared}}
  <tr><td class="mark mark-add">+</td>
      <td>{{.HostSample}}</td>
      <td>{{.RecordCount}}</td></tr>
  {{end}}
</table>
{{end}}

{{if .Added}}
<h2>Added records ({{len .Added}})</h2>
<p>Records present in curr that have no identity match in prev.</p>
<table>
  <tr><th>mark</th><th>host</th><th>module</th><th>site_class</th><th>locus</th></tr>
  {{range .Added}}
  <tr><td class="mark mark-add">+</td>
      <td>{{.Host}}</td>
      <td>{{.Module}}</td>
      <td>{{.SiteClass}}</td>
      <td class="locus">{{.Locus}}</td></tr>
  {{end}}
</table>
{{end}}

{{if .Removed}}
<h2>Removed records ({{len .Removed}})</h2>
<p>Records present in prev that have no identity match in curr.</p>
<table>
  <tr><th>mark</th><th>host</th><th>module</th><th>site_class</th><th>locus</th></tr>
  {{range .Removed}}
  <tr><td class="mark mark-remove">-</td>
      <td>{{.Host}}</td>
      <td>{{.Module}}</td>
      <td>{{.SiteClass}}</td>
      <td class="locus">{{.Locus}}</td></tr>
  {{end}}
</table>
{{end}}

{{if .Changed}}
<h2>Changed records ({{len .Changed}})</h2>
<p>Records with the same (host, module, site_class, locus) tuple
but different content_norm_sha256 between prev and curr.</p>
<table>
  <tr><th>mark</th><th>host</th><th>module</th><th>site_class</th><th>locus</th><th>prev / curr hash</th></tr>
  {{range .Changed}}
  <tr><td class="mark mark-delta">D</td>
      <td>{{.Host}}</td>
      <td>{{.Module}}</td>
      <td>{{.SiteClass}}</td>
      <td class="locus">{{.Locus}}</td>
      <td class="hash">{{.PrevHash}} &rarr; {{.CurrHash}}</td></tr>
  {{end}}
</table>
{{end}}

{{if .Empty}}
<p class="empty">No changes between prev and curr.</p>
{{end}}

</body></html>
`

// diffHTMLData is the projection of DiffSet into a struct the
// HTML template can range over without exposing core.Record's
// noisy fields.
type diffHTMLData struct {
	Title       string
	PrevTotal   int
	CurrTotal   int
	DeltaSigned string

	UnchangedCount int

	Added            []diffRowHTML
	Removed          []diffRowHTML
	Changed          []diffChangedHTML
	HostsAppeared    []HostChange
	HostsDisappeared []HostChange
	Empty            bool
}

type diffRowHTML struct {
	Host      string
	Module    string
	SiteClass string
	Locus     string
}

type diffChangedHTML struct {
	Host      string
	Module    string
	SiteClass string
	Locus     string
	PrevHash  string
	CurrHash  string
}

// renderDiffHTML writes a self-contained HTML report describing a
// DiffSet. The CSS is inlined; no external assets.
func renderDiffHTML(w io.Writer, ds DiffSet, title string) error {
	added := make([]diffRowHTML, 0, len(ds.Added))
	for _, r := range ds.Added {
		added = append(added, diffRowHTML{
			Host: hostKey(r), Module: r.Module, SiteClass: r.SiteClass, Locus: r.Locus,
		})
	}
	removed := make([]diffRowHTML, 0, len(ds.Removed))
	for _, r := range ds.Removed {
		removed = append(removed, diffRowHTML{
			Host: hostKey(r), Module: r.Module, SiteClass: r.SiteClass, Locus: r.Locus,
		})
	}
	changed := make([]diffChangedHTML, 0, len(ds.Changed))
	for _, p := range ds.Changed {
		changed = append(changed, diffChangedHTML{
			Host:      hostKey(p.Curr),
			Module:    p.Curr.Module,
			SiteClass: p.Curr.SiteClass,
			Locus:     p.Curr.Locus,
			PrevHash:  shortHash(p.Prev.ContentNormSHA256),
			CurrHash:  shortHash(p.Curr.ContentNormSHA256),
		})
	}

	data := diffHTMLData{
		Title:            title,
		PrevTotal:        ds.PrevTotal,
		CurrTotal:        ds.CurrTotal,
		DeltaSigned:      fmt.Sprintf("%+d", ds.CurrTotal-ds.PrevTotal),
		UnchangedCount:   ds.UnchangedCount,
		Added:            added,
		Removed:          removed,
		Changed:          changed,
		HostsAppeared:    ds.HostsAppeared,
		HostsDisappeared: ds.HostsDisappeared,
		Empty: len(added) == 0 && len(removed) == 0 && len(changed) == 0 &&
			len(ds.HostsAppeared) == 0 && len(ds.HostsDisappeared) == 0,
	}

	tmpl, err := template.New("diff").Parse(diffHTMLTmpl)
	if err != nil {
		return fmt.Errorf("parse diff template: %w", err)
	}
	return tmpl.Execute(w, data)
}
