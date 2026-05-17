package main

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"strconv"
	"strings"
)

//go:embed assets/style.css
var cssBlob string

//go:embed assets/ui.js
var jsBlob string

//go:embed report.tmpl
var tmplBlob string

// warningSignals are signals the analyst should see at a glance as
// "interesting", not necessarily verdicts. The pill rendering switches
// from accent (informational) to warn (red-orange) for these.
var warningSignals = map[string]struct{}{
	"exec_target_orphan":            {},
	"interpreter_in_tmp":            {},
	"world_writable":                {},
	"non_package_path":              {},
	"systemd_external_unit_symlink": {},
	"systemd_install_alias_external": {},
	"sysv_external_init_symlink":    {},
	"udev_run_directive":            {},
	"kmod_install_directive":        {},
	"ssh_forced_command":            {},
	"sudoers_nopasswd":              {},
	"sudoers_all_commands":          {},
	"sshd_permit_root_login_yes":    {},
	"passwd_uid_zero":               {},
	"passwd_no_password":            {},
	"ld_preload_set":                {},
	"shell_indirect":                {},
	"non_root_owner":                {},
}

// commaInt formats an integer with thousands separators.
func commaInt(n int) string {
	s := strconv.Itoa(n)
	neg := false
	if strings.HasPrefix(s, "-") {
		neg = true
		s = s[1:]
	}
	var b strings.Builder
	for i, ch := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(ch)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

// histMax returns the largest Count across buckets (used to scale bar
// heights). Returns 1 instead of 0 to avoid divide-by-zero.
func histMax(buckets []HistogramBucket) int {
	m := 1
	for _, b := range buckets {
		if b.Count > m {
			m = b.Count
		}
	}
	return m
}

// histPct converts a bucket count into a pixel height in the 0..160
// range. Empty buckets still render a 2-pixel ghost so the bar is
// visible.
func histPct(count, max int) int {
	if max <= 0 {
		return 2
	}
	const maxPx = 160
	const minPx = 2
	h := count * maxPx / max
	if h < minPx {
		return minPx
	}
	return h
}

// signalMax returns the largest Hosts value in a NamedCount slice. As
// before, never returns 0.
func signalMax(rows []NamedCount) int {
	m := 1
	for _, r := range rows {
		if r.Hosts > m {
			m = r.Hosts
		}
	}
	return m
}

// signalPct converts a host count into a percentage width for the
// signal bar.
func signalPct(hosts, max int) int {
	if max <= 0 {
		return 0
	}
	p := hosts * 100 / max
	if p < 1 {
		return 1
	}
	return p
}

func signalIsWarn(name string) bool {
	_, ok := warningSignals[name]
	return ok
}

// render writes the full HTML report to out.
func render(out io.Writer, report *Report, title string) error {
	funcs := template.FuncMap{
		"commaInt":     commaInt,
		"histMax":      histMax,
		"histPct":      histPct,
		"signalMax":    signalMax,
		"signalPct":    signalPct,
		"signalIsWarn": signalIsWarn,
	}
	t, err := template.New("report").Funcs(funcs).Parse(tmplBlob)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}
	data := struct {
		Title  string
		CSS    template.CSS
		JS     template.JS
		Report *Report
	}{
		Title:  title,
		CSS:    template.CSS(cssBlob),
		JS:     template.JS(jsBlob),
		Report: report,
	}
	return t.Execute(out, data)
}
