package systemd

import (
	"bytes"
	"sort"
	"strings"
)

// Normalize returns the canonical content of a systemd unit/timer or
// drop-in file. Two inputs that differ only in cosmetic variance
// (comments, blank lines, line continuations, section order, key
// order, ordering of whitespace-separated set-semantic values) produce
// the same canonical output and therefore the same
// content_norm_sha256. See ADR-0007 for the binding decisions.
func Normalize(raw []byte) []byte {
	sections, _ := ParseUnitFile(raw)
	if len(sections) == 0 {
		return nil
	}
	sections = canonicalizeSections(sections)
	var out bytes.Buffer
	out.Grow(len(raw))
	for i, sec := range sections {
		if i > 0 {
			out.WriteByte('\n')
		}
		out.WriteByte('[')
		out.WriteString(sec.Name)
		out.WriteString("]\n")
		emitEntries(&out, sec.Entries)
	}
	return out.Bytes()
}

// canonicalSectionOrder pins the relative order of the well-known
// systemd section types. Sections not listed here sort alphabetically
// after the known ones, by their lowercased name.
var canonicalSectionOrder = []string{
	"unit",
	// type-specific sections; only one of these is expected in a
	// given file, but we list them all so a malformed file with two
	// type sections produces a deterministic order.
	"service",
	"socket",
	"path",
	"mount",
	"automount",
	"swap",
	"target",
	"timer",
	"install",
}

// canonicalSectionName maps a lowercased section name to the
// canonical systemd capitalization. Sections outside this map keep
// their on-disk casing.
var canonicalSectionName = map[string]string{
	"unit":      "Unit",
	"service":   "Service",
	"socket":    "Socket",
	"path":      "Path",
	"mount":     "Mount",
	"automount": "Automount",
	"swap":      "Swap",
	"target":    "Target",
	"timer":     "Timer",
	"install":   "Install",
}

// setSemanticKeys is the set of keys whose value is a
// whitespace-separated set of tokens. Multiple lines accumulate (with
// the empty-value reset idiom clearing the accumulator) and the
// canonical form sorts and deduplicates the final token set into a
// single line. See systemd.unit(5) under "DEPENDENCY KEYS".
var setSemanticKeys = map[string]struct{}{
	"after":                {},
	"before":               {},
	"wants":                {},
	"requires":             {},
	"requisite":            {},
	"bindsto":              {},
	"partof":               {},
	"conflicts":            {},
	"onfailure":            {},
	"onsuccess":            {},
	"propagatesreloadto":   {},
	"reloadpropagatedfrom": {},
	"joinsnamespaceof":     {},
	"also":                 {},
	"wantedby":             {},
	"requiredby":           {},
	"upholds":              {},
	"upheldby":             {},
}

// execFamilyKeys is the set of keys whose multi-line entries preserve
// source order in the canonical form (the order is semantically
// significant: Pre runs before Start runs before Post).
var execFamilyKeys = map[string]struct{}{
	"execstart":     {},
	"execstartpre":  {},
	"execstartpost": {},
	"execstop":      {},
	"execstoppost":  {},
	"execreload":    {},
	"execcondition": {},
}

// canonicalKeyCase provides the systemd-conventional capitalization
// for the keys we explicitly canonicalize. Limited to ~50 entries to
// keep the maintenance surface small; keys outside this map are
// emitted with the capitalization that appeared on disk.
var canonicalKeyCase = map[string]string{
	"description":          "Description",
	"documentation":        "Documentation",
	"after":                "After",
	"before":               "Before",
	"wants":                "Wants",
	"requires":             "Requires",
	"requisite":            "Requisite",
	"bindsto":              "BindsTo",
	"partof":               "PartOf",
	"conflicts":            "Conflicts",
	"onfailure":            "OnFailure",
	"onsuccess":            "OnSuccess",
	"propagatesreloadto":   "PropagatesReloadTo",
	"reloadpropagatedfrom": "ReloadPropagatedFrom",
	"joinsnamespaceof":     "JoinsNamespaceOf",
	"upholds":              "Upholds",
	"upheldby":             "UpheldBy",
	"also":                 "Also",
	"wantedby":             "WantedBy",
	"requiredby":           "RequiredBy",
	"alias":                "Alias",
	"defaultinstance":      "DefaultInstance",
	"type":                 "Type",
	"user":                 "User",
	"group":                "Group",
	"execstart":            "ExecStart",
	"execstartpre":         "ExecStartPre",
	"execstartpost":        "ExecStartPost",
	"execstop":             "ExecStop",
	"execstoppost":         "ExecStopPost",
	"execreload":           "ExecReload",
	"execcondition":        "ExecCondition",
	"environment":          "Environment",
	"environmentfile":      "EnvironmentFile",
	"workingdirectory":     "WorkingDirectory",
	"rootdirectory":        "RootDirectory",
	"standardinput":        "StandardInput",
	"standardoutput":       "StandardOutput",
	"standarderror":        "StandardError",
	"restart":              "Restart",
	"restartsec":           "RestartSec",
	"remainafterexit":      "RemainAfterExit",
	"killmode":             "KillMode",
	"killsignal":           "KillSignal",
	"timeoutstartsec":      "TimeoutStartSec",
	"timeoutstopsec":       "TimeoutStopSec",
	"oncalendar":           "OnCalendar",
	"onbootsec":            "OnBootSec",
	"onunitactivesec":      "OnUnitActiveSec",
	"onunitinactivesec":    "OnUnitInactiveSec",
	"onstartupsec":         "OnStartupSec",
	"onactivesec":          "OnActiveSec",
	"unit":                 "Unit",
	"accuracysec":          "AccuracySec",
	"randomizeddelaysec":   "RandomizedDelaySec",
	"persistent":           "Persistent",
	"wakesystem":           "WakeSystem",
}

func canonicalKey(k string) string {
	lc := strings.ToLower(k)
	if v, ok := canonicalKeyCase[lc]; ok {
		return v
	}
	return k
}

func canonicalSection(name string) string {
	lc := strings.ToLower(name)
	if v, ok := canonicalSectionName[lc]; ok {
		return v
	}
	return name
}

func canonicalizeSections(in []Section) []Section {
	out := make([]Section, 0, len(in))
	for _, s := range in {
		out = append(out, Section{
			Name:    canonicalSection(s.Name),
			Entries: s.Entries,
		})
	}
	sectionRank := func(name string) (rank int, isKnown bool) {
		lc := strings.ToLower(name)
		for i, k := range canonicalSectionOrder {
			if k == lc {
				return i, true
			}
		}
		return len(canonicalSectionOrder), false
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, ki := sectionRank(out[i].Name)
		rj, kj := sectionRank(out[j].Name)
		switch {
		case ki && kj:
			return ri < rj
		case ki && !kj:
			return true
		case !ki && kj:
			return false
		default:
			return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
		}
	})
	return out
}

// emitEntries writes the canonical key-ordered entries for one section
// to out.
func emitEntries(out *bytes.Buffer, entries []Entry) {
	// Group entries by lowercase key, preserving the first-seen
	// display key for emission.
	type group struct {
		key    string // canonical display
		lcKey  string
		values []string
	}
	groups := make([]group, 0, len(entries))
	idx := make(map[string]int, len(entries))
	for _, e := range entries {
		lc := strings.ToLower(e.Key)
		if i, ok := idx[lc]; ok {
			groups[i].values = append(groups[i].values, e.Value)
			continue
		}
		g := group{
			key:    canonicalKey(e.Key),
			lcKey:  lc,
			values: []string{e.Value},
		}
		idx[lc] = len(groups)
		groups = append(groups, g)
	}
	sort.SliceStable(groups, func(i, j int) bool {
		return groups[i].lcKey < groups[j].lcKey
	})
	for _, g := range groups {
		switch {
		case isSetSemantic(g.lcKey):
			tokens := collapseSetTokens(g.values)
			if len(tokens) == 0 {
				continue
			}
			out.WriteString(g.key)
			out.WriteByte('=')
			out.WriteString(strings.Join(tokens, " "))
			out.WriteByte('\n')
		case isExecFamily(g.lcKey):
			// Preserve source order; honor empty-value reset.
			values := applyEmptyReset(g.values)
			for _, v := range values {
				out.WriteString(g.key)
				out.WriteByte('=')
				out.WriteString(v)
				out.WriteByte('\n')
			}
		default:
			// Preserve source order verbatim; do not deduplicate.
			for _, v := range g.values {
				out.WriteString(g.key)
				out.WriteByte('=')
				out.WriteString(v)
				out.WriteByte('\n')
			}
		}
	}
}

func isSetSemantic(lcKey string) bool {
	_, ok := setSemanticKeys[lcKey]
	return ok
}

func isExecFamily(lcKey string) bool {
	_, ok := execFamilyKeys[lcKey]
	return ok
}

// collapseSetTokens implements the canonical form for set-semantic
// dependency keys: walk values in source order, honor the empty-value
// reset idiom (an empty value clears the accumulator), split each
// non-empty value on whitespace, then sort+dedupe the final set.
func collapseSetTokens(values []string) []string {
	var acc []string
	for _, v := range values {
		if strings.TrimSpace(v) == "" {
			acc = acc[:0]
			continue
		}
		for _, t := range strings.Fields(v) {
			acc = append(acc, t)
		}
	}
	if len(acc) == 0 {
		return nil
	}
	sort.Strings(acc)
	out := acc[:0]
	var last string
	for i, t := range acc {
		if i == 0 || t != last {
			out = append(out, t)
			last = t
		}
	}
	return out
}

// applyEmptyReset implements the empty-value reset idiom for
// list-ordered keys (Exec* family). Walks the values in source order;
// an empty value clears the accumulator. Returns the surviving values
// in source order.
func applyEmptyReset(values []string) []string {
	var acc []string
	for _, v := range values {
		if strings.TrimSpace(v) == "" {
			acc = acc[:0]
			continue
		}
		acc = append(acc, v)
	}
	return acc
}
