// Package actions holds the job handlers and meta RPCs. It is the only package
// that imports both sdkv1 and internal/nuclei; the engine core stays free of
// sdkv1 so it can be tested and swapped independently (build-a-plugin.md §10).
package actions

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"github.com/venapce/nuclei/internal/nuclei"
)

// scannerFor builds a Scanner from the settings a request carries. The engine is
// created per-operation inside the Scanner, so this is cheap and safe to call on
// every request; there is no shared mutable client to pool in v1.
func scannerFor(settings map[string]any) nuclei.Scanner {
	return nuclei.NewFromRaw(settings)
}

// buildFilter maps a decoded action input to the engine Filter. Empty fields are
// dropped so an empty form means "no constraint on that axis".
func buildFilter(in filterInput) nuclei.Filter {
	f := nuclei.Filter{
		Profile:         strings.TrimSpace(in.Profile),
		Severity:        clean(in.Severity),
		ProtocolTypes:   clean(in.ProtocolTypes),
		Tags:            clean(in.Tags),
		ExcludeTags:     clean(in.ExcludeTags),
		Authors:         clean(in.Authors),
		TemplateIDs:     clean(in.TemplateIDs),
		ExcludeIDs:      clean(in.ExcludeIDs),
		CustomTemplates: clean(in.CustomTemplates),
	}
	if c := strings.TrimSpace(in.TemplateCondition); c != "" {
		f.TemplateCondition = []string{c}
	}
	return f
}

// filterInput is the subset of every action's form that selects templates.
type filterInput struct {
	Profile           string   `json:"profile"`
	Severity          []string `json:"severity"`
	ProtocolTypes     []string `json:"protocolTypes"`
	Tags              []string `json:"tags"`
	ExcludeTags       []string `json:"excludeTags"`
	Authors           []string `json:"authors"`
	TemplateIDs       []string `json:"templateIds"`
	ExcludeIDs        []string `json:"excludeIds"`
	TemplateCondition string   `json:"templateCondition"`
	CustomTemplates   []string `json:"customTemplates"`
}

// isEmpty reports whether a filter selects nothing in particular — i.e. it would
// run the whole catalog. That is gated behind an explicit confirmation.
func (f filterInput) isEmpty() bool {
	return strings.TrimSpace(f.Profile) == "" &&
		len(clean(f.Severity)) == 0 &&
		len(clean(f.ProtocolTypes)) == 0 &&
		len(clean(f.Tags)) == 0 &&
		len(clean(f.Authors)) == 0 &&
		len(clean(f.TemplateIDs)) == 0 &&
		strings.TrimSpace(f.TemplateCondition) == ""
}

// clean trims and drops empty entries.
func clean(ss []string) []string {
	var out []string
	for _, s := range ss {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// decodeMeta decodes the flat body a form button posts, falling back to the
// {body:…} envelope other callers use (dependent-fields.md §2). CastRequestTo is
// wrong here — it would yield a zero struct with no error.
func decodeMeta[T any](data []byte) T {
	var out T
	if len(bytes.TrimSpace(data)) == 0 {
		return out
	}
	var envelope struct {
		Body json.RawMessage `json:"body"`
	}
	if json.Unmarshal(data, &envelope) == nil && len(envelope.Body) > 0 {
		if json.Unmarshal(envelope.Body, &out) == nil {
			return out
		}
	}
	_ = json.Unmarshal(data, &out)
	return out
}

// metaSettings pulls the settings map out of a flat meta call.
func metaSettings(data []byte) map[string]any {
	m := decodeMeta[struct {
		Settings map[string]any `json:"settings"`
	}](data)
	return m.Settings
}

// ctxOf returns a background context; a per-job context with cancellation is
// installed by the scan handler itself.
func ctxOf() context.Context { return context.Background() }
