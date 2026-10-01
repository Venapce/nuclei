package nuclei

import (
	"strconv"
	"strings"
)

// Config is the resolved connection: the deployment policy an operator sets in a
// settings profile. Note what is NOT here — no scan target, no template filter,
// and (for the main path) no service credential. Nuclei needs no credential to
// scan; the profile instead holds the safety gates and the load/politeness knobs
// that are an operator decision, never a canvas-node one (feasibility.md §5).
type Config struct {
	TemplatesDir     string
	CustomTemplates  []string // extra template dirs/urls (private catalog)
	TrustedDomains   []string // for remote template urls
	AutoUpdate       bool

	RateLimit   int
	Concurrency int
	BulkSize    int
	Timeout     int
	Retries     int
	MaxHostErr  int

	Proxy            []string
	InteractshServer string
	InteractshToken  string
	CustomHeaders    []string

	// Safety gates. Every one defaults to the safe value; an operator opts in.
	AllowIntrusive            bool // run dos/fuzz/bruteforce/local (IncludeTags over .nuclei-ignore)
	AllowCodeTemplates        bool // run code/self-contained templates (shell on this host)
	AllowLocalFileAccess      bool // -lfa
	RestrictLocalNetworkAccess bool // -lna; DEFAULT TRUE — see parseSettings
	AllowDAST                 bool // run dast/fuzzing templates
	AllowHeadless             bool // run headless templates (needs Chrome)
	SignedOnly                bool // refuse unsigned/tampered templates
}

// parseSettings reads the raw settings map leniently — profiles are often typed
// by hand as key/value rows, so keys are matched case/space/dash/underscore
// insensitively with the obvious synonyms (build-a-plugin.md §7).
func parseSettings(raw map[string]any) Config {
	g := getter(raw)
	c := Config{
		TemplatesDir:     g.str("templatesDir", "templates_dir", "templatesDirectory", "dir"),
		CustomTemplates:  g.list("customTemplates", "custom_templates", "customTemplateSources", "templateSources"),
		TrustedDomains:   g.list("trustedDomains", "trusted_domains"),
		AutoUpdate:       g.boolDefault(false, "autoUpdate", "auto_update"),
		RateLimit:        g.intDefault(150, "rateLimit", "rate_limit", "rl"),
		Concurrency:      g.intDefault(25, "concurrency", "c"),
		BulkSize:         g.intDefault(25, "bulkSize", "bulk_size", "bs"),
		Timeout:          g.intDefault(10, "timeout"),
		Retries:          g.intDefault(1, "retries"),
		MaxHostErr:       g.intDefault(30, "maxHostError", "max_host_error", "mhe"),
		Proxy:            g.list("proxy"),
		InteractshServer: g.str("interactshServer", "interactsh_server"),
		InteractshToken:  g.str("interactshToken", "interactsh_token"),
		CustomHeaders:    g.list("customHeaders", "custom_headers", "headers"),

		AllowIntrusive:       g.boolDefault(false, "allowIntrusive", "allow_intrusive", "intrusive"),
		AllowCodeTemplates:   g.boolDefault(false, "allowCodeTemplates", "allow_code_templates", "code"),
		AllowLocalFileAccess: g.boolDefault(false, "allowLocalFileAccess", "allow_local_file_access", "lfa"),
		AllowDAST:            g.boolDefault(false, "allowDast", "allow_dast", "dast"),
		AllowHeadless:        g.boolDefault(false, "allowHeadless", "allow_headless", "headless"),
		SignedOnly:           g.boolDefault(false, "signedOnly", "signed_only"),
	}
	// The one gate that is dangerous OFF: SSRF protection is ON unless an
	// operator explicitly disables it. Absent key => restricted.
	c.RestrictLocalNetworkAccess = g.boolDefault(true, "restrictLocalNetworkAccess", "restrict_local_network_access", "lna")
	return c
}

// getter does the lenient lookup.
type getter map[string]any

func normKey(s string) string {
	s = strings.ToLower(s)
	for _, ch := range []string{" ", "-", "_"} {
		s = strings.ReplaceAll(s, ch, "")
	}
	return s
}

func (g getter) find(keys ...string) (any, bool) {
	want := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		want[normKey(k)] = struct{}{}
	}
	for k, v := range g {
		if _, ok := want[normKey(k)]; ok {
			return v, true
		}
	}
	return nil, false
}

func (g getter) str(keys ...string) string {
	if v, ok := g.find(keys...); ok {
		if s, ok := v.(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func (g getter) list(keys ...string) []string {
	v, ok := g.find(keys...)
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	case string:
		return splitCSV(t)
	}
	return nil
}

func (g getter) intDefault(def int, keys ...string) int {
	v, ok := g.find(keys...)
	if !ok {
		return def
	}
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
			return n
		}
	}
	return def
}

func (g getter) boolDefault(def bool, keys ...string) bool {
	v, ok := g.find(keys...)
	if !ok {
		return def
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		s := strings.ToLower(strings.TrimSpace(t))
		return s == "true" || s == "yes" || s == "1" || s == "on"
	case float64:
		return t != 0
	}
	return def
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// NewFromRaw parses a raw settings map and returns a Scanner for it.
func NewFromRaw(raw map[string]any) *LibScanner { return New(parseSettings(raw)) }
