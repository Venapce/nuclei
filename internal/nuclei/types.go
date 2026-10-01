// Package nuclei is the transport-free core of the NUCLEI plugin: it wraps the
// projectdiscovery/nuclei engine and template catalog behind one Scanner
// interface, and imports nothing from the inflow SDK. That boundary is
// deliberate (build-a-plugin.md §10) — it keeps the engine testable without NATS
// and lets a future subprocess-isolated backend replace the embedded library
// without touching any action handler.
package nuclei

import "context"

// Filter is the whole of how a scan or a preview selects templates. It mirrors
// nuclei's own filter flags one-for-one; there is no per-template configuration,
// because nuclei has none. A template that needs an external value reads it from
// Vars (nuclei's global -var bag), never from a generated form.
type Filter struct {
	Profile           string   // a named profile from the templates repo (profiles/*.yml)
	Severity          []string // info, low, medium, high, critical
	ExcludeSeverity   []string
	ProtocolTypes     []string // http, dns, network, ssl, file, javascript, headless, code
	Tags              []string
	ExcludeTags       []string
	IncludeTags       []string // force-run tags the .nuclei-ignore deny-list excludes
	Authors           []string
	TemplateIDs       []string // exact ids or wildcards
	ExcludeIDs        []string
	TemplateCondition []string // DSL, e.g. contains(tags,'cve') && cvss_score >= 9.0
	CustomTemplates   []string // inline YAML written to a temp dir for this run
}

// Meta is the lightweight view of a template used by preview and search — never
// the template body.
type Meta struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Severity string   `json:"severity"`
	Protocol string   `json:"protocol"`
	Tags     []string `json:"tags"`
	Authors  []string `json:"authors,omitempty"`
}

// Selection is the answer to "what would this filter run?" — resolved without
// scanning anything.
type Selection struct {
	Count      int            `json:"count"`
	BySeverity map[string]int `json:"bySeverity"`
	Sample     []Meta         `json:"sample"`
}

// Finding is one committed result, projected from nuclei's output.ResultEvent to
// the fields a workflow actually branches on. RequestDump/ResponseDump are
// populated only when the caller opts in, because they dominate payload size.
type Finding struct {
	TemplateID   string   `json:"templateId"`
	Name         string   `json:"name"`
	Severity     string   `json:"severity"`
	Protocol     string   `json:"type"`
	Host         string   `json:"host,omitempty"`
	Port         string   `json:"port,omitempty"`
	URL          string   `json:"url,omitempty"`
	MatchedAt    string   `json:"matchedAt,omitempty"`
	IP           string   `json:"ip,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	CVEID        []string `json:"cveId,omitempty"`
	CWEID        []string `json:"cweId,omitempty"`
	CVSSScore    float64  `json:"cvssScore,omitempty"`
	EPSSScore    float64  `json:"epssScore,omitempty"`
	Description  string   `json:"description,omitempty"`
	Remediation  string   `json:"remediation,omitempty"`
	Reference    []string `json:"reference,omitempty"`
	Extracted    []string `json:"extractedResults,omitempty"`
	CURLCommand  string   `json:"curlCommand,omitempty"`
	RequestDump  string   `json:"request,omitempty"`
	ResponseDump string   `json:"response,omitempty"`
	Timestamp    string   `json:"timestamp,omitempty"`
}

// ScanRequest is one run.
type ScanRequest struct {
	Targets            []string
	Filter             Filter
	Vars               []string // key=value, nuclei's -var
	MaxFindings        int      // 0 = unlimited (guard-railed by the handler, not here)
	IncludeReqResp     bool
	ProbeNonHTTP       bool
}

// Health is what the connection test reports back.
type Health struct {
	OK               bool   `json:"ok"`
	EngineVersion    string `json:"engineVersion"`
	TemplatesDir     string `json:"templatesDir"`
	TemplatesVersion string `json:"templatesVersion"`
	TemplateCount    int    `json:"templateCount"`
	CodeTemplates    bool   `json:"codeTemplatesEnabled"`
	Intrusive        bool   `json:"intrusiveEnabled"`
	Message          string `json:"message,omitempty"`
}

// UpdateResult is the outcome of pulling the latest template release.
type UpdateResult struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Changed bool   `json:"changed"`
}

// Validation is the outcome of parsing one custom template.
type Validation struct {
	Valid    bool     `json:"valid"`
	ID       string   `json:"id,omitempty"`
	Name     string   `json:"name,omitempty"`
	Severity string   `json:"severity,omitempty"`
	Errors   []string `json:"errors,omitempty"`
}

// Scanner is the entire engine contract the action handlers depend on. The
// embedded-library implementation lives in lib.go; a CLI-subprocess backend
// could satisfy the same interface (feasibility.md §4).
type Scanner interface {
	// Health tests the connection: templates present, versions, gates.
	Health(ctx context.Context) Health
	// Select resolves a filter to counts + a sample, without scanning.
	Select(ctx context.Context, f Filter) (*Selection, error)
	// Search substring-matches a query across template id/name/tags.
	Search(ctx context.Context, query string, limit int) ([]Meta, error)
	// Scan runs templates against targets, invoking onFinding as each lands.
	Scan(ctx context.Context, req ScanRequest, onFinding func(Finding)) (int, error)
	// UpdateTemplates pulls the latest released catalog.
	UpdateTemplates(ctx context.Context) (*UpdateResult, error)
	// Validate parses one custom template body.
	Validate(ctx context.Context, body []byte) *Validation
	// Profiles lists the named profiles shipped with the catalog.
	Profiles(ctx context.Context) ([]string, error)
	// Tags lists known tags, most-used first (best-effort from catalog stats).
	Tags(ctx context.Context, limit int) ([]TagCount, error)
	// Close releases engine resources.
	Close()
}

// TagCount is one tag and how many templates carry it.
type TagCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}
