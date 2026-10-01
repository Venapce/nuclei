// Package forms holds the JSON Schema / UI Schema for the settings profile and
// every action, generated with formkit so schema and UI cannot drift. There is
// exactly one form per action, and no form is generated per template — nuclei
// selects templates by filter, not by dialog (feasibility.md §3).
package forms

import (
	"github.com/Inflowenger/go-plugin-sdk/formkit"
	"github.com/Inflowenger/go-plugin-sdk/sdkv1"
)

// Method names, referenced by both the forms (for lookup buttons) and main.go
// (for registration). Renaming one breaks every saved node using it.
const (
	ScanRun          = "nuclei.scan.run"
	TemplatesSelect  = "nuclei.templates.select"
	TemplatesSearch  = "nuclei.templates.search"
	TemplatesUpdate  = "nuclei.templates.update"
	TemplateValidate = "nuclei.template.validate"
	WorkflowRun      = "nuclei.workflow.run"

	MetaPing     = "nuclei.meta.ping"
	MetaProfiles = "nuclei.meta.profiles"
	MetaTags     = "nuclei.meta.tags"
	MetaSearch   = "nuclei.meta.templates.search"
)

var severities = []string{"info", "low", "medium", "high", "critical"}

// Protocol type names are nuclei's filter values, not directory names: the
// network protocol filters as "tcp" (the "network/" folder notwithstanding).
var protocols = []string{"http", "tcp", "dns", "ssl", "file", "javascript", "headless", "code", "websocket", "whois"}

// Settings is the connection form: deployment policy and the safety gates. It
// holds no scan target and no template filter — those belong to the actions —
// and, for the main path, no service credential.
func Settings() *sdkv1.Settings {
	f := formkit.New("Nuclei Connection").
		Describe("Deployment policy for this Nuclei plugin. Templates are selected per-scan, not here. The safety gates below default to the safe setting; open them deliberately.").
		SubmitTo(MetaPing).
		Group("Catalog",
			formkit.Text("templatesDir", "Templates directory").
				Describe("Where nuclei-templates live. Leave empty to use the default and Update Templates."),
			formkit.List("customTemplates", "Custom template sources").
				Describe("Extra template directories or URLs — a private catalog."),
			formkit.Bool("autoUpdate", "Auto-update templates").Default(false),
		).
		Group("Load & politeness",
			formkit.Integer("rateLimit", "Rate limit (req/s)").Default(150),
			formkit.Integer("concurrency", "Template concurrency").Default(25),
			formkit.Integer("bulkSize", "Hosts in parallel per template").Default(25),
			formkit.Integer("timeout", "Timeout (s)").Default(10),
			formkit.Integer("retries", "Retries").Default(1),
			formkit.Integer("maxHostError", "Max errors per host").Default(30),
			formkit.List("proxy", "Proxy (http/socks5)"),
			formkit.List("customHeaders", "Custom headers (header:value)").
				Describe("Sent on every request — e.g. an auth header for authenticated scanning."),
		).
		Group("Safety gates",
			formkit.Bool("restrictLocalNetworkAccess", "Block local/private network").Default(true).
				Describe("SSRF protection. ON by default. Turn OFF only to scan internal hosts you own."),
			formkit.Bool("allowIntrusive", "Allow intrusive templates").Default(false).
				Describe("Run dos/fuzz/bruteforce/local templates that nuclei excludes by default."),
			formkit.Bool("allowCodeTemplates", "Allow code templates").Default(false).
				Describe("Run code/self-contained templates that execute shell ON THIS HOST. Keep off unless you trust the catalog."),
			formkit.Bool("signedOnly", "Signed templates only").Default(false).
				Describe("Refuse unsigned or tampered templates. Recommended when code templates are enabled."),
			formkit.Bool("allowLocalFileAccess", "Allow local file access").Default(false),
			formkit.Bool("allowDast", "Allow DAST/fuzzing templates").Default(false),
			formkit.Bool("allowHeadless", "Allow headless templates").Default(false).
				Describe("Needs a Chrome install on this host."),
		)
	return f.Settings(nil) // SubmitHandler is wired in main.go
}

// FormID is the static tag a lookup button sends so a meta function knows which
// form to rebuild on a form re-render (a browse/search answer replaces the whole
// dialog, so it must be rebuilt from the right base). The key is "fk".
const (
	FormIDScan   = "scan"
	FormIDSelect = "select"
)

// filterFields are the template-selection fields shared by scan.run and
// templates.select. Order matters — profile first (the default path), then the
// finer filters. formID tells the browse/search buttons which form to rebuild.
//
// The browse/search buttons answer by re-rendering: a profile Browse turns the
// profile field into a drop-down of real profiles; Browse tags and Find
// templates turn their target into a multi-select of what the catalog actually
// has. That is the only way to offer options that did not exist at compile time
// (dependent-fields.md) — a static schema cannot, and 13k ids never belonged in
// one.
func filterFields(formID string) []*formkit.Field {
	return []*formkit.Field{
		formkit.Text("profile", "Profile").
			Lookup(MetaProfiles, "Browse").Send("fk", formID).
			Describe("A named bundle from the catalog (e.g. kev, cves, wordpress). Browse to pick one, or leave empty and use the filters below."),
		formkit.Custom("severity", "Severity", map[string]any{
			"type":        "array",
			"uniqueItems": true,
			"items":       map[string]any{"type": "string", "enum": toAny(severities)},
		}).Describe("Only run templates of these severities."),
		formkit.Custom("protocolTypes", "Protocol types", map[string]any{
			"type":        "array",
			"uniqueItems": true,
			"items":       map[string]any{"type": "string", "enum": toAny(protocols)},
		}),
		formkit.List("tags", "Tags").
			Lookup(MetaTags, "Browse tags").Send("fk", formID).
			Describe("Run templates carrying any of these tags. Browse to pick from the catalog's tags."),
		formkit.List("excludeTags", "Exclude tags"),
		formkit.List("authors", "Authors"),
		formkit.Text("templateQuery", "Find templates by keyword").
			Lookup(MetaSearch, "Find").Into("templateIds").Send("fk", formID).
			Describe("Type a keyword and press Find — matching template IDs fill the list below as a multi-select."),
		formkit.List("templateIds", "Template IDs").
			Describe("Exact IDs or wildcards. Use Find above to populate this from the catalog."),
		formkit.List("excludeIds", "Exclude IDs"),
		formkit.Text("templateCondition", "Template condition (DSL)").
			Describe("e.g. contains(tags,'cve') && cvss_score >= 9.0"),
	}
}

// Scan is the form for nuclei.scan.run.
func Scan() sdkv1.FormBuilder {
	f := formkit.New("Run Nuclei Scan").
		Describe("Active vulnerability scan. You are responsible for authorisation to scan these targets.").
		Add(
			formkit.List("targets", "Targets").
				Describe("URLs/hosts to scan. Leave empty to read them from the flow context field below."),
			formkit.Text("targetsPath", "Targets from context (JSON path)").
				Describe("e.g. $.assets[*].url or $this.host. Used when Targets is empty."),
		).
		Group("Template selection", filterFields(FormIDScan)...).
		Group("Run options",
			formkit.List("vars", "Variables (key=value)").
				Describe("Values templates read via {{var}} — nuclei's -var. Applies to the whole run."),
			formkit.Integer("maxFindings", "Max findings").Default(500).
				Describe("Stop after this many findings. 0 = unlimited."),
			formkit.Bool("includeRequestResponse", "Include request/response dumps").Default(false).
				Describe("Adds the full HTTP request and response to each finding (large)."),
			formkit.Bool("probeNonHttp", "Probe non-HTTP targets").Default(false),
			formkit.Bool("confirmFullCatalog", "Confirm unfiltered run").Default(false).
				Describe("Required to run with no profile/filter — a full-catalog scan is heavy."),
		)
	return f.Build()
}

// Select is the form for nuclei.templates.select (preview, no scanning).
func Select() sdkv1.FormBuilder {
	f := formkit.New("Preview Template Selection").
		Describe("Resolve a filter to a count and severity breakdown without scanning.").
		Group("Template selection", filterFields(FormIDSelect)...)
	return f.Build()
}

// Search is the form for nuclei.templates.search as an action (callable mid-flow).
func Search() sdkv1.FormBuilder {
	f := formkit.New("Search Templates").Add(
		formkit.Text("query", "Query").Required().
			Describe("Keyword matched against template id, name and tags."),
		formkit.Integer("limit", "Max results").Default(50),
	)
	return f.Build()
}

// Update is the form for nuclei.templates.update (no inputs).
func Update() sdkv1.FormBuilder {
	f := formkit.New("Update Templates").
		Describe("Pull the latest released nuclei-templates catalog.")
	return f.Build()
}

// Validate is the form for nuclei.template.validate.
func Validate() sdkv1.FormBuilder {
	f := formkit.New("Validate Template").Add(
		formkit.TextArea("template", "Template YAML").Required().
			Describe("A custom nuclei template. Parsed and checked; not run."),
	)
	return f.Build()
}

// Workflow is the form for nuclei.workflow.run.
func Workflow() sdkv1.FormBuilder {
	f := formkit.New("Run Nuclei Workflow").
		Describe("Execute a nuclei workflow against targets.").
		Add(
			formkit.List("targets", "Targets"),
			formkit.Text("targetsPath", "Targets from context (JSON path)"),
			formkit.List("workflows", "Workflow files/dirs").Required(),
			formkit.Integer("maxFindings", "Max findings").Default(500),
			formkit.Bool("includeRequestResponse", "Include request/response dumps").Default(false),
		)
	return f.Build()
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
