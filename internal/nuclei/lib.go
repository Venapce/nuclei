package nuclei

import (
	"errors"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	engine "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
)

// LibScanner is the embedded-library Scanner. One instance per resolved Config
// (i.e. per settings profile); construct it through the pool in the actions
// package, never globally, since a job carries its own connection.
//
// NOTE (feasibility.md §7): nuclei's config.DefaultConfig is a process-wide
// singleton. This v1 standardises on ONE catalog per plugin process — the
// templates directory is set once, at first construction. A second profile that
// points at a different directory is not honoured; that is the documented v1
// limitation, not a bug to paper over here.
type LibScanner struct {
	cfg Config

	dirOnce sync.Once
}

var setDirOnce sync.Once

// New builds a LibScanner for one resolved connection.
func New(cfg Config) *LibScanner {
	s := &LibScanner{cfg: cfg}
	s.applyProcessConfig()
	return s
}

// applyProcessConfig sets the process-wide nuclei config once. Update checks are
// disabled globally so no engine construction ever reaches out to GitHub or the
// PDCP version endpoint on its own — updates run only through UpdateTemplates.
func (s *LibScanner) applyProcessConfig() {
	setDirOnce.Do(func() {
		if s.cfg.TemplatesDir != "" {
			config.DefaultConfig.TemplatesDirectory = s.cfg.TemplatesDir
		}
		config.DefaultConfig.DisableUpdateCheck()
	})
}

// baseOptions are the options common to every engine this scanner builds.
func (s *LibScanner) baseOptions() []engine.NucleiSDKOptions {
	opts := []engine.NucleiSDKOptions{
		engine.DisableUpdateCheck(),
		engine.WithSandboxOptions(s.cfg.AllowLocalFileAccess, s.cfg.RestrictLocalNetworkAccess),
	}
	if s.cfg.AllowCodeTemplates {
		opts = append(opts, engine.EnableCodeTemplates())
	}
	if s.cfg.SignedOnly {
		opts = append(opts, engine.SignedTemplatesOnly())
	}
	if len(s.cfg.CustomTemplates) > 0 {
		opts = append(opts, engine.WithTemplatesOrWorkflows(engine.TemplateSources{
			Templates:      s.cfg.CustomTemplates,
			TrustedDomains: s.cfg.TrustedDomains,
		}))
	}
	if len(s.cfg.CustomHeaders) > 0 {
		opts = append(opts, engine.WithHeaders(s.cfg.CustomHeaders))
	}
	return opts
}

// scanOptions adds the runtime knobs used for an actual scan (not for read-only
// preview/search).
func (s *LibScanner) scanOptions() []engine.NucleiSDKOptions {
	opts := s.baseOptions()
	opts = append(opts,
		engine.WithConcurrency(engine.Concurrency{
			TemplateConcurrency:           s.cfg.Concurrency,
			HostConcurrency:               s.cfg.BulkSize,
			HeadlessHostConcurrency:       10,
			HeadlessTemplateConcurrency:   10,
			JavascriptTemplateConcurrency: 10,
			TemplatePayloadConcurrency:    25,
			ProbeConcurrency:              50,
		}),
		engine.WithNetworkConfig(engine.NetworkConfig{
			Timeout:      s.cfg.Timeout,
			Retries:      s.cfg.Retries,
			MaxHostError: s.cfg.MaxHostErr,
		}),
	)
	if len(s.cfg.Proxy) > 0 {
		opts = append(opts, engine.WithProxy(s.cfg.Proxy, false))
	}
	if s.cfg.AllowDAST {
		opts = append(opts, engine.DASTMode())
	}
	return opts
}

// filterOptions turns a Filter into engine options, applying the gates.
func (s *LibScanner) filterOptions(f Filter) []engine.NucleiSDKOptions {
	var opts []engine.NucleiSDKOptions

	// A named profile is a RuntimeConfig YAML shipped in the catalog; merge it
	// first so explicit filter fields can layer on top.
	if f.Profile != "" {
		if p := s.profilePath(f.Profile); p != "" {
			opts = append(opts, engine.WithConfigFile(p))
		}
	}

	include := append([]string(nil), f.IncludeTags...)
	if s.cfg.AllowIntrusive {
		// Force-run the classes .nuclei-ignore excludes by default. Without an
		// operator opening this gate, the engine's baseline exclusions stand.
		include = append(include, "dos", "local", "fuzz", "bruteforce", "txt-service")
	}

	tf := engine.TemplateFilters{
		Severity:          strings.Join(f.Severity, ","),
		ExcludeSeverities: strings.Join(f.ExcludeSeverity, ","),
		ProtocolTypes:     strings.Join(f.ProtocolTypes, ","),
		Tags:              f.Tags,
		ExcludeTags:       f.ExcludeTags,
		IncludeTags:       include,
		Authors:           f.Authors,
		IDs:               f.TemplateIDs,
		ExcludeIDs:        f.ExcludeIDs,
		TemplateCondition: f.TemplateCondition,
	}
	opts = append(opts, engine.WithTemplateFilters(tf))
	return opts
}

func (s *LibScanner) profilePath(name string) string {
	name = filepath.Base(name) // never let a profile name escape the dir
	if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
		name += ".yml"
	}
	p := filepath.Join(config.DefaultConfig.GetTemplateDir(), "profiles", name)
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

// Health implements Scanner.
func (s *LibScanner) Health(ctx context.Context) Health {
	h := Health{
		EngineVersion:    config.Version,
		TemplatesDir:     config.DefaultConfig.GetTemplateDir(),
		TemplatesVersion: config.DefaultConfig.TemplateVersion,
		CodeTemplates:    s.cfg.AllowCodeTemplates,
		Intrusive:        s.cfg.AllowIntrusive,
	}
	if h.TemplatesDir == "" || !dirExists(h.TemplatesDir) {
		h.Message = "no templates directory: run Update Templates, or set templatesDir in the settings profile"
		return h
	}
	ne, err := engine.NewNucleiEngineCtx(ctx, s.baseOptions()...)
	if err != nil {
		h.Message = "engine init failed: " + err.Error()
		return h
	}
	defer ne.Close()
	if err := ne.LoadAllTemplates(); err != nil {
		h.Message = "template load failed: " + err.Error()
		return h
	}
	h.TemplateCount = len(ne.GetTemplates())
	h.OK = h.TemplateCount > 0
	if !h.OK {
		h.Message = "templates directory present but empty"
	}
	return h
}

// Select implements Scanner.
func (s *LibScanner) Select(ctx context.Context, f Filter) (*Selection, error) {
	opts := append(s.baseOptions(), s.filterOptions(f)...)
	ne, err := engine.NewNucleiEngineCtx(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("engine init: %w", err)
	}
	defer ne.Close()
	if err := ne.LoadAllTemplates(); err != nil {
		return nil, fmt.Errorf("load templates: %w", err)
	}
	tpls := ne.GetTemplates()
	sel := &Selection{Count: len(tpls), BySeverity: map[string]int{}}
	for i, t := range tpls {
		sev := t.Info.SeverityHolder.Severity.String()
		sel.BySeverity[sev]++
		if i < 25 {
			sel.Sample = append(sel.Sample, metaOf(t))
		}
	}
	return sel, nil
}

// Search implements Scanner. v1 loads the catalog and substring-matches; see the
// memory flag in feasibility.md §2. The metadata-index fast path is a follow-up.
func (s *LibScanner) Search(ctx context.Context, query string, limit int) ([]Meta, error) {
	if limit <= 0 {
		limit = 50
	}
	q := strings.ToLower(strings.TrimSpace(query))
	ne, err := engine.NewNucleiEngineCtx(ctx, s.baseOptions()...)
	if err != nil {
		return nil, fmt.Errorf("engine init: %w", err)
	}
	defer ne.Close()
	if err := ne.LoadAllTemplates(); err != nil {
		return nil, fmt.Errorf("load templates: %w", err)
	}
	var out []Meta
	for _, t := range ne.GetTemplates() {
		if q != "" && !templateMatches(t, q) {
			continue
		}
		out = append(out, metaOf(t))
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

// Scan implements Scanner.
func (s *LibScanner) Scan(ctx context.Context, req ScanRequest, onFinding func(Finding)) (int, error) {
	opts := append(s.scanOptions(), s.filterOptions(req.Filter)...)
	if len(req.Vars) > 0 {
		opts = append(opts, engine.WithVars(req.Vars))
	}

	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var count int
	var capped bool
	var mu sync.Mutex
	cb := func(e *output.ResultEvent) {
		mu.Lock()
		defer mu.Unlock()
		count++
		if onFinding != nil {
			onFinding(findingOf(e, req.IncludeReqResp))
		}
		if req.MaxFindings > 0 && count >= req.MaxFindings {
			capped = true
			cancel() // stop the scan once the cap is hit — a success, not a failure
		}
	}

	opts = append(opts, engine.WithResultCallback(cb))
	ne, err := engine.NewNucleiEngineCtx(scanCtx, opts...)
	if err != nil {
		return 0, fmt.Errorf("engine init: %w", err)
	}
	defer ne.Close()
	if err := ne.LoadAllTemplates(); err != nil {
		return 0, fmt.Errorf("load templates: %w", err)
	}
	if len(ne.GetTemplates()) == 0 {
		return 0, fmt.Errorf("no templates matched the filter")
	}
	ne.LoadTargets(req.Targets, req.ProbeNonHTTP)
	if err := ne.ExecuteCallbackWithCtx(scanCtx); err != nil {
		// A cancellation we triggered to enforce the finding cap, or one the
		// parent context carried in (a job stop), is not a scan failure — the
		// findings collected so far are the result. Only other errors are real.
		if capped || errors.Is(err, context.Canceled) {
			return count, nil
		}
		return count, fmt.Errorf("scan: %w", err)
	}
	return count, nil
}

// UpdateTemplates implements Scanner.
func (s *LibScanner) UpdateTemplates(ctx context.Context) (*UpdateResult, error) {
	from := config.DefaultConfig.TemplateVersion
	tm := installer.TemplateManager{}
	if from == "" || !dirExists(config.DefaultConfig.GetTemplateDir()) {
		if err := tm.FreshInstallIfNotExists(); err != nil {
			return nil, fmt.Errorf("install templates: %w", err)
		}
	} else if err := tm.UpdateIfOutdated(); err != nil {
		return nil, fmt.Errorf("update templates: %w", err)
	}
	to := config.DefaultConfig.TemplateVersion
	return &UpdateResult{From: from, To: to, Changed: from != to}, nil
}

// Validate implements Scanner.
func (s *LibScanner) Validate(ctx context.Context, body []byte) *Validation {
	ne, err := engine.NewNucleiEngineCtx(ctx, s.baseOptions()...)
	if err != nil {
		return &Validation{Valid: false, Errors: []string{"engine init: " + err.Error()}}
	}
	defer ne.Close()
	t, err := ne.ParseTemplate(body)
	if err != nil {
		return &Validation{Valid: false, Errors: []string{err.Error()}}
	}
	return &Validation{
		Valid:    true,
		ID:       t.ID,
		Name:     t.Info.Name,
		Severity: t.Info.SeverityHolder.Severity.String(),
	}
}

// Profiles implements Scanner: lists profiles/*.yml in the templates dir.
func (s *LibScanner) Profiles(ctx context.Context) ([]string, error) {
	dir := filepath.Join(config.DefaultConfig.GetTemplateDir(), "profiles")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil // no profiles dir yet is not an error
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if strings.HasSuffix(n, ".yml") || strings.HasSuffix(n, ".yaml") {
			out = append(out, strings.TrimSuffix(strings.TrimSuffix(n, ".yaml"), ".yml"))
		}
	}
	sort.Strings(out)
	return out, nil
}

// Tags implements Scanner: best-effort from the catalog's TEMPLATES-STATS.json,
// which the templates repo ships. Absent it, returns nil rather than paying a
// full catalog load just to count tags.
func (s *LibScanner) Tags(ctx context.Context, limit int) ([]TagCount, error) {
	return readStatsTags(config.DefaultConfig.GetTemplateDir(), limit)
}

// Close implements Scanner. Engines are created and closed per-operation, so
// there is nothing process-lived to release here in v1.
func (s *LibScanner) Close() {}

// --- projections ---

func metaOf(t *templates.Template) Meta {
	return Meta{
		ID:       t.ID,
		Name:     t.Info.Name,
		Severity: t.Info.SeverityHolder.Severity.String(),
		Protocol: t.Type().String(),
		Tags:     t.Info.Tags.ToSlice(),
		Authors:  t.Info.Authors.ToSlice(),
	}
}

func findingOf(e *output.ResultEvent, includeReqResp bool) Finding {
	f := Finding{
		TemplateID: e.TemplateID,
		Name:       e.Info.Name,
		Severity:   e.Info.SeverityHolder.Severity.String(),
		Protocol:   e.Type,
		Host:       e.Host,
		Port:       e.Port,
		URL:        e.URL,
		MatchedAt:  e.Matched,
		IP:         e.IP,
		Tags:       e.Info.Tags.ToSlice(),
		Extracted:  e.ExtractedResults,
		CURLCommand: e.CURLCommand,
	}
	if !e.Timestamp.IsZero() {
		f.Timestamp = e.Timestamp.UTC().Format("2006-01-02T15:04:05Z")
	}
	f.Description = e.Info.Description
	f.Remediation = e.Info.Remediation
	if e.Info.Reference != nil {
		f.Reference = e.Info.Reference.ToSlice()
	}
	if c := e.Info.Classification; c != nil {
		f.CVEID = c.CVEID.ToSlice()
		f.CWEID = c.CWEID.ToSlice()
		f.CVSSScore = c.CVSSScore
		f.EPSSScore = c.EPSSScore
	}
	if includeReqResp {
		f.RequestDump = e.Request
		f.ResponseDump = e.Response
	}
	return f
}

func templateMatches(t *templates.Template, q string) bool {
	if strings.Contains(strings.ToLower(t.ID), q) ||
		strings.Contains(strings.ToLower(t.Info.Name), q) {
		return true
	}
	for _, tag := range t.Info.Tags.ToSlice() {
		if strings.Contains(strings.ToLower(tag), q) {
			return true
		}
	}
	return false
}

func dirExists(p string) bool {
	if p == "" {
		return false
	}
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}
