package actions

import (
	"github.com/Inflowenger/go-plugin-sdk/sdkv1"
	"github.com/venapce/nuclei/internal/nuclei"
)

type selectInput struct {
	filterInput
	Settings map[string]any `json:"settings"`
}

// Select handles nuclei.templates.select — resolve a filter without scanning.
func Select(job sdkv1.Job) {
	req, err := sdkv1.CastRequestTo[selectInput](job.Req.Data)
	if err != nil {
		job.DoneWithError("bad request: " + err.Error())
		return
	}
	sc := scannerFor(req.Body.Settings)
	defer sc.Close()

	job.Progress(20, sdkv1.Frame{Title: "resolving selection", Content: describeFilter(req.Body.filterInput)})
	sel, err := sc.Select(ctxOf(), buildFilter(req.Body.filterInput))
	if err != nil {
		job.DoneWithError(err.Error())
		return
	}
	job.Done(map[string]any{
		"count":      sel.Count,
		"bySeverity": sel.BySeverity,
		"sample":     sel.Sample,
	})
}

type searchInput struct {
	Query    string         `json:"query"`
	Limit    int            `json:"limit"`
	Settings map[string]any `json:"settings"`
}

// SearchAction handles nuclei.templates.search as an action (callable mid-flow,
// e.g. by an LLM node reasoning about the catalog).
func SearchAction(job sdkv1.Job) {
	req, err := sdkv1.CastRequestTo[searchInput](job.Req.Data)
	if err != nil {
		job.DoneWithError("bad request: " + err.Error())
		return
	}
	sc := scannerFor(req.Body.Settings)
	defer sc.Close()

	job.Progress(20, sdkv1.Frame{Title: "searching", Content: req.Body.Query})
	matches, err := sc.Search(ctxOf(), req.Body.Query, req.Body.Limit)
	if err != nil {
		job.DoneWithError(err.Error())
		return
	}
	ids := make([]string, 0, len(matches))
	for _, m := range matches {
		ids = append(ids, m.ID)
	}
	job.Done(map[string]any{"matches": matches, "ids": ids, "count": len(matches)})
}

type updateInput struct {
	Settings map[string]any `json:"settings"`
}

// Update handles nuclei.templates.update.
func Update(job sdkv1.Job) {
	req, err := sdkv1.CastRequestTo[updateInput](job.Req.Data)
	if err != nil {
		job.DoneWithError("bad request: " + err.Error())
		return
	}
	sc := scannerFor(req.Body.Settings)
	defer sc.Close()

	job.Progress(30, sdkv1.Frame{Title: "updating templates", Content: "pulling latest release"})
	res, err := sc.UpdateTemplates(ctxOf())
	if err != nil {
		job.DoneWithError(err.Error())
		return
	}
	job.Done(map[string]any{"from": res.From, "to": res.To, "changed": res.Changed})
}

type validateInput struct {
	Template string         `json:"template"`
	Settings map[string]any `json:"settings"`
}

// Validate handles nuclei.template.validate.
func Validate(job sdkv1.Job) {
	req, err := sdkv1.CastRequestTo[validateInput](job.Req.Data)
	if err != nil {
		job.DoneWithError("bad request: " + err.Error())
		return
	}
	if req.Body.Template == "" {
		job.DoneWithError("no template: paste a nuclei template YAML to validate")
		return
	}
	sc := scannerFor(req.Body.Settings)
	defer sc.Close()

	v := sc.Validate(ctxOf(), []byte(req.Body.Template))
	out := map[string]any{"valid": v.Valid, "id": v.ID, "name": v.Name, "severity": v.Severity, "errors": v.Errors}
	if !v.Valid {
		job.DoneWithErrorData("template is invalid", out)
		return
	}
	job.Done(out)
}

type workflowInput struct {
	Targets                []string       `json:"targets"`
	TargetsPath            string         `json:"targetsPath"`
	Workflows              []string       `json:"workflows"`
	MaxFindings            int            `json:"maxFindings"`
	IncludeRequestResponse bool           `json:"includeRequestResponse"`
	Settings               map[string]any `json:"settings"`
}

// Workflow handles nuclei.workflow.run. A workflow is templates plus flow logic;
// the engine treats the workflow files as its template sources.
func Workflow(job sdkv1.Job) {
	req, err := sdkv1.CastRequestTo[workflowInput](job.Req.Data)
	if err != nil {
		job.DoneWithError("bad request: " + err.Error())
		return
	}
	in := req.Body
	if len(clean(in.Workflows)) == 0 {
		job.DoneWithError("no workflow: provide at least one workflow file or directory")
		return
	}
	targets := clean(in.Targets)
	if len(targets) == 0 && in.TargetsPath != "" {
		targets = targetsFromContext(job, in.TargetsPath)
	}
	if len(targets) == 0 {
		job.DoneWithError("no targets to run the workflow against")
		return
	}

	sc := scannerFor(in.Settings)
	defer sc.Close()

	scanSem <- struct{}{}
	defer func() { <-scanSem }()

	job.Progress(10, sdkv1.Frame{Title: "running workflow", Content: describeList(in.Workflows)})
	var findings []nuclei.Finding
	n, err := sc.Scan(ctxOf(), nuclei.ScanRequest{
		Targets:        targets,
		Filter:         nuclei.Filter{CustomTemplates: clean(in.Workflows)},
		MaxFindings:    in.MaxFindings,
		IncludeReqResp: in.IncludeRequestResponse,
	}, func(f nuclei.Finding) { findings = append(findings, f) })
	out := map[string]any{"findings": findings, "stats": map[string]any{"findings": n, "targets": len(targets)}}
	if err != nil {
		job.DoneWithErrorData("workflow ended with error: "+err.Error(), out)
		return
	}
	job.Done(out)
}

func describeList(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	return ss[0]
}
