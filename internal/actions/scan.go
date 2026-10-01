package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/Inflowenger/go-plugin-sdk/sdkv1"
	"github.com/venapce/nuclei/internal/nuclei"
)

// maxConcurrentScans bounds how many scans run at once across the whole process.
// A single full-catalog scan costs ~600 MB RSS and the store is loaded per scan,
// so memory scales with concurrency, not with one shared copy (feasibility.md
// §7). Keep this small; raise it only with a matching memory budget.
const maxConcurrentScans = 2

var scanSem = make(chan struct{}, maxConcurrentScans)

// jobCancels lets the plugin's signal handler stop an in-flight scan when the
// runtime cancels the node. Registered per job, cleared on completion.
var jobCancels sync.Map // jobId -> context.CancelFunc

// CancelJob is called from main's OnSignal handler on a cancelling conclusion.
func CancelJob(jobID string) {
	if c, ok := jobCancels.Load(jobID); ok {
		c.(context.CancelFunc)()
	}
}

type scanInput struct {
	filterInput
	Targets                []string       `json:"targets"`
	TargetsPath            string         `json:"targetsPath"`
	Vars                   []string       `json:"vars"`
	MaxFindings            int            `json:"maxFindings"`
	IncludeRequestResponse bool           `json:"includeRequestResponse"`
	ProbeNonHTTP           bool           `json:"probeNonHttp"`
	ConfirmFullCatalog     bool           `json:"confirmFullCatalog"`
	Settings               map[string]any `json:"settings"`
}

// Scan handles nuclei.scan.run.
func Scan(job sdkv1.Job) {
	req, err := sdkv1.CastRequestTo[scanInput](job.Req.Data)
	if err != nil {
		job.DoneWithError("bad request: " + err.Error())
		return
	}
	in := req.Body

	if in.filterInput.isEmpty() && !in.ConfirmFullCatalog {
		job.DoneWithError("no filter set: this would run the entire catalog (13k+ templates, ~600 MB). Set a profile/severity/tags/ids, or tick 'Confirm unfiltered run'.")
		return
	}

	targets := clean(in.Targets)
	if len(targets) == 0 && in.TargetsPath != "" {
		targets = targetsFromContext(job, in.TargetsPath)
	}
	if len(targets) == 0 {
		job.DoneWithError("no targets: fill Targets, or point 'Targets from context' at a path that yields hosts/URLs.")
		return
	}

	sc := scannerFor(in.Settings)
	defer sc.Close()

	// Bound concurrency; report the wait so a queued node is legible.
	job.Progress(3, sdkv1.Frame{Title: "queued", Content: "waiting for a scan slot"})
	scanSem <- struct{}{}
	defer func() { <-scanSem }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if job.JobId != "" {
		jobCancels.Store(job.JobId, cancel)
		defer jobCancels.Delete(job.JobId)
	}

	job.Progress(8, sdkv1.Frame{Title: "loading templates", Content: describeFilter(in.filterInput)})

	var findings []nuclei.Finding
	var mu sync.Mutex
	onFinding := func(f nuclei.Finding) {
		mu.Lock()
		findings = append(findings, f)
		n := len(findings)
		mu.Unlock()
		pct := 10 + n%85
		job.Progress(pct, sdkv1.Frame{
			Title:   fmt.Sprintf("[%s] %s", f.Severity, f.TemplateID),
			Content: f.MatchedAt,
		})
	}

	n, scanErr := sc.Scan(ctx, nuclei.ScanRequest{
		Targets:        targets,
		Filter:         buildFilter(in.filterInput),
		Vars:           clean(in.Vars),
		MaxFindings:    in.MaxFindings,
		IncludeReqResp: in.IncludeRequestResponse,
		ProbeNonHTTP:   in.ProbeNonHTTP,
	}, onFinding)

	out := map[string]any{
		"findings": findings,
		"stats": map[string]any{
			"findings": n,
			"targets":  len(targets),
			"capped":   in.MaxFindings > 0 && n >= in.MaxFindings,
		},
	}
	if scanErr != nil {
		// A scan that produced findings before failing still committed value.
		job.DoneWithErrorData("scan ended with error: "+scanErr.Error(), out)
		return
	}
	job.Done(out)
}

// targetsFromContext reads a JSON path out of the flow context and extracts
// hosts/URLs from whatever shape it holds.
func targetsFromContext(job sdkv1.Job, path string) []string {
	v := job.CmdGetScope(path)
	b, ok := v.([]byte)
	if !ok || len(b) == 0 {
		return nil
	}
	return extractTargets(b)
}

// extractTargets accepts a JSON array of strings, a single string, or an array
// of objects carrying url/host/target/ip.
func extractTargets(b []byte) []string {
	var ss []string
	if json.Unmarshal(b, &ss) == nil && len(ss) > 0 {
		return clean(ss)
	}
	var one string
	if json.Unmarshal(b, &one) == nil && one != "" {
		return []string{one}
	}
	var objs []map[string]any
	if json.Unmarshal(b, &objs) == nil {
		var out []string
		for _, o := range objs {
			for _, k := range []string{"url", "host", "target", "ip", "hostname"} {
				if s, ok := o[k].(string); ok && s != "" {
					out = append(out, s)
					break
				}
			}
		}
		return out
	}
	return nil
}

func describeFilter(f filterInput) string {
	if f.Profile != "" {
		return "profile: " + f.Profile
	}
	if len(f.Tags) > 0 {
		return "tags: " + fmt.Sprint(f.Tags)
	}
	if len(f.TemplateIDs) > 0 {
		return fmt.Sprintf("%d template id(s)", len(f.TemplateIDs))
	}
	return "filtered"
}
