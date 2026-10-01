// Command nuclei is an Inflowenger plugin node that wraps the ProjectDiscovery
// nuclei scanner: one NUCLEI node whose actions run template-based scans,
// preview and search the catalog, update it, and validate custom templates.
//
// The node has a fixed, small action surface regardless of how many templates
// the catalog holds — nuclei selects templates by filter, not by dialog, so
// there is no per-template UI to generate (see docs/feasibility.md §3).
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Inflowenger/go-plugin-sdk/sdkv1"
	"github.com/venapce/nuclei/internal/actions"
	"github.com/venapce/nuclei/internal/forms"
)

const version = "v0.1.0"

func main() {
	envFile := os.Getenv("INFLOW_ENV_FILE")
	if envFile == "" {
		envFile = ".env.inflow"
	}

	p, err := sdkv1.NewPlugin(sdkv1.WithDotEnv(envFile))
	if err != nil {
		log.Fatalf("cannot connect to infra (%s): %v", envFile, err)
	}

	settings := forms.Settings()
	settings.SubmitHandler = actions.Ping

	p.Intro(sdkv1.PluginIntro{
		Name:     "NUCLEI",
		Author:   "venapce dev team",
		Version:  version,
		Settings: &settings.FormBuilder,
		Manual:   manual,
	})
	p.RequiredParams(settings)

	p.AddAction(
		sdkv1.Action{
			Method:         forms.ScanRun,
			Title:          "Run Scan",
			Description:    "Run nuclei templates against targets. Streams findings as they are matched.",
			Form:           forms.Scan(),
			RequestHandler: actions.Scan,
		},
		sdkv1.Action{
			Method:         forms.TemplatesSelect,
			Title:          "Preview Selection",
			Description:    "Resolve a template filter to a count and severity breakdown, without scanning.",
			Form:           forms.Select(),
			RequestHandler: actions.Select,
		},
		sdkv1.Action{
			Method:         forms.TemplatesSearch,
			Title:          "Search Templates",
			Description:    "Search the catalog by keyword — usable mid-flow to reason about templates.",
			Form:           forms.Search(),
			RequestHandler: actions.SearchAction,
		},
		sdkv1.Action{
			Method:         forms.TemplatesUpdate,
			Title:          "Update Templates",
			Description:    "Pull the latest released nuclei-templates catalog.",
			Form:           forms.Update(),
			RequestHandler: actions.Update,
		},
		sdkv1.Action{
			Method:         forms.TemplateValidate,
			Title:          "Validate Template",
			Description:    "Parse and check a custom template YAML (not run).",
			Form:           forms.Validate(),
			RequestHandler: actions.Validate,
		},
		sdkv1.Action{
			Method:         forms.WorkflowRun,
			Title:          "Run Workflow",
			Description:    "Execute a nuclei workflow against targets.",
			Form:           forms.Workflow(),
			RequestHandler: actions.Workflow,
		},
	)

	p.AddMeta(
		sdkv1.Meta{Method: forms.MetaProfiles, RequestHandler: actions.Profiles},
		sdkv1.Meta{Method: forms.MetaTags, RequestHandler: actions.Tags},
		sdkv1.Meta{Method: forms.MetaSearch, RequestHandler: actions.Search},
		sdkv1.Meta{Method: forms.MetaPing, RequestHandler: func(r sdkv1.Request) any {
			return actions.Ping(r)
		}},
	)

	// A cancelled node should stop its in-flight scan (a scan holds a network
	// work pool). Signals also arrive on success, so filter on the conclusion.
	p.OnSignal(func(sig sdkv1.Signal) {
		if sig.Conclusion.Canceled() {
			actions.CancelJob(sig.JobId)
		}
	})

	if err := p.Start(); err != nil {
		log.Fatalf("start: %v", err)
	}
	log.Printf("NUCLEI %s ready", version)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println("shutting down")
}

const manual = "# NUCLEI\n\n" +
	"Template-based vulnerability scanning as a workflow node, powered by the " +
	"embedded [nuclei](https://github.com/projectdiscovery/nuclei) engine.\n\n" +
	"**This node performs active scanning against the targets it is given. " +
	"Authorisation to scan them is your responsibility.**\n\n" +
	"Templates are selected by *filter* (profile, severity, tags, IDs, or a DSL " +
	"condition), never one dialog per template. Start with **Preview Selection** " +
	"to see what a filter matches, then **Run Scan**.\n\n" +
	"Check the connection and see the catalog version:\n\n" +
	"```inflow-meta\nnuclei.meta.ping\n```\n\n" +
	"See `## Run` in the README to start the plugin.\n"
