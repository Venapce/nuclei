# NUCLEI — Inflowenger plugin

Template-based vulnerability scanning as a workflow node, powered by the embedded
[nuclei](https://github.com/projectdiscovery/nuclei) engine (ProjectDiscovery,
MIT). One `NUCLEI` node runs scans, previews and searches the catalog, updates
it, and validates custom templates — all against targets a flow provides.

> **This node performs active scanning against the targets it is given.
> Authorisation to scan them is your responsibility.** See
> [Safety](#safety-gates).

The design rationale — why one node covers 13,000+ templates, and why there is no
per-template dialog — is in [docs/feasibility.md](docs/feasibility.md).

---

## Actions

| Method | Title | What it does |
|--------|-------|--------------|
| `nuclei.scan.run` | Run Scan | Run filtered templates against targets; streams findings as they match. |
| `nuclei.templates.select` | Preview Selection | Resolve a filter to a count + severity breakdown, without scanning. |
| `nuclei.templates.search` | Search Templates | Keyword search over the catalog (also callable mid-flow). |
| `nuclei.templates.update` | Update Templates | Pull the latest released catalog. |
| `nuclei.template.validate` | Validate Template | Parse and check a custom template YAML. |
| `nuclei.workflow.run` | Run Workflow | Execute a nuclei workflow against targets. |

Meta RPCs (`nuclei.meta.ping`, `.profiles`, `.tags`, `.templates.search`) back the
connection test and the form's browse/search buttons.

## How templates are selected

Nuclei has no per-template UI, and neither does this node. Templates are chosen by
**filter**, on one form:

- **Profile** — a named bundle from the catalog (`kev`, `cves`, `wordpress`, …).
- **Filters** — severity, protocol, tags, authors, template IDs.
- **Condition (DSL)** — e.g. `contains(tags,'cve') && cvss_score >= 9.0`.
- **Search** — a keyword button fills the IDs list from the catalog index.

Run **Preview Selection** first to see how many templates a filter matches before
scanning.

## The connection

The node holds **no scan credential** — nuclei needs none for its main path. The
settings profile carries *deployment policy*: the templates directory, load and
politeness knobs (rate limit, concurrency, timeout), and the safety gates.

## Safety gates

Every gate defaults to the safe setting; an operator opts in per connection.

- **Block local/private network** — ON by default (SSRF protection). Turn off
  only to scan internal hosts you own.
- **Allow intrusive templates** — dos/fuzz/bruteforce/local, which nuclei
  excludes by default.
- **Allow code templates** — templates that **execute shell on the plugin host**.
  Off by default; pair with **Signed templates only** when enabled.
- **Allow DAST / headless / local file access** — off by default.

## Run

Standard Go plugin command, from the repository root:

```bash
go run .
```

Copy `.env.inflow.example` to `.env.inflow` and fill in `PLUGIN_ID`,
`INFRA_CRED`, `INFRA_URL` first. On FloMorphic, use **Extensions → NUCLEI →
Install** for the generated one-liner and `./plugin.sh`.

The first scan needs a template catalog: run **Update Templates** once, or set
`templatesDir` in the settings profile to an existing nuclei-templates checkout.

## Build notes

- Go 1.27+. The binary embeds the nuclei engine and its dependency graph
  (~150–200 MB, single file — no external `nuclei` binary required).
- `go.mod` currently uses **local `replace` directives** for the SDK and nuclei
  while under development. Remove them before publishing so consumers resolve the
  tagged modules, and confirm the `go-plugin-sdk` version tag carries `formkit`,
  `PluginIntro.Manual`, and `Plugin.OnSignal`.

## Test

```bash
go test ./...
go vet ./...
```
