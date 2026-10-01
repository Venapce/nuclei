# nuclei — feasibility & design assessment

> Investigation of what a **`NUCLEI`** plugin node needs, and how a workflow node
> exposes a scanner whose value lives in **13,000+ community templates**.
> Scope: the embedding decision (library vs. CLI), the template-selection model,
> the resource and safety envelope. Not a build spec — it is the note
> [security-collectors-plan.md §14](../../../plugin-catalog/docs/security-collectors-plan.md)
> asks for before wave 1, and it follows
> [osctrl-feasibility.md](../../../plugin-catalog/docs/osctrl-feasibility.md).
>
> Status: **assessment**. Every number below was measured on this machine; the
> method is in §2.

---

## TL;DR

- **It works, and the hard part is not what it looks like.** A proof-of-concept
  binary that imports **both** `go-plugin-sdk/sdkv1` **and**
  `projectdiscovery/nuclei/v3/lib` compiles and runs. No dependency conflict,
  no CGO, no external binary. **150 MB** stripped, one file, `go run .`.
- **"Supporting all templates" is a non-problem, because templates are not API
  surface.** Nuclei itself never asks *which of 13,000*; it asks for a **filter**
  — tags, severity, protocol, IDs, a DSL condition — or a **named profile**. A
  filter is a handful of strings and arrays, which a static JSON Schema
  expresses perfectly. The node keeps **~6 actions forever**, whether the
  catalog holds 13,000 templates or 130,000.
- **What replaces the impossible dropdown is a search RPC.** The platform cannot
  inject an `enum` at runtime
  ([dependent-fields.md](../../../plugin-catalog/docs/dependent-fields.md)), and
  13,326 options would be unusable anyway. Nuclei ships a **persistent template
  metadata index** (`pkg/catalog/index`, 7.2 MB gob, id/name/tags/authors/
  severity/protocol/product), so a `nuclei.meta.templates.search` meta RPC
  answers "which templates mention grafana" in-process in well under a second,
  and patches the chosen IDs into the form.
- **The real engineering problems are resources and blast radius**, not
  coverage: a full-catalog load costs **~600 MB RSS**, `ThreadSafeNucleiEngine`
  **re-loads the template store per scan** (so memory scales with concurrent
  jobs, not with one shared copy), and the `code`/`self-contained` template
  classes execute **shell on the plugin host**.
- **Recommendation: embed the library, ship one `NUCLEI` node, gate the
  dangerous classes behind the settings profile, cap concurrency at the plugin,
  and keep execution behind one internal `Scanner` interface** so a
  subprocess-isolated backend can be swapped in later without touching the
  actions.

---

## 1. What nuclei is, in plugin terms

Two things, and the plugin must treat them separately.

| | **The engine** | **The catalog** |
|---|---|---|
| What | `projectdiscovery/nuclei` (MIT, Go 1.27) — request builders for http/dns/network/ssl/file/javascript/headless/code, a matcher/extractor DSL, a rate-limited work pool | `projectdiscovery/nuclei-templates` (v10.4.9) — 13.7k YAML files, released as a GitHub archive, versioned independently of the engine |
| Ships as | A Go module you import, or a CLI binary | ~89 MB on disk, installed to a templates directory, updated with `-ut` / `installer.TemplateManager` |
| Cadence | Engine releases | **Continuous** — new CVE templates land daily |
| Plugin's job | Call it | **Keep it fresh, and let a workflow address a subset of it** |

The catalog's independent cadence is the whole reason the node must not enumerate
templates in its schema: a template added tomorrow has to be reachable by a flow
built today, without a plugin release. Filters satisfy that; an `enum` never
could.

---

## 2. The numbers (measured, not estimated)

Environment: this machine, Go 1.27.1, nuclei `dev` @ `a2b6d2a` (reports
`v3.11.1`), nuclei-templates **v10.4.9**, all state isolated into a scratch dir
via `NUCLEI_CONFIG_DIR` + `-ud`.

| Fact | Measured | How |
|---|---|---|
| Nuclei CLI binary | **216 MB** unstripped / **162 MB** stripped | `go build [-ldflags="-s -w"] ./cmd/nuclei` |
| **PoC: inflow SDK + nuclei lib in one binary** | **199 MB** / **150 MB** stripped, runs | scratch module importing `sdkv1` + `nuclei/v3/lib`, `go build` |
| Module graph of that binary | **946 modules** | `go list -m all \| wc -l` |
| Templates on disk | **89 MB**, **13,742** YAML files | `nuclei -ud <dir> -ut` |
| Runnable templates | **13,326** (+ **207** workflows; the ~200 balance is the ignore list and non-template YAML) | `nuclei -tl \| wc -l` |
| Distinct tags / authors | **8,721** / **1,330** | `TEMPLATES-STATS.json` |
| Severity split | info 5,129 · high 3,007 · medium 2,855 · critical 1,967 · low 519 | same |
| By directory | http 11,364 · cloud 663 · file 447 · code 304 · network 282 · dast 251 · workflows 207 · javascript 131 · ssl 38 · dns 31 · headless 24 | same |
| **Full-catalog enumerate** | **1.6 s**, **~600 MB peak RSS** (cold index) → 1.5 s, ~530 MB warm | `/usr/bin/time -v nuclei -tl` |
| Metadata index on disk | **7.2 MB** (`~/.cache/nuclei/index.gob`) | after first run |
| Filtered scan, 1 target | `-tags exposure,misconfig` = **2,014 templates**, **49 s**, **333 MB peak RSS**, 10 findings | local `http.server` on 127.0.0.1, `-jsonl` |
| One finding on the wire | **~2 KB** with `request`/`response` dumps | the JSONL above |

Two of these drive the design directly:

1. **~600 MB to hold the whole catalog** — and it is *per loaded store*, not per
   process (§6). A node that says "run everything" on a 2 GB plugin host is one
   concurrent run away from an OOM kill.
2. **~2 KB per finding** — a 500-finding scan is a 1 MB node output. The action
   must cap results and make the request/response dump opt-in, the way
   [ClickHouse](../../../plugin-catalog/plugins/clickhouse.md) caps rows.

---

## 3. The template problem, and why it dissolves

The instinct is: 13,000 templates → we need a way to show 13,000 things. That is
the wrong frame, and following it produces an unusable node.

**Nuclei's own interface is the answer.** Its CLI has no "pick a template" mode
worth the name; it has a **filter language** and **profiles**. So does the node.
Four layers, in increasing precision, each of them plain form data:

### Layer 1 — Profile (the default path)

The templates repo ships **20 community profiles** in `profiles/*.yml` (`kev`,
`cves`, `pentest`, `recommended`, `wordpress`, `osint`, `cloud`, `compliance`,
`default-login`, `subdomain-takeovers`, `k8s-cluster-security`, the per-cloud
configs, …). Each is a YAML bundle of filters:

```yaml
# profiles/kev.yml
tags:
  - kev
```

One `profile` field, filled by a `nuclei.meta.profiles` RPC that lists the
directory. Most users should never need to touch layers 2–4, and the profile
list grows with the catalog, not with the plugin.

### Layer 2 — Filters

Exactly nuclei's own, as typed fields:

| Field | Nuclei flag / SDK | Form shape |
|---|---|---|
| `severity` / `excludeSeverity` | `-s` / `-es`, `TemplateFilters.Severity` | multi-select over a **5-value static enum** — safe to hardcode |
| `protocolTypes` | `-pt`, `.ProtocolTypes` | static enum (http, dns, network, ssl, file, javascript, headless, code, …) |
| `tags` / `excludeTags` / `includeTags` | `-tags` / `-etags` / `-itags` | array of strings + a "Browse tags" button (`nuclei.meta.tags`) |
| `authors` | `-a` | array of strings |
| `templateCondition` | `-tc`, `.TemplateCondition` | **DSL expression** over `id`/`name`/`tags`/`authors`/`severity`/`protocol`/`cvss_score`/`epss_score`/`cve_id`/`cwe_id` — verified: `contains(tags,'cve') && cvss_score >= 9.0` selects **1,542** templates. One text field that expresses filters no set of checkboxes could |
| `templateIds` / `excludeIds` | `-id` / `-eid` (wildcards allowed) | array of strings, filled by the search RPC (layer 3) |

`-tc` deserves emphasis: it is nuclei's own escape hatch for arbitrary
selection, so the node inherits unbounded expressiveness from one string field.

### Layer 3 — Search, then pick

For "I want *that* template", the
[dependent-fields](../../../plugin-catalog/docs/dependent-fields.md) pattern
applies unchanged: a **`query` text field with a Search button** calls
`nuclei.meta.templates.search`, which returns a patch filling the `templateIds`
array and a readonly `matches` summary.

The backing store is already built: nuclei maintains
`pkg/catalog/index.Index` — a persisted, mtime-validated metadata cache
(`ID`, `Name`, `Authors`, `Tags`, `Severity`, `ProtocolType`, `Product`,
`Verified`) with a `Filter` type and `FilterFunc`, reachable from an engine
instance. 13,326 entries, 7.2 MB, in-process. No service, no API key, no
network — and it answers in the sub-second budget a form button needs.

This is also why the enum limitation costs nothing here. A dropdown of 13,326
templates is not a feature anyone wanted.

### Layer 4 — Templates that are not in the catalog

| Source | Mechanism |
|---|---|
| **Inline YAML** typed into the node | validate with `engine.ParseTemplate([]byte)`, write to a per-job temp dir (`WithTemporaryDirectory`), pass via `WithTemplatesOrWorkflows` |
| **Private template repo** | a path/URL in the **settings profile**; nuclei natively supports custom GitHub/GitLab/S3/Azure template directories |
| **Remote URL** | `TemplateSources.RemoteTemplates` + `TrustedDomains` |

So "support all of its templates" resolves to: *the public catalog by filter, a
private catalog by settings, and a one-off template by paste* — with the node's
schema constant across all three.

### The piece that makes it usable: dry-run

A filter is opaque until you know what it selects. A **`nuclei.templates.select`**
action (and the same call behind a form button) resolves a selection to
**count + severity histogram + a sample of IDs**, without scanning — the
`-tl` code path, 1.5 s for the whole catalog. A designer building a flow can
see that `tags: cve, severity: critical` means 1,967 templates *before* pointing
it at production.

---

## 4. Embedding: library or CLI?

Both work. The catalog's own rule for wrappers is
"[binary dependencies are declared](../../../plugin-catalog/docs/security-collectors-plan.md)"
— but nuclei is Go, so the choice is real.

| | **Embed `nuclei/v3/lib`** | **Exec the `nuclei` CLI** |
|---|---|---|
| Install | `go run .` — one binary, nothing else. Honours the catalog's standard-command rule and the FloMorphic one-liner | plugin **plus** a 162 MB binary the operator installs and keeps in step; meta ping must check for it |
| Results | `WithResultCallback` → a finding becomes `job.Progress` **as it is found** | parse `-jsonl` (stdout or file); progress needs stderr scraping or polling |
| Cancellation | `ExecuteCallbackWithCtx(ctx, …)` → cancel ctx from `p.OnSignal` | kill the process group — cruder, but absolutely reliable |
| Template catalog | direct access to `index.Index` for the search RPC | shell out to `-tl`, parse text |
| Concurrency | `ThreadSafeNucleiEngine`, shared catalog/parser/index | one process per scan, naturally isolated |
| **Blast radius** | a panic, a leak, or an OOM in template execution **takes the plugin down** | a wedged scan dies alone; memory is bounded with cgroups/ulimit |
| API stability | upstream states plainly: *"in active development, expect breaking changes"* | `-jsonl` is a de-facto stable contract |
| Dep graph | **946 modules** vendored into the plugin, incl. cloud SDKs | your own `go.mod` stays small |
| Upstream's own warning | *"Running nuclei as a service may pose security risks"* — applies to both, and the plugin **is** a service |

**Recommendation — embed, with an escape hatch.** The single-binary property is
worth more than it looks: it is what lets the FloMorphic Extensions one-liner
install this plugin the same way it installs
[Postgres](../../../plugin-catalog/plugins/postgres.md), and it is the
difference between "runs anywhere" and "runs where someone installed nuclei".
The PoC proves there is no integration obstacle.

Mitigate the two real costs:

- **API churn** — put every nuclei call behind one internal package
  (`internal/nuclei`, zero `sdkv1` imports, per [build-a-plugin §10]) exposing a
  `Scanner` interface: `Select(Filter) ([]Meta, error)`,
  `Scan(ctx, Targets, Filter, func(Finding)) error`. Pin the module version.
  An upstream break is then a one-package repair.
- **Blast radius** — the same interface admits a second implementation that
  execs the CLI. If in-process execution proves too fragile in Venapce's
  deployments, that swap is contained, and the actions, forms and node contract
  do not move.

---

## 5. Proposed node surface

One node, `NUCLEI`. Small, constant, and independent of catalog size.

### Actions

| Method | Title | What it does | Output |
|---|---|---|---|
| `nuclei.scan.run` | **Run Scan** | targets × selection → findings, streaming progress | `{findings[], stats{templates, requests, matched}, truncated}` |
| `nuclei.templates.select` | **Preview Selection** | resolve a filter without scanning | `{count, bySeverity{}, sample[]}` |
| `nuclei.templates.search` | **Search Templates** | query the metadata index (as an *action* too, so an LLM node can call it mid-flow) | `[{id, name, severity, tags, protocol}]` |
| `nuclei.templates.update` | **Update Templates** | pull the latest release; report old → new version and counts | `{from, to, added, removed}` |
| `nuclei.template.validate` | **Validate Template** | parse a custom YAML, report errors / signature status | `{valid, id, info, errors[]}` |
| `nuclei.workflow.run` | **Run Workflow** | execute a nuclei workflow (207 shipped) | same shape as `scan.run` |

`nuclei.scan.run` is the only action most flows use; the rest exist so a flow —
or an agent — can reason about the catalog instead of guessing at it.

### Meta RPCs

| Method | Backs |
|---|---|
| `nuclei.meta.ping` | settings validation: templates dir present, version, engine version, whether gated classes are enabled |
| `nuclei.meta.profiles` | the profile picker (layer 1) |
| `nuclei.meta.tags` | tag browser, ranked by template count |
| `nuclei.meta.templates.search` | the search-and-patch button (layer 3) |

### Settings profile

The profile is where deployment policy lives — *not* credentials, since nuclei
needs none for its main path. That inverts the usual plugin shape and is worth
stating:

| Key | Why it is profile-level, not node-level |
|---|---|
| `templatesDir`, `customTemplateSources` | which catalog this connection scans with; lets one plugin serve a public catalog and a private one |
| `autoUpdate`, `updateInterval` | operator policy |
| `rateLimit`, `concurrency`, `bulkSize`, `timeout`, `retries`, `maxHostError` | politeness and load, per environment |
| `proxy`, `interactshServer`, `interactshToken` | egress path and OOB server |
| **`allowIntrusive`**, **`allowCodeTemplates`**, **`allowLocalFileAccess`**, **`restrictLocalNetworkAccess`**, **`allowDAST`**, **`allowHeadless`** | the safety gates of §8 — an operator decision, never a canvas-node decision |
| `customHeaders`, `vars` | per-environment auth headers for authenticated scanning |

This matches the plan's rule that the sharp actions are
"gated by an explicit profile flag".

---

## 6. Mapping nuclei onto the Job model

| Nuclei | Inflow |
|---|---|
| target list | `targets[]` in the form, **or** read from context — `job.CmdGetScope("$.assets[*].url")`, or `$this.host` when the node is scoped per asset. This is the single biggest reason this belongs on the canvas rather than in a cron: the target list is produced by the upstream nodes |
| `WithResultCallback(func(*output.ResultEvent))` | `job.Progress(pct, Frame{Title: "[critical] " + id, Content: matchedAt})` — findings appear live |
| scan completion | one `job.Done(map[string]any{...})` |
| `ExecuteCallbackWithCtx(ctx, …)` | `p.OnSignal` → cancel the ctx when `sig.Conclusion.Canceled()` and `sig.JobId` matches |
| exit error | `job.DoneWithErrorData(msg, partialFindings)` — a scan that died at 80% still committed 80% of its value |
| `ResultEvent` | already JSON-tagged and rich: `template-id`, `info{name, severity, tags, description, remediation, reference}`, `classification{cve-id, cwe-id, cvss-score, epss-score, cpe}`, `host`/`port`/`url`/`matched-at`, `extracted-results`, `curl-command`. Commit it close to verbatim — downstream `VULNINTEL` enrichment keys on `cve-id`, and a Rule node branches on `severity` |

Progress arithmetic needs care: nuclei reports findings, not percent-complete.
Derive a percentage from template-index progress via the stats writer
(`UseStatsWriter` / `EnableStatsWithOpts`), or report a coarse 5 → 95 with the
finding count in the frame. Do not fake a smooth bar.

**Caps, per the plan's rule.** `maxFindings` (default ~500, enforced in the
callback), `includeRequestResponse: false` by default (that is the 2 KB), and
`maxDuration` mapped onto the ctx. Report the cap in the closing frame.

---

## 7. State, multi-tenancy, concurrency

Three findings from reading the SDK that a naive implementation gets wrong:

1. **Nuclei's config is a package-level singleton.** `config.DefaultConfig`
   holds the templates directory, version and cache dir process-wide
   (`NUCLEI_CONFIG_DIR`, `SetConfigDir`, `SetStateDir`). Two settings profiles
   pointing at two template directories **cannot** be served by naive
   per-profile engines. Either standardise on one catalog per plugin process
   (simple, and the right v1), or isolate per profile with
   `WithCatalog`/`WithTemporaryDirectory` and treat the global as belonging to
   the default profile. Decide this before writing the client pool.
2. **`ThreadSafeNucleiEngine` re-loads the template store on every
   `ExecuteNucleiWithOptsCtx`** — it shares the catalog, parser and metadata
   index, but calls `store.Load()` per execution. Memory therefore scales with
   **concurrent scans**, not with one shared copy: two full-catalog scans is
   ~1.2 GB, not ~600 MB. The plugin must enforce its own semaphore (1 unfiltered
   scan, N narrow ones) and say so in the frame when a job is queued.
3. **Creating an engine auto-installs and auto-updates templates** unless
   `DisableUpdateCheck()` is passed — the first `NewNucleiEngine` will download
   ~89 MB from GitHub and check the PDCP version endpoint. For a server process
   that must be deliberate: disable it, and drive updates through
   `nuclei.templates.update` (`installer.TemplateManager`) so a flow, not a cold
   start, decides when the catalog moves. Also note the per-execution filter
   subtlety upstream documents in `lib/multi.go`: `WithTemplateFilters` assigns
   a whole filter set and would drop the `.nuclei-ignore` exclusions if the SDK
   did not restore them.

---

## 8. Safety — what must be gated, and why

A scanner node is the first plugin in this catalog whose *normal operation* is
an outbound attack-shaped action. Three distinct risks:

**a) The plugin becomes an SSRF engine.** Targets arrive from flow context. A
node that scans `$this.url` will happily scan `169.254.169.254` or an internal
admin panel. `WithSandboxOptions(allowLocalFileAccess, restrictLocalNetworkAccess)`
maps to `-lfa`/`-lna`; **default to `restrictLocalNetworkAccess: true`** and
require an operator to open it in the settings profile. Consider a
profile-level target allowlist (CIDR/domain) enforced in the plugin before
nuclei ever sees the list — nuclei has `-exclude-hosts`, but a deny-list is the
wrong default for a hosted service.

**b) `code` and `self-contained` templates run shell on the plugin host.** This
is not theoretical — it is how the 304 `code/` and most of the 663 `cloud/`
templates work:

```yaml
# cloud/azure/azure-env.yaml
self-contained: true
code:
  - engine: [sh, bash]
    source: |
      az account show
# digest: 490a0046304402...     ← signature
```

Nuclei's own controls are the right ones: `code` is **off by default**, requires
`EnableCodeTemplates()`, and templates carry a `# digest:` signature verified
against a public key (`SignedTemplatesOnly()` / `-dut` refuse unsigned or
tampered ones). The plugin must keep code templates **off unless the settings
profile enables them**, and should keep `SignedTemplatesOnly` on when they are.
A second consequence: the cloud profiles need `az`/`aws`/`gcloud` installed
**and authenticated on the plugin host**, which puts credentials outside the
settings-profile model — so treat the cloud template families as out of scope
for v1 and revisit with the `AWS`/`AZURE`/`GCP` collectors.

**c) Intrusive template classes.** Nuclei ships `.nuclei-ignore`, excluding
`dos`, `local`, `fuzz`, `bruteforce`, `txt-service` by default. **Never silently
override it.** Surface one `allowIntrusive` profile flag that maps to
`IncludeTags`, and require `allowDAST` for the 251 `dast/` templates (which
mutate parameters) and `allowHeadless` for the 24 headless ones (which need
Chrome on the host). Log, in the node output, which gates were open for a run —
a finding's provenance matters in a report.

And the flat statement that belongs in the README: **this node performs active
scanning against the targets it is given. Authorisation to scan them is the
operator's responsibility.**

---

## 9. Risks and open questions

| Risk | Severity | Mitigation |
|---|---|---|
| OOM from concurrent full-catalog scans | **High** | plugin-side semaphore; `maxTemplates` guard that refuses an unfiltered run unless explicitly confirmed; document a 2 GB floor |
| `lib` API breaks on upgrade | Medium | pin the version; isolate behind `internal/nuclei`; the CLI backend stays an option |
| 150 MB binary / 946-module graph | Medium | it is the price of no external dependency; `go.sum` review at each bump; CI build-size check |
| Plugin process dies mid-scan | Medium | findings stream as progress frames, so partial results are already on the canvas; `DoneWithErrorData` commits what was found |
| A scan being used against out-of-scope targets | **High** | §8a allowlist + the README statement + gates recorded in output |
| Template auto-update changes results between runs | Low | pin the templates version in the settings profile; report the version in every scan's output |

Open, and worth deciding before code:

1. **One catalog per process, or one per settings profile?** (§7.1) — recommend
   one per process for v1.
2. **Is `interactsh` allowed?** OOB detection needs egress to `oast.pro`
   (or a self-hosted server). Some Venapce deployments will forbid it; without
   it a class of findings silently disappears, which the node should say out
   loud rather than under-report.
3. **Where do findings go?** `job.Done` commits them to the flow, but a scan of
   1,000 hosts wants a sink — `CmdSvcCall` to a store, or a downstream
   `DEFECTDOJO`/`CLICKHOUSE` node. The plan already anticipates DefectDojo as a
   sink; the node should not grow its own storage.
4. **Node name** — `NUCLEI`, and no OpenConnector dependency, so **Runs on: any
   host**.

---

## 10. Verdict and next steps

**Feasible, and a genuine quick win** — the plan's own classification holds up.
The plugin is ~6 actions and 4 meta RPCs over an embedded engine; there is no
server to deploy, no credential to broker, and no API to reverse-engineer. The
catalog-size question, which looked like the blocker, is answered by nuclei's
own filter model plus one search RPC.

Suggested order:

1. **Skeleton + `nuclei.templates.select` and `nuclei.meta.*`.** Catalog-only —
   no scanning, no risk — and it proves the index, the profiles, the search
   button and the settings form end to end.
2. **`nuclei.scan.run`** against a lab target, with caps, streaming progress and
   ctx cancellation.
3. **`nuclei.templates.update`, `template.validate`, custom templates.**
4. **Gates and the allowlist** (§8) before anything is pointed at a real estate.
5. **`workflow.run`**, then the catalog entry and listing.

The PoC that established §2 lives in this session's scratch directory, not in
the repo; the first commit should re-create it as `internal/nuclei` with the
`Scanner` interface of §4.

---

**Sources.** [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei)
(MIT) · [`lib/README.md`](https://github.com/projectdiscovery/nuclei/blob/dev/lib/README.md)
and the `lib`, `pkg/catalog/index`, `pkg/installer`, `pkg/output` packages at
`a2b6d2a` · [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
v10.4.9 and its `TEMPLATES-STATS.json` · catalog docs
[concepts](../../../plugin-catalog/docs/concepts.md),
[build-a-plugin](../../../plugin-catalog/docs/build-a-plugin.md),
[dependent-fields](../../../plugin-catalog/docs/dependent-fields.md),
[security-collectors-plan](../../../plugin-catalog/docs/security-collectors-plan.md).
