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

## Install

On a fresh machine, one command does the whole dependency chain — Go toolchain,
modules, build, template catalog:

```bash
./scripts/install.sh      # or: make install
```

It needs no root, is safe to re-run, and keeps an existing `.env.inflow`.
Options: `--no-templates`, `--templates-dir DIR`, `--go-version X.Y.Z`,
`--skip-env`, `--help`.

What it installs, and why a script is warranted for a plugin whose engine is
embedded:

| Dependency | Handled by |
|---|---|
| Go toolchain (go.mod asks for 1.27.1) | Used if present; Go ≥1.21 fetches the right toolchain itself; otherwise the official tarball is downloaded to `~/.local/share/inflow-go` and **checksum-verified** against the release index. |
| Go modules, incl. the nuclei engine | `go mod download` + `go mod verify`, with retries. |
| nuclei's own module zip | Served from `third_party/goproxy` in this repo — see below. |
| Template catalog (the one runtime dependency) | `./nuclei-plugin -install-templates`. |

### The in-repo module proxy

`third_party/goproxy/` carries one module: `nuclei/v3 v3.11.1` (13 MB), laid out
as a [file-based GOPROXY][goproxy] and tried **before** the network. The public
proxy serves that particular zip unreliably — it has returned `403 Forbidden`
and truncated transfers mid-download, which fails the build with a confusing
error. The committed zip is byte-identical to the proxy's and to a VCS build,
and `go.sum` verifies it on every use, so this is a **cache, not a trust
shortcut**: a tampered zip fails the build. It also means the plugin builds with
no access to the Go proxy at all.

[goproxy]: https://go.dev/ref/mod#goproxy-protocol

To bypass it and resolve everything from upstream:

```bash
GOPROXY=https://proxy.golang.org,direct go build -o nuclei-plugin .
```

Updating the pinned nuclei version means replacing the three files under
`third_party/goproxy/github.com/projectdiscovery/nuclei/v3/@v/` with the new
version's `.info`, `.mod` and `.zip` from the module cache, and bumping `list`.

## Run

```bash
./nuclei-plugin        # or: make run
```

Fill in `PLUGIN_ID`, `INFRA_CRED` and `INFRA_URL` in `.env.inflow` first — the
installer creates it from the example. On FloMorphic, use **Extensions → NUCLEI
→ Install** for the generated one-liner and `./plugin.sh`.

The first scan needs a template catalog. The installer fetches it; otherwise run
**Update Templates** once, `./nuclei-plugin -install-templates`, or point
`templatesDir` in the settings profile at an existing nuclei-templates checkout.
The catalog download reaches `api.github.com` and `github.com`, so a host that
blocks them must use `templatesDir` instead.

## Build notes

- Go 1.27+. The binary embeds the nuclei engine and its dependency graph
  (~165 MB, single file — no external `nuclei` binary required). Building it
  wants roughly 4 GB free for the module and build caches.
- `go.mod` carries **no `replace` directives**: the SDK (`v0.2.8`) and nuclei
  (`v3.11.1`) both resolve as published modules. Do not re-add a local `replace`
  for a dev checkout without removing it again — a replace pointing at a path
  that exists on one machine only is what breaks every other install.

## Test

```bash
go test ./...
go vet ./...
```
