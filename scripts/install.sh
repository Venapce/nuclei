#!/usr/bin/env bash
#
# Install the NUCLEI plugin's dependencies on this machine, then build it.
#
# The plugin embeds the nuclei engine, so every dependency is a build-time Go
# module except one: the template catalog, which is fetched at the end. Nothing
# here needs root, and nothing is installed outside this repository except an
# optional private Go toolchain under ~/.local/share (and the shared Go module
# cache, which is where `go` always puts downloads).
#
# Two things about this dependency graph are not ordinary, and are why a script
# exists at all:
#
#   1. nuclei's module zip is 13 MB and the public proxy serves it unreliably —
#      it has answered 403 and truncated mid-transfer. So this repo carries the
#      module in third_party/goproxy as a file-based GOPROXY, tried FIRST. Its
#      contents are verified against the committed go.sum exactly like a
#      download, so a tampered zip fails the build; it is a cache, not a trust
#      shortcut.
#   2. Building nuclei's graph needs ~4 GB of disk and several minutes.
#
# Usage: scripts/install.sh [options]
#   --no-templates        Skip the template catalog (do it later from the UI)
#   --templates-dir DIR   Install the catalog here instead of the default
#   --go-version X.Y.Z    Toolchain to fetch if Go is missing (default: go.mod's)
#   --skip-env            Do not create .env.inflow from the example
#   -h, --help            Show this help

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="nuclei-plugin"
LOCAL_PROXY="$REPO/third_party/goproxy"

# Go 1.21 is the floor for toolchain switching: an older `go` cannot fetch the
# version go.mod asks for, so it has to be replaced rather than used.
GO_SWITCH_MIN="1.21"
GO_INSTALL_ROOT="${GO_INSTALL_ROOT:-$HOME/.local/share/inflow-go}"

want_templates=1
templates_dir=""
go_version=""
write_env=1

while [ $# -gt 0 ]; do
	case "$1" in
		--no-templates) want_templates=0 ;;
		--templates-dir) templates_dir="${2:?--templates-dir needs a path}"; shift ;;
		--go-version) go_version="${2:?--go-version needs a version}"; shift ;;
		--skip-env) write_env=0 ;;
		-h|--help) sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//; $d'; exit 0 ;;
		*) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
	esac
	shift
done

say()  { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# version_ge A B — true when version A is at least version B.
version_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

# retry N cmd... — network steps here fail intermittently on the public proxy,
# and a retried download is cheap next to a failed install.
retry() {
	local tries="$1" n=1; shift
	until "$@"; do
		if [ "$n" -ge "$tries" ]; then return 1; fi
		warn "'$1' failed (attempt $n/$tries); retrying in $((n * 3))s"
		sleep $((n * 3))
		n=$((n + 1))
	done
}

# ---------------------------------------------------------------- platform ---

case "$(uname -s)" in
	Linux)  os=linux ;;
	Darwin) os=darwin ;;
	*) die "unsupported OS $(uname -s). Build manually with: go build -o $BINARY ." ;;
esac
case "$(uname -m)" in
	x86_64|amd64) arch=amd64 ;;
	arm64|aarch64) arch=arm64 ;;
	*) die "unsupported architecture $(uname -m)" ;;
esac

required_go="$(sed -n 's/^go \([0-9.]*\).*/\1/p' "$REPO/go.mod" | head -1)"
[ -n "$required_go" ] || die "cannot read the required Go version from go.mod"
: "${go_version:=$required_go}"

say "NUCLEI plugin installer — $os/$arch, go.mod wants Go $required_go"

# --------------------------------------------------------------------- git ---

# The direct fallback below clones from VCS, and so does any module the proxy
# cannot serve. Without git those paths simply are not available.
command -v git >/dev/null 2>&1 || die "git is required (install it, then re-run this script)"

# ---------------------------------------------------------------------- go ---

# A toolchain already unpacked by an earlier run is on no PATH but this one's.
if [ -x "$GO_INSTALL_ROOT/go/bin/go" ]; then
	PATH="$GO_INSTALL_ROOT/go/bin:$PATH"
fi
export PATH

install_go() {
	local ver="$1"
	local tarball="go${ver}.${os}-${arch}.tar.gz"
	local url="https://go.dev/dl/${tarball}"
	local tmp
	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' RETURN

	say "fetching Go $ver -> $GO_INSTALL_ROOT"

	# Checksums come from the release index, not from the tarball's neighbour on
	# the same server, so a bad mirror cannot vouch for itself.
	local want
	want="$(curl -fsSL "https://go.dev/dl/?mode=json&include=all" \
		| tr '{' '\n' \
		| grep -F "\"filename\": \"${tarball}\"" \
		| grep -o '"sha256": "[a-f0-9]\{64\}"' \
		| head -1 | cut -d'"' -f4)" || true
	[ -n "$want" ] || die "no published SHA256 for $tarball — check that Go $ver exists for $os/$arch"

	retry 3 curl -fsSL --retry 2 -o "$tmp/$tarball" "$url" || die "cannot download $url"

	local got
	if command -v sha256sum >/dev/null 2>&1; then
		got="$(sha256sum "$tmp/$tarball" | cut -d' ' -f1)"
	else
		got="$(shasum -a 256 "$tmp/$tarball" | cut -d' ' -f1)"
	fi
	[ "$got" = "$want" ] || die "checksum mismatch for $tarball (got $got, want $want)"

	mkdir -p "$GO_INSTALL_ROOT"
	rm -rf "$GO_INSTALL_ROOT/go"
	tar -C "$GO_INSTALL_ROOT" -xzf "$tmp/$tarball"
	PATH="$GO_INSTALL_ROOT/go/bin:$PATH"
	export PATH
	say "Go $ver installed; add this to your shell profile to keep it:"
	printf '      export PATH="%s/go/bin:$PATH"\n' "$GO_INSTALL_ROOT"
}

if command -v go >/dev/null 2>&1; then
	have_go="$(go env GOVERSION 2>/dev/null | sed 's/^go//')"
	if version_ge "$have_go" "$required_go"; then
		say "using Go $have_go ($(command -v go))"
	elif version_ge "$have_go" "$GO_SWITCH_MIN"; then
		# Go >=1.21 reads go.mod's version and fetches that toolchain itself.
		say "Go $have_go found; it will fetch toolchain go$required_go automatically"
		export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"
	else
		warn "Go $have_go is too old to fetch a newer toolchain (needs >= $GO_SWITCH_MIN)"
		install_go "$go_version"
	fi
else
	say "no Go toolchain on PATH"
	install_go "$go_version"
fi

# ----------------------------------------------------------------- modules ---

# A file:// URL cannot carry a space, so a repo under such a path must fall back
# to the network rather than silently building a broken proxy list.
if [ -d "$LOCAL_PROXY" ] && [ "${REPO#* }" = "$REPO" ]; then
	say "using the in-repo module proxy for nuclei, then the public proxy"
	export GOPROXY="file://$LOCAL_PROXY,https://proxy.golang.org,direct"
else
	[ -d "$LOCAL_PROXY" ] && warn "repository path contains a space; skipping the in-repo proxy"
	export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"
fi

# Disk: nuclei's graph is big, and running out mid-build leaves a confusing
# half-populated module cache behind.
avail_kb="$(df -Pk "$(go env GOMODCACHE 2>/dev/null || echo "$HOME")" 2>/dev/null | awk 'NR==2{print $4}')"
if [ -n "${avail_kb:-}" ] && [ "$avail_kb" -lt 4194304 ]; then
	warn "under 4 GB free where the Go module cache lives; this build may not fit"
fi

say "downloading Go modules (~minutes on a cold cache)"
retry 3 go mod download || die "module download failed — see the errors above"

say "verifying module checksums against go.sum"
go mod verify >/dev/null || die "module verification failed; clear the module cache and re-run"

# -------------------------------------------------------------------- build ---

say "building $BINARY (embeds the nuclei engine; ~165 MB, a few minutes)"
( cd "$REPO" && go build -o "$BINARY" . ) || die "build failed"
say "built $REPO/$BINARY"

# ---------------------------------------------------------------------- env ---

if [ "$write_env" -eq 1 ]; then
	if [ -f "$REPO/.env.inflow" ]; then
		say ".env.inflow already present; left untouched"
	else
		cp "$REPO/.env.inflow.example" "$REPO/.env.inflow"
		say "created .env.inflow from the example — fill in PLUGIN_ID, INFRA_CRED, INFRA_URL"
	fi
fi

# ---------------------------------------------------------------- templates ---

if [ "$want_templates" -eq 1 ]; then
	say "installing the nuclei template catalog (runtime dependency)"
	if [ -n "$templates_dir" ]; then
		export NUCLEI_TEMPLATES_DIR="$templates_dir"
	fi
	retry 2 "$REPO/$BINARY" -install-templates || die "template install failed — retry later with: ./$BINARY -install-templates"
else
	say "skipped the template catalog; run './$BINARY -install-templates' or the Update Templates action before the first scan"
fi

# -------------------------------------------------------------------- done ---

cat <<EOF

$(say "done")

  Start the plugin:   cd $REPO && ./$BINARY
  Re-run safely:      scripts/install.sh      (idempotent; .env.inflow is kept)

  The node performs active scanning against whatever targets a flow gives it.
  Authorisation to scan them is yours to establish.
EOF
