# The plugin embeds the nuclei engine, so there is no external `nuclei` binary
# to install — but the module graph has one awkward member: nuclei's own 13 MB
# module zip, which the public Go proxy serves unreliably (it has answered 403
# and truncated mid-transfer). This repo therefore carries that one module in
# third_party/goproxy and puts it FIRST in GOPROXY. go.sum still verifies it, so
# the in-repo copy is a cache, not a trust shortcut.
#
# `make install` is the full first-time path: toolchain, modules, build, and the
# template catalog. The targets below assume Go is already in place.

BINARY  := nuclei-plugin
GO      ?= go
PROXY   := file://$(CURDIR)/third_party/goproxy,https://proxy.golang.org,direct

export GOPROXY = $(PROXY)

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: install
install: ## First-time setup on this machine: deps, build, template catalog
	./scripts/install.sh

.PHONY: deps
deps: ## Download and verify the Go modules
	$(GO) mod download
	$(GO) mod verify

.PHONY: build
build: ## Build the plugin binary (~165 MB; embeds the engine)
	$(GO) build -o $(BINARY) .

.PHONY: templates
templates: build ## Install or update the nuclei template catalog
	./$(BINARY) -install-templates

.PHONY: run
run: build ## Build and run the plugin
	./$(BINARY)

.PHONY: test
test: ## Run the tests
	$(GO) test ./...

.PHONY: vet
vet: ## Vet the code
	$(GO) vet ./...

.PHONY: fmt
fmt: ## Format the Go sources
	gofmt -w $(shell find . -name '*.go' -not -path './third_party/*')

.PHONY: check
check: vet test ## Vet and test

.PHONY: clean
clean: ## Remove the build output (keeps the module cache and the catalog)
	rm -f $(BINARY)
