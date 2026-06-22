# Test & quality targets. See TESTING.md for the conventions behind them.
# Tooling is Go-stdlib-first; integration tests boot a local Postgres
# (server binaries auto-discovered under /usr/lib/postgresql/*/bin).

GO ?= go

.PHONY: help
help: ## List available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: fmt
fmt: ## Format all Go code in place
	gofmt -w .

.PHONY: lint
lint: ## Check formatting (no writes) and run go vet
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi
	$(GO) vet ./...

.PHONY: test
test: ## Unit tests (no DB, no external infra)
	$(GO) test ./...

.PHONY: test-integration
test-integration: ## Integration tests — boots an ephemeral local Postgres
	$(GO) test -tags=integration ./...

.PHONY: test-security
test-security: ## Security-acceptance suite: one test per Critical threat ID (the hard gate)
	$(GO) test ./... -run '^TestThreat_' -v

.PHONY: fuzz
fuzz: ## Run fuzz targets briefly (set FUZZTIME to extend)
	$(GO) test ./pkg/validate -run '^$$' -fuzz 'FuzzSubjectToken' -fuzztime $(or $(FUZZTIME),15s)

.PHONY: cover
cover: ## Coverage report (tracked, not enforced)
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1

.PHONY: vuln
vuln: ## Dependency vuln scan (needs: go install golang.org/x/vuln/cmd/govulncheck@latest)
	govulncheck ./...

.PHONY: check
check: lint test test-security ## Pre-push gate: lint + unit + security-acceptance
