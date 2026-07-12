PYTHON ?= python3
GO ?= go
GOFMT ?= gofmt

.DEFAULT_GOAL := help

.PHONY: help build test race vet fmt fmt-check schema-check integration-check \
	docs-check license-check vendor-check docker-check check clean

help:
	@echo 'AgentAPI Doctor development commands'
	@echo '  make check          Run the complete local quality gate'
	@echo '  make build          Build all supported commands'
	@echo '  make test           Run all Go tests'
	@echo '  make race           Run all Go tests with the race detector'
	@echo '  make vet            Run go vet'
	@echo '  make fmt            Format Go source'
	@echo '  make fmt-check      Check Go formatting without modifying files'
	@echo '  make schema-check   Validate schemas, catalogs, and support locks'
	@echo '  make integration-check  Run integration and packaging tests'
	@echo '  make docs-check     Check repository-local Markdown links'
	@echo '  make license-check  Validate vendored dependency licenses'
	@echo '  make vendor-check   Verify the committed vendor tree'
	@echo '  make docker-check   Build and smoke hardened images offline'

build:
	$(GO) build ./cmd/doctor ./cmd/registry ./cmd/reference-server \
		./cmd/catalog-check ./cmd/schema-index ./cmd/support-check

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

fmt-check:
	@files="$$(find . -path './vendor' -prune -o -path './dist' -prune -o -type f -name '*.go' -print | sort | xargs $(GOFMT) -l)"; \
	test -z "$$files" || { echo "$$files" >&2; echo 'Go files require gofmt' >&2; exit 1; }

schema-check:
	$(GO) run ./cmd/schema-index --check
	$(GO) run ./cmd/catalog-check --check
	$(GO) run ./cmd/support-check

integration-check:
	$(PYTHON) -m unittest discover -s tools -p 'test_*.py'
	$(PYTHON) -m unittest discover -s integrations/github-action -p 'test_*.py'
	$(PYTHON) -m unittest discover -s integrations/reusable-workflow -p 'test_*.py'
	$(PYTHON) -m unittest discover -s integrations/homebrew -p 'test_*.py'
	$(PYTHON) integrations/homebrew/validate.py
	$(PYTHON) -m unittest discover -s integrations/scoop -p 'test_*.py'
	$(PYTHON) integrations/scoop/validate.py

docs-check:
	$(PYTHON) tools/check_docs.py --root .

license-check:
	$(PYTHON) tools/check_vendor_licenses.py --root .
	$(PYTHON) tools/generate_third_party_notices.py --root . --check

vendor-check:
	$(GO) mod vendor
	git diff --exit-code -- vendor

docker-check:
	@set -eu; \
	prefix=agentapi-doctor:local-check-$$(id -u)-$$$$; \
	doctor="$$prefix-doctor"; registry="$$prefix-registry"; reference="$$prefix-reference"; \
	trap 'docker image rm "$$doctor" "$$registry" "$$reference" >/dev/null 2>&1 || true' EXIT INT TERM; \
	docker build --network=none --target doctor --tag "$$doctor" .; \
	docker build --network=none --target registry --tag "$$registry" .; \
	docker build --network=none --target reference-server --tag "$$reference" .; \
	docker run --rm --network=none --read-only --cap-drop ALL --security-opt no-new-privileges "$$doctor" version --json; \
	docker run --rm --network=none --read-only --cap-drop ALL --security-opt no-new-privileges "$$registry" version; \
	docker run --rm --network=none --read-only --cap-drop ALL --security-opt no-new-privileges "$$reference" -version

check: schema-check vendor-check fmt-check build test vet integration-check docs-check license-check

clean:
	rm -rf bin dist .agentapi
