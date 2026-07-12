# Product-candidate checks are intentionally separate from the protected,
# pre-Genesis Makefile. Adding this file does not amend or approve the P00.B00
# control plane.
PYTHON ?= python3
GO ?= go
GOFMT ?= gofmt

.PHONY: help build-product test-product race-product vet-product fmt-product \
	fmt-check-product schema-check product-check vendor-check integration-check \
	docs-check license-check docker-build-check

help:
	@echo 'agentapi-doctor product-candidate commands'
	@echo '  make -f Product.mk product-check'
	@echo '  make -f Product.mk build-product'
	@echo '  make -f Product.mk test-product'
	@echo '  make -f Product.mk race-product'
	@echo '  make -f Product.mk schema-check'
	@echo '  make -f Product.mk integration-check'
	@echo '  make -f Product.mk docs-check'
	@echo '  make -f Product.mk license-check'
	@echo '  make -f Product.mk docker-build-check'

build-product:
	$(GO) build ./cmd/doctor ./cmd/registry ./cmd/reference-server \
		./cmd/catalog-check ./cmd/schema-index ./cmd/support-check

test-product:
	$(GO) test ./...

race-product:
	$(GO) test -race ./...

vet-product:
	$(GO) vet ./...

fmt-product:
	$(GO) fmt ./...

fmt-check-product:
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

vendor-check:
	$(GO) mod vendor
	git diff --exit-code -- vendor

docker-build-check:
	@set -eu; \
	prefix=agentapi-doctor:local-check-$$(id -u)-$$$$; \
	doctor="$$prefix-doctor"; registry="$$prefix-registry"; reference="$$prefix-reference"; \
	trap 'docker image rm "$$doctor" "$$registry" "$$reference" >/dev/null 2>&1 || true' EXIT INT TERM; \
	docker build --network=none --target doctor --tag "$$doctor" .; \
	docker build --network=none --target registry --tag "$$registry" .; \
	docker build --network=none --target reference-server --tag "$$reference" .; \
	docker run --rm --network=none --read-only --cap-drop ALL --security-opt no-new-privileges "$$doctor" version --json; \
	docker run --rm --network=none --read-only --cap-drop ALL --security-opt no-new-privileges "$$registry" -h; \
	docker run --rm --network=none --read-only --cap-drop ALL --security-opt no-new-privileges "$$reference" -list-mutants

product-check: schema-check vendor-check fmt-check-product build-product test-product vet-product integration-check docs-check license-check
