# Thin, POSIX-make-compatible wrappers around the versioned phase-gate CLI.
PYTHON ?= python3
PHASEGATE ?= tools/phasegate/main.py
ROOT ?= .

.PHONY: help bootstrap verify test-bootstrap test-protected-verifier state-verify \
	control-plane-verify gate-unit gate gate-all evidence-verify clean-checkout ga-gate \
	protected-chain-replay protected-chain-append

help:
	@echo 'agentapi-doctor bootstrap/control-plane commands'
	@echo '  make bootstrap'
	@echo '  make verify'
	@echo '  make test-bootstrap'
	@echo '  make test-protected-verifier'
	@echo '  make state-verify'
	@echo '  make control-plane-verify'
	@echo '  make gate-unit UNIT=P00.W01 [OUTPUT=path]'
	@echo '  make gate PHASE=P00 [OUTPUT=path]'
	@echo '  make gate-all [OUTPUT=path]'
	@echo '  make evidence-verify PHASE=P00 EVIDENCE=path'
	@echo '  make clean-checkout PHASE=P00 [OUTPUT=path]'
	@echo '  make ga-gate [OUTPUT=path]'
	@echo '  make protected-chain-replay CHAIN=path BOOTSTRAP_REQUEST_COMMIT=sha CHAIN_HEAD=sha256:... WORKFLOW_COMMIT=sha OUTPUT=path'
	@echo '  make protected-chain-append CHAIN=path BUNDLE=path BOOTSTRAP_REQUEST_COMMIT=sha CHAIN_HEAD=sha256:... WORKFLOW_COMMIT=sha OPERATION=... TO_STATE=... PHASE=P00 [WORK_UNIT=P00.W01] OUTPUT=path [BUNDLE_DIGEST=sha256:...]'
	@echo ''
	@echo 'PYTHON, PHASEGATE, and ROOT may be overridden. OUTPUT is passed only when set;'
	@echo 'gate commands therefore do not create evidence by default.'

bootstrap:
	$(PYTHON) $(PHASEGATE) bootstrap --root "$(ROOT)"

verify: bootstrap test-bootstrap

test-bootstrap:
	$(PYTHON) -m unittest discover -s test/bootstrap -p 'test_*.py'

test-protected-verifier:
	$(PYTHON) -m unittest discover -s test/bootstrap -p 'test_protected_verifier.py'

state-verify:
	$(PYTHON) $(PHASEGATE) state-verify --root "$(ROOT)"

control-plane-verify:
	$(PYTHON) $(PHASEGATE) control-plane-verify --root "$(ROOT)"

gate-unit:
	@if test -z "$(UNIT)"; then echo 'UNIT is required (for example UNIT=P00.W01)' >&2; exit 2; fi; \
	set --; \
	if test -n "$(OUTPUT)"; then set -- --output "$(OUTPUT)"; fi; \
	exec $(PYTHON) $(PHASEGATE) gate-unit "$(UNIT)" "$$@" --root "$(ROOT)"

gate:
	@if test -z "$(PHASE)"; then echo 'PHASE is required (for example PHASE=P00)' >&2; exit 2; fi; \
	set --; \
	if test -n "$(OUTPUT)"; then set -- --output "$(OUTPUT)"; fi; \
	exec $(PYTHON) $(PHASEGATE) gate "$(PHASE)" "$$@" --root "$(ROOT)"

gate-all:
	@set --; \
	if test -n "$(OUTPUT)"; then set -- --output "$(OUTPUT)"; fi; \
	exec $(PYTHON) $(PHASEGATE) gate-all "$$@" --root "$(ROOT)"

evidence-verify:
	@if test -z "$(PHASE)"; then echo 'PHASE is required (for example PHASE=P00)' >&2; exit 2; fi; \
	if test -z "$(EVIDENCE)"; then echo 'EVIDENCE is required (path to existing evidence)' >&2; exit 2; fi; \
	exec $(PYTHON) $(PHASEGATE) evidence-verify "$(PHASE)" --evidence "$(EVIDENCE)" --root "$(ROOT)"

clean-checkout:
	@if test -z "$(PHASE)"; then echo 'PHASE is required (for example PHASE=P00)' >&2; exit 2; fi; \
	set --; \
	if test -n "$(OUTPUT)"; then set -- --output "$(OUTPUT)"; fi; \
	exec $(PYTHON) $(PHASEGATE) clean-checkout "$(PHASE)" "$$@" --root "$(ROOT)"

ga-gate:
	@set --; \
	if test -n "$(OUTPUT)"; then set -- --output "$(OUTPUT)"; fi; \
	exec $(PYTHON) $(PHASEGATE) ga-gate "$$@" --root "$(ROOT)"

protected-chain-replay:
	@test -n "$(CHAIN)" || { echo 'CHAIN is required' >&2; exit 2; }; \
	test -n "$(BOOTSTRAP_REQUEST_COMMIT)" || { echo 'BOOTSTRAP_REQUEST_COMMIT is required' >&2; exit 2; }; \
	test -n "$(CHAIN_HEAD)" || { echo 'CHAIN_HEAD is required' >&2; exit 2; }; \
	test -n "$(WORKFLOW_COMMIT)" || { echo 'WORKFLOW_COMMIT is required' >&2; exit 2; }; \
	test -n "$(OUTPUT)" || { echo 'OUTPUT is required' >&2; exit 2; }; \
	exec $(PYTHON) $(PHASEGATE) protected-chain-replay \
		--chain "$(CHAIN)" \
		--bootstrap-request-commit "$(BOOTSTRAP_REQUEST_COMMIT)" \
		--expected-chain-head-digest "$(CHAIN_HEAD)" \
		--current-workflow-execution-commit "$(WORKFLOW_COMMIT)" \
		--output "$(OUTPUT)" --root "$(ROOT)"

protected-chain-append:
	@test -n "$(CHAIN)" || { echo 'CHAIN is required' >&2; exit 2; }; \
	test -n "$(BUNDLE)" || { echo 'BUNDLE is required' >&2; exit 2; }; \
	test -n "$(BOOTSTRAP_REQUEST_COMMIT)" || { echo 'BOOTSTRAP_REQUEST_COMMIT is required' >&2; exit 2; }; \
	test -n "$(CHAIN_HEAD)" || { echo 'CHAIN_HEAD is required' >&2; exit 2; }; \
	test -n "$(WORKFLOW_COMMIT)" || { echo 'WORKFLOW_COMMIT is required' >&2; exit 2; }; \
	test -n "$(OPERATION)" || { echo 'OPERATION is required' >&2; exit 2; }; \
	test -n "$(TO_STATE)" || { echo 'TO_STATE is required' >&2; exit 2; }; \
	phase='$(PHASE)'; test -n "$$phase" || phase=P00; \
	if test "$(OPERATION)" = phase-transition; then \
		test -z "$(WORK_UNIT)" || { echo 'WORK_UNIT must be empty for phase-transition' >&2; exit 2; }; \
	else \
		test -n "$(WORK_UNIT)" || { echo 'WORK_UNIT is required for work-unit operations' >&2; exit 2; }; \
	fi; \
	test -n "$(OUTPUT)" || { echo 'OUTPUT is required' >&2; exit 2; }; \
	set -- --phase "$$phase"; \
	if test -n "$(WORK_UNIT)"; then set -- "$$@" --work-unit "$(WORK_UNIT)"; fi; \
	if test -n "$(BUNDLE_DIGEST)"; then set -- "$$@" --expected-bundle-digest "$(BUNDLE_DIGEST)"; fi; \
	exec $(PYTHON) $(PHASEGATE) protected-chain-append \
		--chain "$(CHAIN)" --bundle "$(BUNDLE)" \
		--bootstrap-request-commit "$(BOOTSTRAP_REQUEST_COMMIT)" \
		--expected-current-chain-head-digest "$(CHAIN_HEAD)" \
		--current-workflow-execution-commit "$(WORKFLOW_COMMIT)" \
		--operation "$(OPERATION)" --to-state "$(TO_STATE)" \
		--output "$(OUTPUT)" \
		$$@ --root "$(ROOT)"
