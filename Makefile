# Thin, POSIX-make-compatible wrappers around the versioned phase-gate CLI.
PYTHON ?= python3
PHASEGATE ?= tools/phasegate/main.py
ROOT ?= .

.PHONY: help bootstrap verify test-bootstrap test-protected-verifier state-verify \
	control-plane-verify gate-unit gate gate-all evidence-verify clean-checkout ga-gate

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
