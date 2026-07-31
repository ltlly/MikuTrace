PYTHON ?= uv run python
CARGO  ?= cargo
NPM    ?= npm
PORT   ?= 18900
PY_CHECKS := tracemiku scripts/frontend_resource_audit.py scripts/frontend_ui_audit.py scripts/frontend_cap_audit.py scripts/frontend_stability_audit.py scripts/frontend_api_client_audit.py scripts/rust_cli_web_parity.py scripts/rust_web_smoke.py scripts/frontend_event_smoke.py scripts/build_smoke_trace.py scripts/device_trace_integration.py tools/vm_replay_plan_eval.py examples/llm_cookbook.py scripts/contract_audit.py

.PHONY: help fmt test test-v2 test-fast test-slow test-device smoke-web smoke-ui webui clean test-contract

help:
	@echo "make fmt       - rust cargo fmt"
	@echo "make test      - full v2 validation"
	@echo "make test-v2   - fmt check + Python wrapper compile + Rust tests + frontend build + CLI/web parity"
	@echo "make test-contract - contract coverage audit + black-box contract tests (fast, no frontend)"
	@echo "make test-fast - Python wrapper compile + Rust core/cli tests"
	@echo "make smoke-web RUN=<trace_dir> [SMOKE_ARGS='--all-surfaces']"
	@echo "make smoke-ui BASE=<url> [UI_SMOKE_ARGS='--browser chromium']"
	@echo "make webui RUN=<trace_dir> [PORT=18900]"
	@echo "make clean     - rm local caches/build outputs"

fmt:
	cd rust && $(CARGO) fmt

test: test-v2

test-v2:
	$(PYTHON) -m py_compile $(PY_CHECKS)
	$(PYTHON) scripts/frontend_resource_audit.py
	$(PYTHON) scripts/frontend_ui_audit.py
	$(PYTHON) scripts/frontend_cap_audit.py
	$(PYTHON) scripts/frontend_stability_audit.py
	$(PYTHON) scripts/frontend_api_client_audit.py
	cd rust && $(CARGO) fmt --check
	cd rust && $(CARGO) test -p tracemiku-core -- --nocapture
	cd rust && $(CARGO) test -p tracemiku-server -- --nocapture
	cd rust && $(CARGO) test -p tracemiku-cli -- --nocapture
	cd frontend && $(NPM) run build
	$(PYTHON) scripts/rust_cli_web_parity.py --debug-bin

test-fast:
	$(PYTHON) -m py_compile $(PY_CHECKS)
	$(PYTHON) -m pytest tests/host_trace_helpers_test.py -q
	$(PYTHON) scripts/frontend_resource_audit.py
	$(PYTHON) scripts/frontend_ui_audit.py
	$(PYTHON) scripts/frontend_cap_audit.py
	$(PYTHON) scripts/frontend_stability_audit.py
	$(PYTHON) scripts/frontend_api_client_audit.py
	cd rust && $(CARGO) test -p tracemiku-core
	cd rust && $(CARGO) test -p tracemiku-cli

test-contract:
	@echo "=== contract coverage audit ==="
	$(PYTHON) scripts/contract_audit.py
	cd rust && $(CARGO) clippy --workspace --lib -- -D warnings
	cd rust && $(CARGO) run -p tracemiku-cli --bin gen_schemas
	cd rust && $(CARGO) test -p tracemiku-cli
	cd rust && $(CARGO) test -p tracemiku-server
	cd rust && $(CARGO) test -p tracemiku-core
	cd tracer && node --experimental-strip-types tests/record_contract_test.ts
	cd tracer && node --experimental-strip-types tests/external_writes_contract_test.ts
	$(PYTHON) scripts/rust_cli_web_parity.py --debug-bin

test-slow:
	@echo "No separate v2 slow suite is defined. Use 'make test-v2'."

test-device:
	@echo "=== Device integration: cross-compile → push → trace → verify ==="
	$(PYTHON) scripts/device_trace_integration.py

smoke-web:
	@if [ -z "$(RUN)" ]; then echo "usage: make smoke-web RUN=<trace_dir> [SMOKE_ARGS='--all-surfaces']"; exit 2; fi
	$(PYTHON) scripts/rust_web_smoke.py "$(RUN)" $(SMOKE_ARGS)

smoke-ui:
	@if [ -z "$(BASE)" ]; then echo "usage: make smoke-ui BASE=<url> [UI_SMOKE_ARGS='--browser chromium']"; exit 2; fi
	$(PYTHON) scripts/frontend_event_smoke.py "$(BASE)" $(UI_SMOKE_ARGS)

webui:
	@if [ -z "$(RUN)" ]; then echo "usage: make webui RUN=<trace_dir>"; exit 2; fi
	./tracemiku web "$(RUN)" --port $(PORT)

clean:
	rm -rf .pytest_cache __pycache__ */__pycache__ */*/__pycache__ build dist *.egg-info
	rm -rf frontend/dist rust/target/tmp
