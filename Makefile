PYTHON ?= uv run python
CARGO  ?= cargo
NPM    ?= npm
PORT   ?= 18900

.PHONY: help fmt test test-v2 test-fast test-slow smoke-web webui clean

help:
	@echo "make fmt       - rust cargo fmt"
	@echo "make test      - full v2 validation"
	@echo "make test-v2   - fmt check + Python wrapper compile + Rust tests + frontend build + CLI/web parity"
	@echo "make test-fast - Python wrapper compile + Rust core/cli tests"
	@echo "make smoke-web RUN=<trace_dir> [SMOKE_ARGS='--all-surfaces']"
	@echo "make webui RUN=<trace_dir> [PORT=18900]"
	@echo "make clean     - rm local caches/build outputs"

fmt:
	cd rust && $(CARGO) fmt

test: test-v2

test-v2:
	$(PYTHON) -m py_compile tracemiku
	cd rust && $(CARGO) fmt --check
	cd rust && $(CARGO) test -p tracemiku-core -- --nocapture
	cd rust && $(CARGO) test -p tracemiku-server -- --nocapture
	cd rust && $(CARGO) test -p tracemiku-cli -- --nocapture
	cd frontend && $(NPM) run build
	$(PYTHON) scripts/rust_cli_web_parity.py --debug-bin

test-fast:
	$(PYTHON) -m py_compile tracemiku
	cd rust && $(CARGO) test -p tracemiku-core
	cd rust && $(CARGO) test -p tracemiku-cli

test-slow:
	@echo "No separate v2 slow suite is defined. Use 'make test-v2'."

smoke-web:
	@if [ -z "$(RUN)" ]; then echo "usage: make smoke-web RUN=<trace_dir> [SMOKE_ARGS='--all-surfaces']"; exit 2; fi
	$(PYTHON) scripts/rust_web_smoke.py "$(RUN)" $(SMOKE_ARGS)

webui:
	@if [ -z "$(RUN)" ]; then echo "usage: make webui RUN=<trace_dir>"; exit 2; fi
	./tracemiku web "$(RUN)" --port $(PORT)

clean:
	rm -rf .pytest_cache __pycache__ */__pycache__ */*/__pycache__ build dist *.egg-info
	rm -rf frontend/dist rust/target/tmp
