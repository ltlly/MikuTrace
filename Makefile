PYTHON ?= uv run python
CARGO  ?= cargo
NPM    ?= npm

# tracemiku_{fork,device,diag}.py 被 tracemiku 模块级（或运行期）导入，
# py_compile 不跟随导入，必须逐个编译。
PY_CHECKS := tracemiku tracemiku_fork.py tracemiku_device.py tracemiku_diag.py \
    tracemiku_transport.py tracemiku_target.py tracemiku_commands.py \
	scripts/build_smoke_trace.py scripts/benchmark_records.py \
	scripts/device_trace_integration.py tools/vm_replay_plan_eval.py \
	examples/llm_cookbook.py scripts/contract_audit.py

HOST_TESTS := tests/host_trace_helpers_test.py tests/host_spawn_flow_test.py \
             tests/host_device_link_test.py tests/host_plugins_transport_test.py

.PHONY: help fmt lint test test-v2 test-fast test-device cli clean test-contract py-compile host-tests

help:
	@echo "make fmt       - rust cargo fmt"
	@echo "make lint      - ruff check (scripts tests tools; uv 不可用时降级 python3 -m ruff)"
	@echo "make test      - full v2 validation"
	@echo "make test-v2   - fmt check + Python compile + host pytest + Rust tests + agent typecheck + format contracts"
	@echo "make test-contract - contract coverage audit + core/CLI + unified entrypoint contract tests (offline)"
	@echo "make test-fast - Python compile + host pytest + Rust core/cli tests"
	@echo "make cli       - build the Rust analysis CLI"
	@echo "make agent     - build tracer/_agent.js (frida agent)"
	@echo "make clean     - rm local caches/build outputs"

fmt:
	cd rust && $(CARGO) fmt

# Frida agent 构建。必须用 lockfile 装依赖并显式走本地 node_modules:
# 缺依赖时 PATH 上的全局 frida-compile 会解析到不匹配的 @types/frida-gum,
# 报出一堆与本仓库无关的 TS 错误。frida 包有 install script, npm 默认会拦,
# 需要 npm rebuild frida 生成 frida_binding.node。
agent:
	cd tracer && npm install
	cd tracer && npm rebuild frida
	cd tracer && npm run build
	@test -s tracer/_agent.js || { echo "tracer/_agent.js 未产出"; exit 1; }
	@echo "agent ok: $$(wc -c < tracer/_agent.js) bytes"

lint:
	@if command -v uv >/dev/null 2>&1; then \
		uv run --extra test ruff check scripts tests tools; \
	else \
		python3 -m ruff check scripts tests tools; \
	fi

py-compile:
	$(PYTHON) -m py_compile $(PY_CHECKS)

host-tests:
	$(PYTHON) -m pytest $(HOST_TESTS) -q

test: test-v2

test-v2: py-compile host-tests
	cd tracer && $(NPM) run typecheck
	cd tracer && node --experimental-strip-types tests/record_contract_test.ts
	cd tracer && node --experimental-strip-types tests/external_writes_contract_test.ts
	cd tracer && node --experimental-strip-types tests/plugins_transport_test.ts
	cd tracer && node --experimental-strip-types tests/agent_lifecycle_test.ts
	cd rust && $(CARGO) fmt --check
	cd rust && $(CARGO) test -p tracemiku-core -- --nocapture
	cd rust && $(CARGO) test -p tracemiku-cli -- --nocapture

test-fast: py-compile host-tests
	cd tracer && node --experimental-strip-types tests/plugins_transport_test.ts
	cd tracer && node --experimental-strip-types tests/agent_lifecycle_test.ts
	cd rust && $(CARGO) test -p tracemiku-core
	cd rust && $(CARGO) test -p tracemiku-cli

cli:
	cd rust && $(CARGO) build -p tracemiku-cli --bin tracemiku-cli

test-contract: cli host-tests
	@echo "=== contract coverage audit ==="
	$(PYTHON) scripts/contract_audit.py
	cd rust && $(CARGO) clippy --workspace --lib -- -D warnings
	cd rust && $(CARGO) run -p tracemiku-cli --bin gen_schemas
	cd rust && $(CARGO) test -p tracemiku-cli
	cd rust && $(CARGO) test -p tracemiku-core
	cd tracer && node --experimental-strip-types tests/record_contract_test.ts
	cd tracer && node --experimental-strip-types tests/external_writes_contract_test.ts
	cd tracer && node --experimental-strip-types tests/plugins_transport_test.ts
	cd tracer && node --experimental-strip-types tests/agent_lifecycle_test.ts

test-device:
	@echo "=== Device integration: cross-compile → push → trace → verify ==="
	$(PYTHON) scripts/device_trace_integration.py

clean:
	rm -rf .pytest_cache __pycache__ */__pycache__ */*/__pycache__ build dist *.egg-info
	rm -rf rust/target/tmp
