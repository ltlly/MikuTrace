PYTHON ?= /usr/bin/python3
PORT   ?= 8765

.PHONY: help test test-fast test-slow webui install-test clean

help:
	@echo "make test       - full pytest run (skips slow if deps missing)"
	@echo "make test-fast  - skip @slow markers (no BN/device/browser)"
	@echo "make test-slow  - only @slow markers"
	@echo "make webui RUN=<trace_dir> [PORT=8765]"
	@echo "make install-test - pip install -e .[test]"
	@echo "make clean      - rm caches"

test:
	$(PYTHON) -m pytest

test-fast:
	$(PYTHON) -m pytest -m "not slow"

test-slow:
	$(PYTHON) -m pytest -m slow

webui:
	@if [ -z "$(RUN)" ]; then echo "usage: make webui RUN=<trace_dir>"; exit 2; fi
	./tracemiku web "$(RUN)" --port $(PORT)

install-test:
	$(PYTHON) -m pip install -e ".[test]"

clean:
	rm -rf .pytest_cache __pycache__ */__pycache__ */*/__pycache__ build dist *.egg-info
