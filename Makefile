PY ?= python
TARGET_PORT ?= 8000

.PHONY: install test lint target data demo clean

install:
	$(PY) -m pip install -r requirements.txt

test:
	$(PY) -m pytest

lint:
	$(PY) -m ruff check .

target:
	$(PY) -m uvicorn target.app:app --host 127.0.0.1 --port $(TARGET_PORT)

data:
	$(PY) -m target.gen_data

# STUB (Phase 0): the full deploy -> proof -> ticket -> fix -> auto-close loop lands in Phases 1-4.
demo: data
	@echo "make demo is a stub until Phase 4."
	@echo "Phase 0 check: run 'make test' (egress guard, seed isolation, gateway) and 'make target'."

clean:
	rm -rf out .pytest_cache .ruff_cache
