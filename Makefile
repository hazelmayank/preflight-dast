PY ?= python
TARGET_PORT ?= 8000

.PHONY: install test lint target data demo demo-live bench clean

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

# The whole loop, offline, against our own synthetic target (about a minute or two).
demo:
	$(PY) -m demo.run_demo

# Same, but keeps the control room up afterwards (Ctrl-C to stop). Add MANUAL=1 to decide in the UI.
demo-live:
	$(PY) -m demo.run_demo --keep-alive $(if $(MANUAL),--manual,)

# Re-score the last run against the ground truth and rewrite docs/BENCHMARKS.md.
bench:
	$(PY) -m bench.score

clean:
	rm -rf out .pytest_cache .ruff_cache
