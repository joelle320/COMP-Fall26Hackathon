PYTHON ?= .venv/bin/python

.PHONY: setup frontend test demo evaluate serve verify

setup:
	uv sync --locked --extra dev
	cd frontend && npm ci

frontend:
	cd frontend && npm run build

test:
	$(PYTHON) -m pytest

demo:
	$(PYTHON) -m sentinel demo --output work/demo.json

evaluate:
	$(PYTHON) -m sentinel evaluate --output work/evaluation.json

serve:
	$(PYTHON) -m sentinel serve

verify: frontend test demo evaluate
