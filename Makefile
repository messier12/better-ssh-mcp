.PHONY: install test lint check

install:
	uv sync

test:
	uv run pytest --cov=mcp_ssh tests/

lint:
	uv run ruff check mcp_ssh/ && uv run mypy mcp_ssh/

check: lint test
