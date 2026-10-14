.PHONY: install test run demo clean

install:
	python -m pip install -e ".[dev]"

test:
	pytest -q

run:
	python -m iac_pr_guard --demo

demo:
	python -m iac_pr_guard --demo --format markdown

clean:
	python -m iac_pr_guard --demo clean --format markdown
