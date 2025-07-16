.PHONY: help venv install run test clean all

all: install run

help:
	@echo "Available commands:"
	@echo "  make venv       - Create virtualenv (.venv)"
	@echo "  make install    - Install dependencies from requirements.txt"
	@echo "  make run        - Run backend API with uvicorn"
	@echo "  make test       - Run test script"
	@echo "  make clean      - Remove virtualenv and __pycache__"

venv:
	python3 -m venv .venv

install:
	. .venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt

run:
	. .venv/bin/activate && uvicorn backend.app.api.endpoints:app --reload

test:
	. .venv/bin/activate && python tests/test_api.py

clean:
	rm -rf .venv
	find . -type d -name "__pycache__" -exec rm -rf {} +
