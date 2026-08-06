.PHONY: install run test lint format docker-build

install:
	python -m pip install -r requirements.txt

run:
	python run.py

test:
	pytest

lint:
	ruff check .

format:
	ruff format .

docker-build:
	docker build -t digiscope:local .
