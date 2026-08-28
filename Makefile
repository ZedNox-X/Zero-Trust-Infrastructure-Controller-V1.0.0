install:
	pip install -e '.[dev]'
test:
	pytest -q
lint:
	ruff check .
run:
	uvicorn controller.main:app --reload --host 0.0.0.0 --port 8000
compose-up:
	docker compose up --build
compose-down:
	docker compose down -v
