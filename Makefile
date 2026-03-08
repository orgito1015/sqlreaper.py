install:
	pip install -r requirements.txt --break-system-packages

install-dev:
	pip install -r requirements-dev.txt --break-system-packages

test:
	pytest tests/ -v

lint:
	black . --line-length 100
	isort .
	flake8 . --max-line-length 100

run:
	python3 sqlreaper.py

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -name "*.pyc" -delete
