# PhishGuard developer Makefile
# Thin wrappers around docker compose.

.PHONY: help env build build-sandbox up down restart logs ps
.PHONY: shell test test-docker test-live clean nuke status mlflow-ui kibana retrain retrain-docker

help:
	@grep -E "^[a-zA-Z_-]+:.*?## .*$$" $(MAKEFILE_LIST) | sort | awk 'BEGIN{FS=":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

env: ## Copy .env.example to .env if missing
	@if [ ! -f .env ]; then cp .env.example .env; echo "Created .env from template"; else echo ".env already exists"; fi

build-sandbox: ## Build the headless browser sandbox
	docker compose --profile build-only build sandbox

build: build-sandbox ## Build all images
	docker compose build

up: ## Start the full stack in the background
	docker compose up -d
	@echo ""
	@echo "PhishGuard stack starting..."
	@echo "  app        -> http://localhost:8000"
	@echo "  dashboard  -> http://localhost:8000/dashboard"
	@echo "  kibana     -> http://localhost:5601"
	@echo "  mlflow     -> http://localhost:5000"
	@echo "  smtp       -> localhost:8025"
	@echo ""
	@echo "Tail logs: make logs"

down: ## Stop the stack
	docker compose down

restart: down up ## Restart the stack

logs: ## Tail logs from all services
	docker compose logs -f --tail=100

logs-app: ## Tail app logs only
	docker compose logs -f --tail=200 app

ps: ## Show service status
	docker compose ps

status: ## Health summary
	@docker compose ps --format "table {{.Service}}\t{{.Status}}\t{{.Ports}}"

shell: ## Open a bash shell in the running app container
	docker compose exec app bash

test: ## Run pytest suite locally
	python3 -m pytest -q

test-docker: ## Run pytest inside the app container
	docker compose exec app python3 -m pytest -q

test-live: ## Run live integration tests (requires API keys / webhooks in .env)
	python3 -m pytest tests/ -v -k _live

mlflow-ui: ## Open MLflow UI
	open http://localhost:5000 || xdg-open http://localhost:5000 || true

kibana: ## Open Kibana UI
	open http://localhost:5601 || xdg-open http://localhost:5601 || true

retrain: ## Retrain the Layer 5 ML classifier locally
	python3 -m scripts.train_layer5

retrain-docker: ## Retrain the Layer 5 ML classifier inside the app container
	docker compose exec app python3 -m scripts.train_layer5

clean: ## Remove stopped containers and dangling images
	docker compose rm -f
	docker image prune -f

nuke: ## Stop AND wipe volumes destructive
	docker compose down -v
