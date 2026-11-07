.PHONY: setup demo test data detect evaluate up down load
setup:    ; pip install -r requirements.txt
demo:     ; python -m src.cli demo
test:     ; python -m pytest -q
data:     ; python -m src.cli gen-cdr && python -m src.cli gen-iam
detect:   ; python -m src.cli detect-cdr && python -m src.cli detect-iam
evaluate: ; python -m src.cli evaluate
up:       ; docker compose up -d        # needs .env (cp .env.example .env)
down:     ; docker compose down
load:     ; python -m src.pipeline.load_opensearch
