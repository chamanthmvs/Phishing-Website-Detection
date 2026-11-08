# PhishGuard Backend (FastAPI)

The backend owns feature extraction and the trained models, and exposes a small
JSON API. It is the **only** component that imports scikit-learn or touches the
model files; the frontend communicates with it purely over HTTP.

## Setup

```bash
cd backend
python3 -m venv ../.venv          # or your preferred venv location
source ../.venv/bin/activate
pip install -r requirements.txt
```

## Train the models (reproducible, offline)

```bash
python scripts/generate_legit_deeplinks.py   # optional: regenerate augmentation data
python train.py
```

`train.py` extracts lexical features from `raw_datasets/`, trains three models
(Random Forest, Histogram Gradient Boosting, Logistic Regression), prints a
comparison, and writes each model plus `models/models_metadata.json`. Training is
seeded and needs no network access.

## Run the API

```bash
uvicorn app.main:app --reload --port 8000
```

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

### Endpoints

| Method | Path | Description |
| --- | --- | --- |
| GET | `/api/health` | Liveness and number of models loaded. |
| GET | `/api/models` | Available models with their metrics; names the default. |
| POST | `/api/scan` | Classify a URL. Body: `{ "url": "...", "model": "optional" }`. |

Example:

```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "http://secure-login.paypal.com.verify.tk/webscr"}'
```

### CORS

Allowed frontend origins default to `http://localhost:3000`. Override with the
`ALLOWED_ORIGINS` environment variable (comma-separated).

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest
```

Covers feature extraction, the model registry, and the API endpoints.

## Layout

```
app/
  main.py        FastAPI app, routes, CORS
  registry.py    loads models + metadata, runs predictions
  schemas.py     Pydantic request/response models
featureExtraction.py   lexical feature extraction (source of truth)
train.py               training + evaluation pipeline
scripts/               dataset generation helpers
models/                saved .sav models + models_metadata.json
raw_datasets/          source URL lists
tests/                 pytest suite
```
