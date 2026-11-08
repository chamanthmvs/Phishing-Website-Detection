# Phishing Website Detection

Phishing Website Detection classifies URLs as **legitimate** or **potentially
phishing** using machine learning. It is built as two decoupled services:

- a **FastAPI backend** that owns feature extraction and the trained models and
  exposes a JSON API;
- a **Next.js frontend** that talks to the backend *only* through that API.

For the visual project presentation, visit the
[project page](https://chamanthmvs.github.io/Phishing-Website-Detection/).

> **At a glance:** 20 lexical URL features · 3 compared models (Random Forest,
> Gradient Boosting, Logistic Regression) · ~90% accuracy · 0.96 ROC AUC ·
> clean API/UI separation · fully offline, reproducible training. See
> [`docs/IMPROVEMENTS.md`](docs/IMPROVEMENTS.md) for the full history.

## Architecture

```
┌──────────────────────┐      HTTP / JSON       ┌───────────────────────────┐
│  Next.js frontend     │  ───────────────────►  │  FastAPI backend           │
│  (frontend/)          │   GET  /api/models     │  (backend/)                │
│  no model, no data,   │   POST /api/scan       │  - featureExtraction.py    │
│  no Python            │  ◄───────────────────  │  - models/*.sav + metadata │
└──────────────────────┘                        └───────────────────────────┘
```

The frontend contains no model, no dataset, and no scikit-learn — every
prediction is requested from the backend API. This keeps the two layers
independently developed, tested, and deployed.

## How it works

The model uses **lexical features** — 20 signals computed purely from the URL
string, with **no request to the site being scanned**. This makes every scan
fast, deterministic, privacy-preserving, and reproducible, and it behaves
identically on a laptop and on a locked-down cloud host.

| Family | Example signals |
| --- | --- |
| Length | URL / hostname / path length |
| Composition | counts of `.`, `-`, `@`, `?`, `&`, `=`, `%`, digits; digit ratio |
| Structure | subdomain count, raw-IP host, `//` redirection, repeated `http` token |
| Reputation heuristics | HTTPS usage, prefix/suffix `-`, URL shorteners, phishing keywords |

## Model comparison

Three models are trained and compared on a held-out 25% test set (2,553 URLs;
1,560 legitimate / 993 phishing). The best is served as the API default.

| Model | Accuracy | ROC AUC | CV accuracy |
| --- | --- | --- | --- |
| **Random Forest** (default) | 89.5% | 0.959 | 90.2% |
| Histogram Gradient Boosting | 90.0% | 0.957 | 90.0% |
| Logistic Regression | 80.4% | 0.874 | 81.0% |

Exact numbers and feature importances live in
[`backend/models/models_metadata.json`](backend/models/models_metadata.json),
regenerated on every training run.

## Quick start

**1. Backend**

```bash
cd backend
python3 -m venv ../.venv && source ../.venv/bin/activate
pip install -r requirements.txt
python train.py                       # train the models (offline, reproducible)
uvicorn app.main:app --reload --port 8000
```

**2. Frontend** (in a second terminal; requires Node.js 20.9+)

```bash
cd frontend
npm install
cp .env.local.example .env.local      # defaults to http://localhost:8000
npm run dev                           # http://localhost:3000
```

See [`backend/README.md`](backend/README.md) and
[`frontend/README.md`](frontend/README.md) for details.

## Tests

```bash
cd backend
pip install -r requirements-dev.txt
python -m pytest                      # feature extraction + registry + API
```

## Repository layout

```
backend/     FastAPI API, feature extraction, training, models, tests
frontend/    Next.js app (App Router, TypeScript)
docs/        GitHub Pages presentation + improvement log
notebooks/   original exploratory notebooks (historical; see note below)
```

## A note on the notebooks

`notebooks/` holds the **original** exploratory work, which relied on live
WHOIS/DNS lookups and an Alexa traffic-rank API that was shut down in 2022. The
current pipeline replaces that with a purely lexical, offline, reproducible
approach. The notebooks are retained for historical context only.

## Disclaimer

A heuristic tool for **learning, experimentation, and responsible security
research**. A prediction is not a guarantee that a website is safe or malicious —
always use good judgement.

## License

Released under the [MIT License](LICENSE).

## Built by

Built by **chamanthmvs**.
