# Project Improvements Log

This document records the state of the **Phishing Website Detection** project
before this round of work, the problems that were found, what was changed, and
why. It is meant to be read alongside the code so anyone reviewing the repository
can understand both *what* the project does and *how it got better*.

**Author:** chamanthmvs

This log has two parts:

- **Revision 1** — correctness, reliability, and reproducibility of the model
  (the original Streamlit app era).
- **Revision 2** — splitting the project into a decoupled **FastAPI backend** +
  **Next.js frontend** and adding a **multi-model comparison**.

---

# Revision 1 — model correctness & reproducibility (2026-11-08)

---

## 1. Summary

The project classifies URLs as *legitimate* or *phishing* using a Random Forest
model behind a Streamlit interface. The core idea was sound, but a detailed
review surfaced several issues that affected **correctness, reliability,
reproducibility, and real-world behavior**. This revision fixes all of them and
adds the engineering scaffolding (tests, pinned dependencies, a reproducible
training pipeline, licensing, and documentation) expected of a portfolio-grade
project.

Headline outcome: the model went from **flagging 6 of 7 well-known legitimate
URLs (GitHub, Wikipedia, Amazon, …) as phishing** to classifying them correctly,
while keeping strong phishing detection — **~90% cross-validated accuracy, 0.96
ROC AUC** — with a pipeline that is now fully offline, deterministic, and tested.

---

## 2. What existed before (baseline)

| Area | Baseline state |
| --- | --- |
| **App** | `app.py` — Streamlit UI with a binary Legitimate/Phishing result. |
| **Features** | `featureExtraction.py` — 13 features, several requiring **live network calls** (WHOIS, DNS, and an Alexa traffic-rank API). |
| **Model** | `RandomForestModel.sav` — a Random Forest **pickled with scikit-learn 0.19.1 (2017)**, loaded at runtime on scikit-learn 1.9.0. |
| **Training** | Only Jupyter notebooks; the runtime depended on manually generated, git-ignored CSVs. |
| **Dependencies** | `requirements.txt` with **no version pins**. |
| **Tests** | None. |
| **License** | None. |
| **Docs** | `README.md` and a GitHub Pages site, with no stated accuracy. |

---

## 3. Problems found (and why they mattered)

### 3.1 Critical

1. **The "Web Traffic" feature was dead.** It called `http://data.alexa.com`,
   an API **Amazon shut down in May 2022**. Every call failed and silently
   returned a constant fallback value, so one of the 13 model inputs carried no
   information — `google.com` and a crafted phishing URL received the identical
   value. The model was effectively running on a degraded input.

2. **Model/library version mismatch.** The model was trained on scikit-learn
   0.19.1 and loaded on 1.9.0. scikit-learn explicitly warns that loading across
   versions *"might lead to invalid results."* The app only loaded at all thanks
   to a fragile custom unpickler shim — a future library release could break it
   entirely.

3. **Unpinned dependencies.** `requirements.txt` listed bare package names. This
   is the *root cause* of problem #2: an unpinned install drifted from the 2017
   library to the 2026 one. `numpy`, used directly by the app, was not even
   listed.

4. **Severe real-world false positives (discovered during testing).** The
   legitimate training URLs were almost entirely short homepages, while the
   phishing URLs had long, deep paths. The model therefore learned *"long URL =
   phishing"* and flagged **6 of 7** common legitimate deep links
   (`github.com/user/repo`, a Wikipedia article, an Amazon product page, a Stack
   Overflow question, …) as phishing. This is a classic dataset-distribution bug
   and would have been glaringly visible in any demo.

### 3.2 Robustness & reliability

5. **Slow, unreliable live lookups.** Each scan performed multiple WHOIS calls,
   a DNS resolution, and the Alexa fetch — several seconds per scan, with
   frequent timeouts. On hosts like Streamlit Community Cloud, outbound WHOIS/DNS
   is commonly blocked, so those features silently collapsed to defaults and
   predictions quietly degraded.

6. **Bare `except:` clauses** throughout feature extraction swallowed *all*
   exceptions (including `KeyboardInterrupt`) and hid real failures.

7. **No prediction confidence** was surfaced, even though Random Forest provides
   calibrated-ish class probabilities.

### 3.3 Engineering hygiene

8. **No tests**, **no license**, **no reproducible training entry point**, and a
   README that stated no measured performance.

---

## 4. What changed

### 4.1 Feature extraction rewritten — lexical and offline

`featureExtraction.py` was rewritten to compute **20 features purely from the URL
string**, with **no network access**. This single decision fixes problems #1, #5,
and #6 at once:

- the dead Alexa call is gone;
- scans are instant, deterministic, and private;
- behavior is identical on a laptop and on a locked-down cloud host;
- every feature is unit-testable.

The feature set is organized into four families:

| Family | Features |
| --- | --- |
| Length | `url_length`, `hostname_length`, `path_length` |
| Composition | `num_dots`, `num_hyphens`, `num_at`, `num_question_marks`, `num_ampersand`, `num_equals`, `num_percent`, `num_digits`, `digit_ratio` |
| Structure | `num_subdomains`, `has_ip`, `has_redirection`, `has_http_token` |
| Reputation heuristics | `is_https`, `has_prefix_suffix`, `has_shortener`, `has_suspicious_word` |

The module now exposes a clean public API (`FEATURE_NAMES`,
`FEATURE_DESCRIPTIONS`, `extract_features`, `features_dataframe`) and keeps the
original `getAttributess` name as a backward-compatible alias.

### 4.2 Reproducible training pipeline

A new `train.py` reads the raw datasets, extracts features, trains the model,
prints a full evaluation report (accuracy, ROC AUC, 5-fold cross-validation,
confusion matrix, feature importances), and writes:

- `RandomForestModel.sav` — **re-trained and re-pickled with the current
  scikit-learn (1.9.0)**, eliminating problem #2 and letting the old unpickler
  shim be deleted entirely;
- `model_metadata.json` — feature layout, metrics, feature importances, and the
  exact training environment.

Training is seeded (`random_state=42`) and fully offline, so results are
reproducible and auditable.

### 4.3 Fixing the false-positive bias with data augmentation

Problem #4 could not be fixed by feature engineering — the training data simply
lacked legitimate *deep links*. A new, seeded generator,
`scripts/generate_legit_deeplinks.py`, produces **545 realistic legitimate deep
links** across well-known domains (news articles, GitHub repos/issues, Wikipedia
pages, Stack Overflow questions, documentation, product pages, videos, profiles,
and search results). These were added as a labeled dataset
(`raw_datasets/legitimate_deeplinks.txt`).

After augmentation, the model can no longer rely on raw length alone and must use
genuine phishing signals (keywords, raw-IP hosts, brand-lookalike hyphens,
shorteners, excessive subdomains). The result:

| Check | Before | After |
| --- | --- | --- |
| Known legitimate URLs misclassified | **6 / 7** | **0 / 9** |
| Known phishing URLs detected | 5 / 5 | **6 / 6** |
| 5-fold CV accuracy | 0.885 | **0.902** |

> Note: the held-out *test accuracy* reads slightly lower after augmentation
> (0.92 → 0.895). That earlier number was **inflated** by the length artifact;
> the post-augmentation model is less accurate on the biased test split but
> dramatically more accurate on real URLs, which is what matters.

### 4.4 App improvements (`app.py`)

- Removed the scikit-learn compatibility shim (no longer needed).
- Loads the model and `model_metadata.json`; shows live **accuracy / ROC AUC /
  CV** metrics in the header.
- Shows a **confidence score** and a progress bar alongside each result
  (fixing #7).
- The extracted-signals table now includes a **plain-English explanation** for
  every feature.
- Passes a named DataFrame to the model so scikit-learn validates the feature
  layout, and adds a clear educational disclaimer.

### 4.5 Dependencies, tests, license

- `requirements.txt` now **pins exact versions** and drops the unused
  `beautifulsoup4` / `python-whois`; `requirements-dev.txt` adds `pytest`
  (fixing #3).
- A `tests/` suite (**27 tests**) covers feature extraction (known inputs →
  expected outputs, edge cases) and the model (loads, correct feature count,
  binary probabilistic output, and a **regression guard** that known-legitimate
  URLs are not flagged and known-phishing URLs are caught) — fixing #8.
- Added an MIT `LICENSE`.

### 4.6 Documentation

- `README.md` rewritten: new feature families, a performance table, offline
  training/testing instructions, and an honest note on the legacy notebooks.
- The GitHub Pages site (`docs/index.html`) updated with the new signal families
  and a live performance band.
- This improvement log added.

---

## 5. Files added / changed / removed

**Added**

- `train.py` — reproducible training + evaluation pipeline
- `model_metadata.json` — generated model metadata & metrics
- `scripts/generate_legit_deeplinks.py` — curated legitimate deep-link generator
- `raw_datasets/legitimate_deeplinks.txt` — 545 augmentation URLs
- `tests/test_features.py`, `tests/test_model.py` — pytest suite
- `requirements-dev.txt` — dev/test dependencies
- `LICENSE` — MIT
- `docs/IMPROVEMENTS.md` — this document

**Changed**

- `featureExtraction.py` — rewritten: 20 lexical, offline, tested features
- `app.py` — confidence score, metrics header, richer signals, shim removed
- `RandomForestModel.sav` — retrained with modern scikit-learn on augmented data
- `requirements.txt` — pinned; unused network deps removed
- `README.md`, `docs/index.html` — updated content and metrics

**Retained (historical)**

- `notebooks/` — original exploratory work (Alexa/WHOIS era), kept for context
  but no longer the source of truth.

---

## 6. Honest limitations & future work

- **Lexical-only by design.** The model never visits the site, so it cannot see
  page content, TLS certificate details, or hosting reputation. It is a fast
  first-pass filter, not a complete verdict.
- **Dataset size and age.** ~2,500 URLs is modest, and phishing tactics evolve.
  A larger, continuously refreshed dataset (e.g. PhishTank + Tranco) would
  improve robustness.
- **Augmentation is template-based.** The generated deep links are realistic but
  synthetic; a sample of *real* legitimate deep links would be stronger still.
- **No probability calibration.** Confidence scores are the forest's raw class
  probabilities; `CalibratedClassifierCV` could make them better calibrated.
- **Possible next steps:** gradient-boosted trees (XGBoost/LightGBM) with the
  same features, SHAP explanations in the UI, and a small CI workflow that runs
  `pytest` on every push.

---

# Revision 2 — API/UI decoupling & model comparison (2026-11-08)

Revision 1 produced a correct, reliable model behind a Streamlit app. Streamlit,
however, couples the UI and the backend in one process. Revision 2 separates them
into two independently deployable services and broadens the modeling.

## 2.1 Goals

1. **No coupling between UI and backend** — the UI must reach the model *only*
   through an HTTP API.
2. **A modern, best-in-class UI** — rebuilt in Next.js (React, TypeScript).
3. **More models** — compare several classifiers and serve the best.

## 2.2 New architecture

```
frontend/ (Next.js)  ──HTTP/JSON──►  backend/ (FastAPI)  ──►  models/*.sav
   no Python, no model, no data          owns features + models
```

- **Backend — FastAPI** (`backend/`): owns `featureExtraction.py`, the trained
  models, and the training pipeline. Endpoints:
  - `GET /api/health` — liveness + models loaded
  - `GET /api/models` — model list with metrics; names the default
  - `POST /api/scan` — classify a URL, optionally choosing a model
  - auto-generated Swagger (`/docs`) and ReDoc (`/redoc`)
  - CORS restricted to the frontend origin (configurable via `ALLOWED_ORIGINS`)
- **Frontend — Next.js 16** (`frontend/`): App Router + TypeScript + React 18. Contains no
  model, no dataset, and no Python. All backend access is isolated in
  `lib/api.ts`; the base URL is injected via `NEXT_PUBLIC_API_BASE_URL`, so the
  same build points at a local or deployed backend. Features a model selector,
  a live performance bar, a confidence meter, and the 20 extracted signals with
  plain-English explanations. Light and dark themes.
- **Streamlit removed** entirely (it violated the decoupling requirement).

## 2.3 Multi-model comparison

`train.py` now trains and compares three classifiers and serves the best as the
default. All are pure scikit-learn — no heavy new dependencies.

| Model | Accuracy | Precision | Recall | F1 | ROC AUC | CV acc |
| --- | --- | --- | --- | --- | --- | --- |
| **Random Forest** (default) | 0.895 | 0.873 | 0.855 | 0.864 | 0.959 | 0.902 |
| Histogram Gradient Boosting | 0.900 | 0.890 | 0.847 | 0.868 | 0.957 | 0.900 |
| Logistic Regression | 0.804 | 0.774 | 0.703 | 0.737 | 0.874 | 0.810 |

The default is chosen automatically (best cross-validated accuracy, tie-broken on
ROC AUC). The API exposes every model, so the UI offers a switcher and the user
can compare verdicts live. Feature importances for the default model are computed
with permutation importance (comparable across model types) and stored in
`models/models_metadata.json`.

**Why these three:** Random Forest and Histogram Gradient Boosting are the
strongest performers on this kind of tabular, lexical data and are
near-identical here; Logistic Regression is included as a fast, interpretable
baseline. Deep learning was deliberately excluded — it adds deployment weight
with no benefit on 20 engineered features.

## 2.4 Repository restructure

```
backend/     app/ (main, registry, schemas), featureExtraction.py, train.py,
             scripts/, models/, raw_datasets/, tests/, requirements*.txt
frontend/    app/, components/, lib/, package.json, tsconfig.json
docs/        GitHub Pages site + this log
notebooks/   historical
```

## 2.5 Tests

The backend test suite grew to cover the new surface:

- feature extraction (unchanged, 11 cases),
- the model **registry** (all models load, binary probabilistic output, unknown
  model raises, known-legit not flagged, known-phishing detected),
- the **API** via FastAPI's `TestClient` (health, model list, scan for
  phishing/legit, explicit model selection, 404 for unknown model, 422 for empty
  URL).

All pass (`python -m pytest` in `backend/`).

## 2.6 Verification performed

- Full backend test suite green.
- Live `uvicorn` server exercised end to end with `curl`: health reports 3
  models; `/api/models` lists them with metrics and the default; `/api/scan`
  returns correct verdicts, confidence, and 20 features; explicit model
  selection works; the CORS preflight for `http://localhost:3000` returns 200.
- **Frontend build-verified** (Next.js 16.4.5, React 18, TypeScript): `npm run
  build` compiles and type-checks cleanly, `npm run lint` passes, and the two
  services were run together — the frontend serves on `:3000`, its built bundle
  carries the correct API base URL, and the exact cross-origin `/api/scan`
  request the browser makes returns a correct verdict.

### Security posture of the frontend

The frontend was pinned to **Next.js 16.4.5** (the current patched release) after
`npm audit` flagged a critical advisory on the initial Next 14.2.x pin.
`npm audit --omit=dev` now reports **0 production vulnerabilities**. The only
remaining advisories are **dev-only** (a moderate `minimatch` ReDoS pulled in
transitively by the `@typescript-eslint` lint toolchain), which never ship to
users. ESLint uses the modern flat config (`eslint.config.mjs`) on ESLint 9.

## 2.7 Deployment notes

- **Backend** deploys as a standard ASGI app (`uvicorn`/`gunicorn`) on any Python
  host; set `ALLOWED_ORIGINS` to the frontend's URL.
- **Frontend** deploys to Vercel or any Node host; set `NEXT_PUBLIC_API_BASE_URL`
  to the deployed backend.
