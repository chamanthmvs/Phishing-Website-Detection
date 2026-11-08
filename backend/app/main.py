# coding: utf-8
"""PhishGuard FastAPI backend.

Exposes a small JSON API that owns the model(s) and feature extraction. The
frontend communicates only through these endpoints.

Endpoints
---------
- ``GET  /api/health``  : liveness + how many models are loaded.
- ``GET  /api/models``  : the available models and their metrics.
- ``POST /api/scan``    : classify a URL (optionally choosing a model).

Interactive docs are served at ``/docs`` (Swagger) and ``/redoc``.
"""

from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .registry import ModelNotFoundError, get_registry
from .schemas import (
    HealthResponse,
    ModelsResponse,
    ScanRequest,
    ScanResponse,
)

app = FastAPI(
    title="PhishGuard API",
    description="URL phishing detection via lexical features and tree-based models.",
    version="2.0.0",
)

# CORS: the Next.js frontend runs on a different origin. Allowed origins can be
# overridden with the ALLOWED_ORIGINS env var (comma-separated).
_default_origins = "http://localhost:3000,http://127.0.0.1:3000"
_origins = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", _default_origins).split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.get("/api/health", response_model=HealthResponse, tags=["meta"])
def health() -> HealthResponse:
    reg = get_registry()
    return HealthResponse(
        status="ok",
        models_loaded=len(reg.available),
        default_model=reg.default_model,
    )


@app.get("/api/models", response_model=ModelsResponse, tags=["meta"])
def list_models() -> ModelsResponse:
    reg = get_registry()
    return ModelsResponse(
        default_model=reg.default_model,
        trained_at=reg.metadata.get("trained_at"),
        n_samples=reg.metadata.get("n_samples"),
        models=reg.models_info(),
    )


@app.post("/api/scan", response_model=ScanResponse, tags=["scan"])
def scan(request: ScanRequest) -> ScanResponse:
    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=422, detail="URL must not be empty.")
    reg = get_registry()
    try:
        result = reg.predict(url, request.model)
    except ModelNotFoundError:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown model '{request.model}'. Available: {reg.available}",
        )
    except Exception as error:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Could not scan URL: {error}")
    return ScanResponse(**result)


@app.get("/", include_in_schema=False)
def root() -> dict:
    return {"name": "PhishGuard API", "docs": "/docs", "health": "/api/health"}
