# coding: utf-8
"""Pydantic request/response schemas for the PhishGuard API."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="The URL to scan.")
    model: str | None = Field(
        default=None,
        description="Optional model name; defaults to the server's best model.",
    )


class FeatureValue(BaseModel):
    name: str
    value: float
    description: str


class Probabilities(BaseModel):
    legitimate: float
    phishing: float


class ScanResponse(BaseModel):
    url: str
    model: str
    model_display_name: str
    is_phishing: bool
    label: str
    confidence: float
    probabilities: Probabilities
    features: list[FeatureValue]


class ModelMetrics(BaseModel):
    test_accuracy: float | None = None
    test_precision: float | None = None
    test_recall: float | None = None
    test_f1: float | None = None
    test_roc_auc: float | None = None
    cv5_accuracy_mean: float | None = None
    cv5_accuracy_std: float | None = None
    confusion_matrix: list[list[int]] | None = None


class ModelInfo(BaseModel):
    name: str
    display_name: str
    metrics: ModelMetrics
    is_default: bool


class ModelsResponse(BaseModel):
    default_model: str
    trained_at: str | None = None
    n_samples: int | None = None
    models: list[ModelInfo]


class HealthResponse(BaseModel):
    status: str
    models_loaded: int
    default_model: str
