# coding: utf-8
"""Model registry: loads the trained models and runs predictions.

The registry is the single place that knows about the saved ``.sav`` files and
``models_metadata.json``. The API layer talks only to this module, and the
frontend talks only to the API -- so the UI has no dependency on scikit-learn,
the feature code, or the model files.
"""

from __future__ import annotations

import json
import pickle
from functools import lru_cache
from pathlib import Path

import featureExtraction as fe

BACKEND_ROOT = Path(__file__).resolve().parents[1]
MODELS_DIR = BACKEND_ROOT / "models"
METADATA_PATH = MODELS_DIR / "models_metadata.json"


class ModelNotFoundError(KeyError):
    """Raised when a requested model name is not available."""


class Registry:
    def __init__(self) -> None:
        if not METADATA_PATH.exists():
            raise FileNotFoundError(
                f"Missing {METADATA_PATH}. Run `python train.py` first."
            )
        self.metadata: dict = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
        self.feature_names: list[str] = self.metadata["feature_names"]
        self.default_model: str = self.metadata["default_model"]
        self._models: dict[str, object] = {}
        for name in self.metadata["models"]:
            path = MODELS_DIR / f"{name}.sav"
            if path.exists():
                with path.open("rb") as fh:
                    self._models[name] = pickle.load(fh)
        if self.default_model not in self._models and self._models:
            self.default_model = next(iter(self._models))

    # -- introspection ------------------------------------------------------
    @property
    def available(self) -> list[str]:
        return list(self._models.keys())

    def models_info(self) -> list[dict]:
        info = []
        for name in self.available:
            meta = self.metadata["models"][name]
            info.append(
                {
                    "name": name,
                    "display_name": meta.get("display_name", name),
                    "metrics": meta.get("metrics", {}),
                    "is_default": name == self.default_model,
                }
            )
        return info

    def resolve(self, model_name: str | None) -> str:
        if not model_name:
            return self.default_model
        if model_name not in self._models:
            raise ModelNotFoundError(model_name)
        return model_name

    # -- prediction ---------------------------------------------------------
    def predict(self, url: str, model_name: str | None = None) -> dict:
        name = self.resolve(model_name)
        model = self._models[name]
        frame = fe.features_dataframe(url)
        prediction = int(model.predict(frame)[0])
        proba = model.predict_proba(frame)[0]
        confidence = float(proba[prediction])

        descriptions = fe.FEATURE_DESCRIPTIONS
        features = [
            {
                "name": col,
                "value": float(frame.iloc[0][col]),
                "description": descriptions.get(col, ""),
            }
            for col in self.feature_names
        ]

        return {
            "url": url,
            "model": name,
            "model_display_name": self.metadata["models"][name].get("display_name", name),
            "is_phishing": bool(prediction),
            "label": "Phishing" if prediction else "Legitimate",
            "confidence": round(confidence, 4),
            "probabilities": {
                "legitimate": round(float(proba[0]), 4),
                "phishing": round(float(proba[1]), 4),
            },
            "features": features,
        }


@lru_cache(maxsize=1)
def get_registry() -> Registry:
    """Return a process-wide singleton registry (models loaded once)."""
    return Registry()
