"use client";

import type { ModelInfo } from "@/lib/types";

interface Props {
  model?: ModelInfo;
  nSamples?: number;
}

function pct(v?: number) {
  return v != null ? `${(v * 100).toFixed(1)}%` : "—";
}

export default function MetricsBar({ model, nSamples }: Props) {
  if (!model) return null;
  const m = model.metrics;
  const items = [
    { label: "Accuracy", value: pct(m.test_accuracy) },
    { label: "ROC AUC", value: m.test_roc_auc != null ? m.test_roc_auc.toFixed(3) : "—" },
    { label: "CV accuracy", value: pct(m.cv5_accuracy_mean) },
    { label: "Training URLs", value: nSamples != null ? nSamples.toLocaleString() : "—" },
  ];
  return (
    <div className="metrics-bar" aria-label="Model performance">
      {items.map((it) => (
        <div key={it.label} className="metric">
          <div className="metric-value">{it.value}</div>
          <div className="metric-label">{it.label}</div>
        </div>
      ))}
    </div>
  );
}
