"use client";

import type { ModelInfo } from "@/lib/types";

interface Props {
  models: ModelInfo[];
  selected: string;
  onChange: (name: string) => void;
  disabled?: boolean;
}

export default function ModelSelector({ models, selected, onChange, disabled }: Props) {
  if (models.length === 0) return null;
  return (
    <label className="field model-field">
      <span className="field-label">Model</span>
      <select
        className="select"
        value={selected}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
      >
        {models.map((m) => (
          <option key={m.name} value={m.name}>
            {m.display_name}
            {m.is_default ? " (best)" : ""}
            {m.metrics.test_accuracy != null
              ? ` · ${(m.metrics.test_accuracy * 100).toFixed(1)}% acc`
              : ""}
          </option>
        ))}
      </select>
    </label>
  );
}
