"use client";

import { useState } from "react";
import type { FeatureValue } from "@/lib/types";

interface Props {
  features: FeatureValue[];
}

function formatValue(v: number): string {
  if (Number.isInteger(v)) return String(v);
  return v.toFixed(4);
}

export default function FeaturesTable({ features }: Props) {
  const [open, setOpen] = useState(false);
  return (
    <div className="features">
      <button
        type="button"
        className="features-toggle"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        <span>{open ? "▾" : "▸"}</span> View the {features.length} extracted signals
      </button>
      {open && (
        <div className="features-table-wrap">
          <table className="features-table">
            <thead>
              <tr>
                <th>Signal</th>
                <th className="num">Value</th>
                <th>What it measures</th>
              </tr>
            </thead>
            <tbody>
              {features.map((f) => (
                <tr key={f.name}>
                  <td className="mono">{f.name}</td>
                  <td className="num mono">{formatValue(f.value)}</td>
                  <td className="muted">{f.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
