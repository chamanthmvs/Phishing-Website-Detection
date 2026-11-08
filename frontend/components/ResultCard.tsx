"use client";

import type { ScanResult } from "@/lib/types";
import FeaturesTable from "./FeaturesTable";

interface Props {
  result: ScanResult;
}

export default function ResultCard({ result }: Props) {
  const phishing = result.is_phishing;
  const confidencePct = Math.round(result.confidence * 100);
  const phishingPct = Math.round(result.probabilities.phishing * 100);

  return (
    <section className={`result-card ${phishing ? "is-phishing" : "is-legit"}`} aria-live="polite">
      <div className="result-head">
        <div>
          <div className="result-eyebrow">Scan result</div>
          <div className="result-label">
            <span className="result-icon" aria-hidden="true">
              {phishing ? "⚠" : "✓"}
            </span>
            {result.label}
          </div>
        </div>
        <div className="result-confidence">
          <div className="confidence-value">{confidencePct}%</div>
          <div className="confidence-caption">confidence</div>
        </div>
      </div>

      <div className="prob-meter" role="img" aria-label={`Phishing probability ${phishingPct} percent`}>
        <div className="prob-fill" style={{ width: `${phishingPct}%` }} />
      </div>
      <div className="prob-legend">
        <span>Legitimate {Math.round(result.probabilities.legitimate * 100)}%</span>
        <span>Phishing {phishingPct}%</span>
      </div>

      <div className="result-meta">
        <span className="chip">{result.model_display_name}</span>
        <span className="result-url mono" title={result.url}>
          {result.url}
        </span>
      </div>

      <FeaturesTable features={result.features} />
    </section>
  );
}
