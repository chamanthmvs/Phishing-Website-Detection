"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { ApiError, fetchModels, scanUrl } from "@/lib/api";
import type { ModelInfo, ModelsResponse, ScanResult } from "@/lib/types";
import ModelSelector from "@/components/ModelSelector";
import MetricsBar from "@/components/MetricsBar";
import ResultCard from "@/components/ResultCard";

const EXAMPLES = [
  "https://github.com/chamanthmvs/Phishing-Website-Detection",
  "http://secure-login.account-verify.paypal.com.update-info.tk/webscr",
  "http://bit.ly/3xYzAbc",
];

export default function Home() {
  const [meta, setMeta] = useState<ModelsResponse | null>(null);
  const [backendError, setBackendError] = useState<string | null>(null);
  const [selectedModel, setSelectedModel] = useState<string>("");

  const [url, setUrl] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    fetchModels(controller.signal)
      .then((res) => {
        setMeta(res);
        setSelectedModel(res.default_model);
        setBackendError(null);
      })
      .catch((err) => {
        if (err?.name === "AbortError") return;
        setBackendError(
          "Could not reach the backend API. Make sure it is running (see the README) and reload.",
        );
      });
    return () => controller.abort();
  }, []);

  const selectedModelInfo: ModelInfo | undefined = useMemo(
    () => meta?.models.find((m) => m.name === selectedModel),
    [meta, selectedModel],
  );

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    const trimmed = url.trim();
    if (!trimmed) {
      setScanError("Enter a URL to scan.");
      return;
    }
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    setLoading(true);
    setScanError(null);
    try {
      const res = await scanUrl(trimmed, selectedModel || undefined, controller.signal);
      setResult(res);
    } catch (err) {
      if ((err as Error)?.name === "AbortError") return;
      const message = err instanceof ApiError ? err.message : "The scan failed. Please try again.";
      setScanError(message);
      setResult(null);
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="page">
      <header className="hero">
        <div className="eyebrow">PhishGuard · URL intelligence</div>
        <h1>Check a link before you trust it.</h1>
        <p className="lede">
          Enter a URL and a machine-learning model scores it from 20 lexical signals —
          read straight from the link text, with no request made to the site itself.
        </p>
      </header>

      {backendError && <div className="banner error">{backendError}</div>}

      {meta && <MetricsBar model={selectedModelInfo} nSamples={meta.n_samples} />}

      <form className="scan-form" onSubmit={onSubmit}>
        <label className="field url-field">
          <span className="field-label">Website URL</span>
          <input
            className="input"
            type="text"
            inputMode="url"
            autoComplete="off"
            placeholder="https://example.com/account"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={!!backendError}
          />
        </label>

        {meta && (
          <ModelSelector
            models={meta.models}
            selected={selectedModel}
            onChange={setSelectedModel}
            disabled={loading || !!backendError}
          />
        )}

        <button className="button" type="submit" disabled={loading || !!backendError}>
          {loading ? "Scanning…" : "Scan URL"}
        </button>
      </form>

      <div className="examples">
        <span className="examples-label">Try:</span>
        {EXAMPLES.map((ex) => (
          <button
            key={ex}
            type="button"
            className="example-chip mono"
            onClick={() => setUrl(ex)}
            disabled={!!backendError}
            title={ex}
          >
            {ex.length > 46 ? ex.slice(0, 46) + "…" : ex}
          </button>
        ))}
      </div>

      {scanError && <div className="banner warn">{scanError}</div>}

      {result && <ResultCard result={result} />}

      <section className="disclaimer">
        This is a heuristic, educational tool. A result is not a guarantee that a site is safe or
        malicious — always use good judgement.
      </section>

      <footer className="footer">
        Built by chamanthmvs · <a href="https://github.com/chamanthmvs/Phishing-Website-Detection">Source on GitHub</a>
      </footer>
    </main>
  );
}
