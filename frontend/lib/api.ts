// Thin API client. The UI talks to the backend ONLY through these functions.

import type { ModelsResponse, ScanResult } from "./types";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/$/, "") ?? "http://localhost:8000";

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function handle<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let detail = `Request failed (${res.status})`;
    try {
      const body = await res.json();
      if (body?.detail) {
        detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
      }
    } catch {
      /* ignore non-JSON error bodies */
    }
    throw new ApiError(detail, res.status);
  }
  return (await res.json()) as T;
}

export async function fetchModels(signal?: AbortSignal): Promise<ModelsResponse> {
  const res = await fetch(`${API_BASE_URL}/api/models`, { signal });
  return handle<ModelsResponse>(res);
}

export async function scanUrl(
  url: string,
  model?: string,
  signal?: AbortSignal,
): Promise<ScanResult> {
  const res = await fetch(`${API_BASE_URL}/api/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, model: model ?? null }),
    signal,
  });
  return handle<ScanResult>(res);
}

export { API_BASE_URL };
