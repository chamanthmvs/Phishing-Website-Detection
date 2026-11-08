# PhishGuard Frontend (Next.js)

A decoupled Next.js 16 (App Router, TypeScript, React 18) frontend for the
PhishGuard URL scanner. It contains **no model, no data, and no Python** — it
talks to the backend exclusively over its HTTP API.

## Prerequisites

- Node.js 20.9+ (required by Next.js 16)
- The backend API running (see [`../backend/README.md`](../backend/README.md))

## Setup

```bash
cd frontend
npm install
cp .env.local.example .env.local   # point NEXT_PUBLIC_API_BASE_URL at the backend
```

By default the app expects the backend at `http://localhost:8000`.

## Run

```bash
npm run dev      # development server at http://localhost:3000
```

```bash
npm run build && npm run start   # production build
```

## How it talks to the backend

All network access goes through [`lib/api.ts`](lib/api.ts):

- `GET  /api/models` — populate the model selector and performance metrics
- `POST /api/scan`   — classify a URL with the chosen model

The base URL is read from `NEXT_PUBLIC_API_BASE_URL` at build/run time, so the
frontend can point at a local or deployed backend without code changes.

## Structure

```
app/
  layout.tsx        root layout + metadata
  page.tsx          main scanner page (client component)
  globals.css       design system (light + dark)
components/
  ModelSelector.tsx model dropdown
  MetricsBar.tsx    accuracy / AUC / CV / dataset size
  ResultCard.tsx    verdict, confidence meter, probabilities
  FeaturesTable.tsx the 20 extracted signals with explanations
lib/
  api.ts            the only place that calls the backend
  types.ts          response types mirroring the API
```

## Deploy

The frontend deploys cleanly to Vercel (or any Node host). Set
`NEXT_PUBLIC_API_BASE_URL` to the deployed backend URL, and add the frontend's
origin to the backend's `ALLOWED_ORIGINS`.
