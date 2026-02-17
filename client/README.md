# client (React UI)

Vite-powered React frontend for submitting analyses, viewing results, and history.

## Entry points

- `src/main.tsx`: React root and app bootstrap.
- `src/App.tsx`: router and layout.

## Pages

- `Dashboard.tsx`: input form and summary widgets.
- `AnalysisResult.tsx`: detailed risk and threat intelligence view.
- `History.tsx`: list of past analyses.
- `not-found.tsx`: fallback route.

## Key subfolders

- `src/components/`: shared UI components (Header, RiskGauge, HeuristicList, etc.).
- `src/components/ui/`: Radix-based UI primitives and shadcn-style components.
- `src/hooks/`: data fetching and UI helpers (`use-analysis`, `use-toast`, `use-mobile`).
- `src/lib/`: query client setup, input detection, and utilities.
- `public/`: static assets.

## Data flow

- Calls API routes defined in `shared/routes.ts`.
- Response shapes align with `shared/schema.ts`.

## Styling and build

- Tailwind styles live in `src/index.css`.
- Vite root is `client/` and builds to `dist/public`.
