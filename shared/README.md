# shared

Shared type and API contract layer for client and server.

- `schema.ts`: Drizzle schema for `analyses` plus Zod schemas for `AnalysisDetails` and threat intelligence.
- `routes.ts`: typed API routes, request/response schemas, and the `buildUrl` helper.

Use these definitions to keep request shapes and responses consistent across the app.
