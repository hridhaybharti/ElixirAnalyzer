import express, { type Express } from "express";
import fs from "fs";
import path from "path";

export function serveStatic(app: Express) {
  const distPath = path.resolve(process.cwd(), "dist/public");
  if (!fs.existsSync(distPath)) {
    console.warn(
      `[static] Client build not found at ${distPath}. API will still run, but the UI will not be served.`,
    );

    app.get("/", (_req, res) => {
      res
        .status(200)
        .type("html")
        .send(
          [
            "<!doctype html>",
            "<html><head><meta charset='utf-8'/>",
            "<meta name='viewport' content='width=device-width, initial-scale=1'/>",
            "<title>Elixir Analyzer</title>",
            "</head><body style='font-family: system-ui, sans-serif; padding: 24px'>",
            "<h1>Elixir Analyzer API is running</h1>",
            "<p>The client UI is not built. Run the client build to serve the dashboard.</p>",
            "<p>API base: <code>/api</code></p>",
            "</body></html>",
          ].join(""),
        );
    });

    return;
  }

  app.use(express.static(distPath));

  // fall through to index.html if the file doesn't exist
  app.use("/{*path}", (_req, res) => {
    res.sendFile(path.resolve(distPath, "index.html"));
  });
}
