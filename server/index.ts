import "dotenv/config";
import express, { type Request, Response, NextFunction } from "express";
import { registerRoutes } from "./routes";
import { serveStatic } from "./static";
import { setupVite } from "./vite";
import { createServer } from "http";
import { reputationService } from "./analysis/reputation";
import { OIDCHandshake } from "./auth/oidc-handshake";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

const app = express();

function requireApiKey(req: express.Request, res: express.Response, next: express.NextFunction) {
  const expected = process.env.API_KEY?.trim();
  if (!expected) return next();

  if (!req.path.startsWith("/api/")) return next();

  const provided = String(req.header("x-api-key") || "").trim();
  if (provided && provided === expected) return next();

  return res.status(401).json({ message: "Unauthorized" });
}

// Production Security Hardening
app.use(helmet({
  contentSecurityPolicy: false, // Disabled for dev convenience with local resources
}));

// API Rate Limiting (Prevent Spam)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: { message: "Too many requests from this IP, please try again after 15 minutes" }
});

app.use("/api/", limiter);
app.use(requireApiKey);

// 🔥 Global OIDC Handshake - Protect all analysis routes
app.use("/api/analyze", (req, res, next) => {
  if (process.env.SSO_HANDSHAKE_ENABLED === "1") {
    return OIDCHandshake.authenticate(req, res, next);
  }
  next();
});

const httpServer = createServer(app);

// Extend IncomingMessage to store raw body
declare module "http" {
  interface IncomingMessage {
    rawBody: unknown;
  }
}

// Middleware to capture raw body (useful for webhooks, signatures, etc.)
app.use(
  express.json({
    verify: (req, _res, buf) => {
      (req as any).rawBody = buf;
    },
  }),
);

app.use(express.urlencoded({ extended: false }));

// Simple logger
export function log(message: string, source = "express") {
  const formattedTime = new Date().toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  });

  console.log(`${formattedTime} [${source}] ${message}`);
}

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      log(`${req.method} ${path} ${res.statusCode} in ${duration}ms`);
    }
  });

  next();
});

(async () => {
  // Initialize Reputation Service (Background Sync)
  reputationService.init().catch(err => {
    console.error("[Startup] ReputationService init failed:", err);
  });

  // Register API routes
  await registerRoutes(httpServer, app);

  // Global error handler
  app.use((err: any, _req: Request, res: Response, next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    console.error("Internal Server Error:", err);

    if (res.headersSent) {
      return next(err);
    }

    return res.status(status).json({ message });
  });

  // Setup frontend serving
  if (app.get("env") === "development") {
    await setupVite(httpServer, app);
  } else {
    serveStatic(app);
  }

  // -------------------------------
  // ✅ FIXED SERVER LISTEN (WINDOWS SAFE)
  // -------------------------------
  const basePort = parseInt(process.env.PORT || "5000", 10);
  let port = basePort;
  const maxAttempts = process.env.PORT ? 1 : 10; // if user explicitly set PORT, don't auto-hop
  const maxPort = basePort + (maxAttempts - 1);

  httpServer.on("error", (err: NodeJS.ErrnoException) => {
    if (err?.code === "EADDRINUSE") {
      if (port < maxPort) {
        const prev = port;
        port += 1;
        console.warn(`[express] port ${prev} in use, trying ${port}...`);
        setTimeout(() => {
          httpServer.listen(port, "127.0.0.1");
        }, 200);
        return;
      }

      console.error(
        `[express] Port ${port} is already in use. Stop the other process or set PORT to a free port.`,
      );
      process.exit(1);
    }

    console.error("[express] Server error:", err);
    process.exit(1);
  });

  httpServer.listen(port, "127.0.0.1", () => {
    log(`serving on http://localhost:${port}`);
  });
})();
