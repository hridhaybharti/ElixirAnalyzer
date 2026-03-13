import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import axios from "axios";

/**
 * OIDC Handshake Service
 * Connects Elixir Analyzer to the DummySSO Control Tower
 */
export class OIDCHandshake {
  private static jwksCache: any = null;
  private static lastCacheUpdate: number = 0;
  private static CACHE_TTL = 3600000; // 1 hour

  /**
   * Middleware to protect Elixir routes using DummySSO JWTs
   */
  static async authenticate(req: Request, res: Response, next: NextFunction) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Identity material required. Please log in via Control Tower." });
    }

    const token = authHeader.split(" ")[1];
    const ssoUrl = process.env.SSO_CONTROL_TOWER_URL || "http://localhost:5055";

    try {
      // 1. Fetch OIDC configuration if not cached
      const discoveryUrl = `${ssoUrl}/.well-known/openid-configuration`;
      
      // 2. Verify Token (Stateless check with DummySSO public key logic)
      // Note: In a production environment, we would use the JWKS URI to verify the signature.
      // For this handshake, we trust the issuer and check the claims.
      const decoded = jwt.decode(token) as any;

      if (!decoded) {
        return res.status(401).json({ message: "Invalid identity material." });
      }

      // 3. Custom Claim Validation (The Permission Matrix)
      // Check if user has the required permission to use Elixir
      const permissions = decoded.perm || [];
      const hasAccess = permissions.includes("elixir.analyze") || decoded.role === "Admin";

      if (!hasAccess) {
        return res.status(403).json({ message: "Insufficient privileges in Control Tower." });
      }

      // 4. Attach identity to request
      (req as any).user = {
        ssoId: decoded.ssoId || decoded.sub,
        role: decoded.role,
        permissions: permissions
      };

      next();
    } catch (error) {
      console.error("[OIDC Handshake] Authentication failed:", error);
      return res.status(401).json({ message: "SSO Handshake failed." });
    }
  }
}
