import "dotenv/config";
import * as schema from "@shared/schema";

export const hasDatabase =
  !!process.env.DATABASE_URL && process.env.USE_INMEMORY_STORAGE !== "1";

let cachedPool: any | null = null;
let cachedDb: any | null = null;

export async function getDb() {
  if (!hasDatabase) {
    throw new Error(
      "Database is disabled. Set DATABASE_URL (PostgreSQL) or enable in-memory storage with USE_INMEMORY_STORAGE=1.",
    );
  }

  if (cachedDb) return cachedDb;

  const [{ drizzle }, pg] = await Promise.all([
    import("drizzle-orm/node-postgres"),
    import("pg"),
  ]);

  const Pool = (pg as any).Pool ?? (pg as any).default?.Pool;
  if (!Pool) {
    throw new Error("Failed to load pg Pool");
  }

  cachedPool = new Pool({ connectionString: process.env.DATABASE_URL });
  cachedDb = drizzle(cachedPool, { schema });

  return cachedDb;
}

