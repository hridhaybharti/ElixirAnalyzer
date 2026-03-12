import { analyses, type Analysis, type InsertAnalysis } from "@shared/schema";
import { getDb, hasDatabase } from "./db";
import { desc, eq } from "drizzle-orm";

export interface IStorage {
  createAnalysis(analysis: InsertAnalysis): Promise<Analysis>;
  getHistory(): Promise<Analysis[]>;
  getAnalysis(id: number): Promise<Analysis | undefined>;
  clearHistory(): Promise<void>;
}

export class DatabaseStorage implements IStorage {
  /* =========================
     CREATE
  ========================= */

  async createAnalysis(
    insertAnalysis: InsertAnalysis
  ): Promise<Analysis> {
    const db = await getDb();
    const [analysis] = await db
      .insert(analyses)
      .values(insertAnalysis)
      .returning();

    return analysis;
  }

  /* =========================
     HISTORY
  ========================= */

  async getHistory(): Promise<Analysis[]> {
    const db = await getDb();
    return await db
      .select()
      .from(analyses)
      .orderBy(desc(analyses.createdAt));
  }

  /* =========================
     SINGLE ANALYSIS
  ========================= */

  async getAnalysis(id: number): Promise<Analysis | undefined> {
    const db = await getDb();
    const [analysis] = await db
      .select()
      .from(analyses)
      .where(eq(analyses.id, id));

    return analysis;
  }

  /* =========================
     CLEAR
  ========================= */

  async clearHistory(): Promise<void> {
    const db = await getDb();
    await db.delete(analyses);
  }
}

export class InMemoryStorage implements IStorage {
  private nextId = 1;
  private analyses: Analysis[] = [];

  async createAnalysis(insertAnalysis: InsertAnalysis): Promise<Analysis> {
    const analysis: Analysis = {
      id: this.nextId++,
      type: insertAnalysis.type,
      input: insertAnalysis.input,
      riskScore: insertAnalysis.riskScore,
      riskLevel: insertAnalysis.riskLevel,
      summary: insertAnalysis.summary,
      details: insertAnalysis.details,
      createdAt: new Date(),
      isFavorite: insertAnalysis.isFavorite ?? false,
    };

    this.analyses.unshift(analysis);
    return analysis;
  }

  async getHistory(): Promise<Analysis[]> {
    return [...this.analyses];
  }

  async getAnalysis(id: number): Promise<Analysis | undefined> {
    return this.analyses.find((a) => a.id === id);
  }

  async clearHistory(): Promise<void> {
    this.analyses = [];
  }
}

export const storage: IStorage = hasDatabase
  ? new DatabaseStorage()
  : new InMemoryStorage();
