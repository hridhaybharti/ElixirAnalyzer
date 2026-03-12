export class TTLCache<V> {
  private readonly ttlMs: number;
  private readonly maxEntries: number;
  private readonly store = new Map<string, { expiresAt: number; value: V }>();

  constructor(options?: { ttlMs?: number; maxEntries?: number }) {
    this.ttlMs = options?.ttlMs ?? 60 * 60 * 1000;
    this.maxEntries = options?.maxEntries ?? 1000;
  }

  get(key: string): V | undefined {
    const item = this.store.get(key);
    if (!item) return undefined;

    if (Date.now() > item.expiresAt) {
      this.store.delete(key);
      return undefined;
    }

    return item.value;
  }

  set(key: string, value: V, ttlMs?: number): void {
    const expiresAt = Date.now() + (ttlMs ?? this.ttlMs);
    this.store.set(key, { expiresAt, value });
    this.prune();
  }

  private prune() {
    // Remove expired
    const now = Date.now();
    this.store.forEach((v, k) => {
      if (now > v.expiresAt) this.store.delete(k);
    });

    // Enforce max entries (remove oldest)
    while (this.store.size > this.maxEntries) {
      const oldestKey = this.store.keys().next().value as string | undefined;
      if (!oldestKey) break;
      this.store.delete(oldestKey);
    }
  }
}
