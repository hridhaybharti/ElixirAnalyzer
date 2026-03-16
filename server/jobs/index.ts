import type { InputType } from "../analysis/analyzeInput";
import { analyzeInput } from "../analysis/analyzeInput";

// In-memory fallback implementation (existing behavior)
class InMemoryQueueImpl {
  private jobs = new Map<string, any>();
  private q: string[] = [];
  private running = false;

  submit(type: InputType, input: string) {
    const id = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
    const job = { id, type, input, status: 'queued' as const, createdAt: Date.now() };
    this.jobs.set(id, job);
    this.q.push(id);
    this.kick();
    return job;
  }

  get(id: string) {
    return this.jobs.get(id);
  }

  private async kick() {
    if (this.running) return;
    this.running = true;
    try {
      while (this.q.length > 0) {
        const id = this.q.shift()!;
        const job = this.jobs.get(id);
        if (!job) continue;
        job.status = 'processing';
        job.startedAt = Date.now();
        try {
          job.result = await analyzeInput(job.type, job.input);
          job.status = 'completed';
        } catch (e: any) {
          job.status = 'failed';
          job.error = String(e?.message || e);
        }
        job.finishedAt = Date.now();
      }
    } finally {
      this.running = false;
    }
  }
}

// Attempt BullMQ (Redis-backed) if REDIS_URL is present and module is available
async function createBullQueue() {
  const url = process.env.REDIS_URL || process.env.REDIS_CONNECTION_URL;
  if (!url) return null;
  try {
    // Dynamically import to avoid hard dependency
    const { Queue, Worker, JobsOptions, QueueEvents } = await import('bullmq');
    const connection = { connection: { url } } as any;
    const queue = new Queue('analysis', connection);
    const events = new QueueEvents('analysis', connection);

    new Worker('analysis', async (job: any) => {
      const { type, input } = job.data;
      const result = await analyzeInput(type, input);
      return result;
    }, connection);

    return {
      async submit(type: InputType, input: string) {
        const job = await queue.add('analyze', { type, input } as any, { removeOnComplete: 1000, removeOnFail: 1000 } as any as JobsOptions);
        return { id: job.id, status: 'queued', createdAt: Date.now() };
      },
      async get(id: string) {
        const job = await queue.getJob(id);
        if (!job) return undefined;
        const state = await job.getState();
        const map: any = { waiting: 'queued', delayed: 'queued', active: 'processing', completed: 'completed', failed: 'failed' };
        const status = map[state] || 'queued';
        const base: any = { id: job.id, status, createdAt: job.timestamp, startedAt: job.processedOn, finishedAt: job.finishedOn };
        if (status === 'completed') base.result = await job.returnvalue;
        if (status === 'failed') base.error = job.failedReason || 'failed';
        return base;
      }
    };
  } catch (e) {
    return null;
  }
}

let runtimeQueue: any = null;

export const analysisQueue = {
  async submit(type: InputType, input: string) {
    if (!runtimeQueue) runtimeQueue = (await createBullQueue()) || new InMemoryQueueImpl();
    return runtimeQueue.submit(type, input);
  },
  async get(id: string) {
    if (!runtimeQueue) return undefined;
    return runtimeQueue.get(id);
  }
};
