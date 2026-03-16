import { analyzeInput, type InputType } from "../analysis/analyzeInput";

export type JobStatus = "queued" | "processing" | "completed" | "failed";

export interface AnalysisJob {
  id: string;
  type: InputType;
  input: string;
  status: JobStatus;
  createdAt: number;
  startedAt?: number;
  finishedAt?: number;
  result?: any;
  error?: string;
}

class InMemoryQueue {
  private jobs = new Map<string, AnalysisJob>();
  private queue: string[] = [];
  private running = false;
  private concurrency = 1;

  submit(type: InputType, input: string): AnalysisJob {
    const id = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
    const job: AnalysisJob = {
      id,
      type,
      input,
      status: "queued",
      createdAt: Date.now(),
    };
    this.jobs.set(id, job);
    this.queue.push(id);
    this.kick();
    return job;
  }

  get(id: string): AnalysisJob | undefined {
    return this.jobs.get(id);
  }

  private async kick() {
    if (this.running) return;
    this.running = true;

    try {
      while (this.queue.length > 0) {
        const ids = this.queue.splice(0, this.concurrency);
        await Promise.all(ids.map(async (id) => {
          const job = this.jobs.get(id);
          if (!job) return;
          if (job.status !== "queued") return;

          job.status = "processing";
          job.startedAt = Date.now();
          try {
            const res = await analyzeInput(job.type, job.input);
            job.result = res;
            job.status = "completed";
            job.finishedAt = Date.now();
          } catch (err: any) {
            job.error = err?.message || String(err);
            job.status = "failed";
            job.finishedAt = Date.now();
          }

          // Basic retention: keep only last 500 jobs
          if (this.jobs.size > 600) {
            const removeN = this.jobs.size - 500;
            const all = Array.from(this.jobs.values()).sort((a,b) => (a.createdAt - b.createdAt));
            for (let i = 0; i < removeN; i++) {
              this.jobs.delete(all[i].id);
            }
          }
        }));
      }
    } finally {
      this.running = false;
      // If new jobs arrived during processing, loop again
      if (this.queue.length > 0) this.kick();
    }
  }
}

export const analysisQueue = new InMemoryQueue();
