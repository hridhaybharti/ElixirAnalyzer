type Method = string; type Path = string; type Status = number;

class Metrics {
  private reqCount = 0;
  private reqByCode: Record<string, number> = {};
  private reqByRoute: Record<string, number> = {};
  private durations: number[] = [];

  private egressCount = 0;
  private egressByHost: Record<string, number> = {};
  private egressDurations: number[] = [];

  // Email pipeline counters
  private emailTotal = 0;
  private emailSpfPass = 0;
  private emailDkimKeyFound = 0;
  private emailDmarcReject = 0;
  private emailWithAttachments = 0;
  private emailLinksTotal = 0;

  recordRequest(method: Method, path: Path, status: Status, durationMs: number) {
    this.reqCount += 1;
    const codeKey = String(Math.floor(status / 100)) + 'xx';
    this.reqByCode[codeKey] = (this.reqByCode[codeKey] || 0) + 1;
    const routeKey = `${method} ${path.split('?')[0]}`;
    this.reqByRoute[routeKey] = (this.reqByRoute[routeKey] || 0) + 1;
    if (this.durations.length < 5000) this.durations.push(durationMs);
  }

  recordEgress(host: string, status: number, durationMs: number) {
    this.egressCount += 1;
    if (host) this.egressByHost[host] = (this.egressByHost[host] || 0) + 1;
    if (this.egressDurations.length < 5000) this.egressDurations.push(durationMs);
  }

  recordEmail(stats: { spfResult?: string; dkimReason?: string; dmarcPolicy?: string; attachmentCount?: number; linkCount?: number }) {
    this.emailTotal += 1;
    if (stats.spfResult === 'pass') this.emailSpfPass += 1;
    if (stats.dkimReason === 'key-found-not-verified') this.emailDkimKeyFound += 1;
    if (stats.dmarcPolicy === 'reject') this.emailDmarcReject += 1;
    if ((stats.attachmentCount || 0) > 0) this.emailWithAttachments += 1;
    this.emailLinksTotal += (stats.linkCount || 0);
  }

  private quantiles(xs: number[]) {
    if (xs.length === 0) return { p50: 0, p95: 0, p99: 0 };
    const s = [...xs].sort((a, b) => a - b);
    const at = (p: number) => s[Math.min(s.length - 1, Math.floor(p * s.length))];
    return { p50: at(0.5), p95: at(0.95), p99: at(0.99) };
  }

  snapshot() {
    return {
      requests: {
        total: this.reqCount,
        byCode: this.reqByCode,
        byRoute: this.reqByRoute,
        latencyMs: this.quantiles(this.durations),
      },
      egress: {
        total: this.egressCount,
        byHost: this.egressByHost,
        latencyMs: this.quantiles(this.egressDurations),
      },
      email: {
        total: this.emailTotal,
        spfPass: this.emailSpfPass,
        dkimKeyFound: this.emailDkimKeyFound,
        dmarcRejectPolicy: this.emailDmarcReject,
        withAttachments: this.emailWithAttachments,
        linksTotal: this.emailLinksTotal,
      },
      ts: Date.now(),
      _debug: { requestDurations: this.durations, egressDurations: this.egressDurations },
    };
  }
}

export const metrics = new Metrics();
