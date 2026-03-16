function esc(v: string) {
  return v.replace(/[\\"\n]/g, (m) => (m === '\\' ? '\\\\' : m === '"' ? '\\"' : '\\n'));
}

export function renderPrometheus(s: any): string {
  const lines: string[] = [];
  // Requests total
  lines.push('# HELP app_requests_total Total API requests');
  lines.push('# TYPE app_requests_total counter');
  lines.push(`app_requests_total ${Number(s?.requests?.total || 0)}`);

  // Requests by code family
  lines.push('# HELP app_requests_code_total Total API requests by status family');
  lines.push('# TYPE app_requests_code_total counter');
  const byCode = s?.requests?.byCode || {};
  for (const code in byCode) {
    lines.push(`app_requests_code_total{code="${esc(code)}"} ${Number(byCode[code] || 0)}`);
  }

  // Requests by route (may be high-cardinality; keep simple)
  const byRoute = s?.requests?.byRoute || {};
  lines.push('# HELP app_requests_route_total Total API requests by route');
  lines.push('# TYPE app_requests_route_total counter');
  for (const route in byRoute) {
    lines.push(`app_requests_route_total{route="${esc(route)}"} ${Number(byRoute[route] || 0)}`);
  }

  // Request latency summary (ms)
  const lat = s?.requests?.latencyMs || { p50: 0, p95: 0, p99: 0 };
  const latDurations = s?._debug?.requestDurations || []; // optional
  const latCount = Array.isArray(latDurations) ? latDurations.length : 0;
  const latSum = Array.isArray(latDurations) ? latDurations.reduce((a: number,b: number)=>a+b,0) : 0;
  lines.push('# HELP app_request_duration_ms Request duration summary in milliseconds');
  lines.push('# TYPE app_request_duration_ms summary');
  lines.push(`app_request_duration_ms{quantile="0.5"} ${Number(lat.p50 || 0)}`);
  lines.push(`app_request_duration_ms{quantile="0.95"} ${Number(lat.p95 || 0)}`);
  lines.push(`app_request_duration_ms{quantile="0.99"} ${Number(lat.p99 || 0)}`);
  lines.push(`app_request_duration_ms_sum ${latSum}`);
  lines.push(`app_request_duration_ms_count ${latCount}`);

  // Egress totals
  lines.push('# HELP app_egress_total Total egress HTTP requests');
  lines.push('# TYPE app_egress_total counter');
  lines.push(`app_egress_total ${Number(s?.egress?.total || 0)}`);

  // Egress by host
  const byHost = s?.egress?.byHost || {};
  lines.push('# HELP app_egress_host_total Total egress by host');
  lines.push('# TYPE app_egress_host_total counter');
  for (const host in byHost) {
    lines.push(`app_egress_host_total{host="${esc(host)}"} ${Number(byHost[host] || 0)}`);
  }

  // Egress latency summary (ms)
  const elat = s?.egress?.latencyMs || { p50: 0, p95: 0, p99: 0 };
  const eLatDurations = s?._debug?.egressDurations || [];
  const eCount = Array.isArray(eLatDurations) ? eLatDurations.length : 0;
  const eSum = Array.isArray(eLatDurations) ? eLatDurations.reduce((a: number,b: number)=>a+b,0) : 0;
  lines.push('# HELP app_egress_duration_ms Egress duration summary in milliseconds');
  lines.push('# TYPE app_egress_duration_ms summary');
  lines.push(`app_egress_duration_ms{quantile="0.5"} ${Number(elat.p50 || 0)}`);
  lines.push(`app_egress_duration_ms{quantile="0.95"} ${Number(elat.p95 || 0)}`);
  lines.push(`app_egress_duration_ms{quantile="0.99"} ${Number(elat.p99 || 0)}`);
  lines.push(`app_egress_duration_ms_sum ${eSum}`);
  lines.push(`app_egress_duration_ms_count ${eCount}`);

  return lines.join('\n') + '\n';
}
