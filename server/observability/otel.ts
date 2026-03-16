export async function initObservability() {
  if (process.env.OTEL_ENABLED !== '1') return;
  try {
    // Dynamic import to avoid hard dependency when disabled
    const [{ NodeSDK }, { Resource }, { SEMRESATTRS_SERVICE_NAME }, otlp] = await Promise.all([
      import('@opentelemetry/sdk-node' as any),
      import('@opentelemetry/resources' as any),
      import('@opentelemetry/semantic-conventions' as any),
      import('@opentelemetry/exporter-trace-otlp-http' as any).catch(async () => null as any),
    ]);

    const exporter = otlp ? new (otlp as any).OTLPTraceExporter({
      url: process.env.OTEL_EXPORTER_OTLP_ENDPOINT || undefined,
      headers: {},
    }) : undefined;

    const resource = new (Resource as any)({
      [SEMRESATTRS_SERVICE_NAME]: process.env.OTEL_SERVICE_NAME || 'elixir-analyzer',
    });

    const sdk = new (NodeSDK as any)({
      resource,
      traceExporter: exporter,
      // auto-instrumenters can be added here when installed
    } as any);

    await sdk.start();
    console.log('[otel] OpenTelemetry started');
  } catch (e: any) {
    console.warn('[otel] init failed or packages missing:', e?.message || e);
  }
}
