// Container healthcheck. The runtime image has no curl or wget, so Node probes /readyz itself.
const port = process.env.PORT ?? '3000';

try {
  const res = await fetch(`http://127.0.0.1:${port}/readyz`, { signal: AbortSignal.timeout(2500) });
  process.exit(res.ok ? 0 : 1);
} catch {
  process.exit(1);
}
