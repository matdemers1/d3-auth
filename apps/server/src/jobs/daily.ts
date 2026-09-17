import type { Logger } from '../log.js';

// Something that happens once a day at a fixed UTC time (T-6.1, T-6.2).
//
// Deliberately small: one process, one timer per job, no persistence. A missed run — the container
// was down at 02:30 — is not replayed; the alert rules notice a backup older than a day and a half,
// which is the failure that matters, whatever caused it.

export interface DailyJob {
  stop(): void;
}

const DAY = 24 * 60 * 60 * 1000;

/** Milliseconds from `now` until the next `HH:MM` UTC. */
export function untilNext(at: string, now = new Date()): number {
  const [hours = 0, minutes = 0] = at.split(':').map(Number);
  const next = new Date(now);
  next.setUTCHours(hours, minutes, 0, 0);
  if (next.getTime() <= now.getTime()) next.setTime(next.getTime() + DAY);
  return next.getTime() - now.getTime();
}

export function scheduleDaily(name: string, at: string, run: () => Promise<unknown>, logger: Logger): DailyJob {
  let timer: NodeJS.Timeout | undefined;
  let running = false;
  const arm = (): void => {
    const wait = untilNext(at);
    logger.info({ job: name, at, inMinutes: Math.round(wait / 60_000) }, 'daily job scheduled');
    timer = setTimeout(() => {
      void (async () => {
        if (running) {
          logger.warn({ job: name }, 'daily job still running from last time; skipping');
        } else {
          running = true;
          try {
            await run();
          } catch (err) {
            // The job records its own failure in the audit trail; this only keeps the timer alive.
            logger.error({ job: name, err }, 'daily job threw');
          } finally {
            running = false;
          }
        }
        arm();
      })();
    }, wait);
    timer.unref();
  };
  arm();
  return {
    stop() {
      if (timer) clearTimeout(timer);
    },
  };
}
