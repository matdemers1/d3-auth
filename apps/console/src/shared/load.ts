import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiError } from '../api';

// What a page knows about the data it asked for (Page states pattern).
//
// A refusal and a failure are different answers and get different screens: 403 means the server
// understood and said no, so the page says who can say yes; anything else means nothing is known,
// so the page says what failed and offers to try again. Treating every failure as "no access"
// told an owner whose network blinked that the keys were not theirs.

export type Loaded<T> =
  | { status: 'loading' }
  | { status: 'ready'; data: T }
  | { status: 'denied' }
  | { status: 'failed'; message: string };

export const failureOf = (err: unknown): Loaded<never> =>
  err instanceof ApiError && err.status === 403
    ? { status: 'denied' }
    : { status: 'failed', message: err instanceof ApiError ? err.message : 'The console could not reach the server.' };

/**
 * Loads once on mount (and again when `key` changes). `reload` fetches in the background and keeps
 * what is on screen until the answer arrives, so acting on a row does not flash the page back to
 * skeletons. `retry` is the error state's *Try again*, and does show the skeleton, because there is
 * nothing on screen to keep.
 */
export function useLoad<T>(fetcher: () => Promise<T>, key = ''): { state: Loaded<T>; reload: () => void; retry: () => void } {
  const [state, setState] = useState<Loaded<T>>({ status: 'loading' });
  const latest = useRef(fetcher);
  latest.current = fetcher;

  const run = useCallback((showLoading: boolean) => {
    if (showLoading) setState({ status: 'loading' });
    latest
      .current()
      .then((data) => {
        setState({ status: 'ready', data });
      })
      .catch((err: unknown) => {
        setState((current) => (current.status === 'ready' && !showLoading ? current : failureOf(err)));
      });
  }, []);

  useEffect(() => {
    run(true);
  }, [run, key]);

  return { state, reload: useCallback(() => { run(false); }, [run]), retry: useCallback(() => { run(true); }, [run]) };
}

/** The server's own words when it gave some, and a plain sentence when it did not. */
export const messageOf = (err: unknown, fallback = 'That did not work. Try again.'): string =>
  err instanceof ApiError ? err.message : fallback;
