/**
 * useApi.ts
 *
 * Generic hook for async API calls with loading / error state.
 *
 * Features:
 *   - Loading state
 *   - Error state
 *   - Successful data retrieval
 *   - Refetch functionality
 *   - Safe handling of component unmounting (aborts in-flight requests)
 *   - Request sequencing (ignores responses from outdated requests)
 *   - Stable refetch reference (avoids unnecessary re-renders)
 */

import { useCallback, useEffect, useRef, useState } from 'react';

interface ApiState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  refetch: () => void;
}

export function useApi<T>(fetchFn: () => Promise<T>): ApiState<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchRef = useRef(fetchFn);
  const abortRef = useRef<AbortController | null>(null);
  const requestSeqRef = useRef(0);

  // Keep fetchRef in sync with the latest fetchFn (updated in effect, not during render)
  useEffect(() => {
    fetchRef.current = fetchFn;
  }, [fetchFn]);

  const execute = useCallback(() => {
    // Cancel any in-flight request before starting a new one
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    const requestSeq = ++requestSeqRef.current;

    setLoading(true);
    setError(null);

    fetchRef.current()
      .then((result) => {
        if (!controller.signal.aborted && requestSeq === requestSeqRef.current) {
          setData(result);
        }
      })
      .catch((err: unknown) => {
        if (!controller.signal.aborted && requestSeq === requestSeqRef.current) {
          if (err instanceof DOMException && err.name === 'AbortError') {
            return;
          }
          setError(err instanceof Error ? err.message : 'An error occurred');
        }
      })
      .finally(() => {
        if (!controller.signal.aborted && requestSeq === requestSeqRef.current) {
          setLoading(false);
        }
      });
  }, []);

  useEffect(() => {
    execute();
    return () => {
      abortRef.current?.abort();
    };
  }, [execute]);

  return { data, loading, error, refetch: execute };
}
