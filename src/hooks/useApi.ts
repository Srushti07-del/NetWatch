/**
 * useApi.ts
 *
 * Generic hook for async API calls with loading / error state.
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
  // Keep a stable reference to fetchFn to avoid unnecessary re-renders
  const fetchRef = useRef(fetchFn);
  fetchRef.current = fetchFn;

  const execute = useCallback(() => {
    setLoading(true);
    setError(null);
    fetchRef
      .current()
      .then((result) => {
        setData(result);
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : 'An error occurred');
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    execute();
  }, [execute]);

  return { data, loading, error, refetch: execute };
}
