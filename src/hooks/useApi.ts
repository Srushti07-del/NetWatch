/**
 * useApi.ts
 *
 * Generic hook for async API calls with loading / error state.
 *
 * Features:
 *   - Loading state
 *   - Error state
 *   - Successful data retrieval
 *   - Refetch functionality (preserves existing data while reloading)
 *   - Request cancellation via AbortController on supersede & unmount
 *   - Stale-response protection via monotonic request sequencing
 *   - Safe handling of component unmounting (prevents post-unmount updates)
 *   - Dependency-aware refresh (clears stale data when deps/mode change)
 *   - Stable refetch reference (avoids unnecessary re-renders)
 */

import { type DependencyList, useCallback, useEffect, useRef, useState } from 'react';

export interface ApiRequestState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
}

export interface ApiState<T> extends ApiRequestState<T> {
  refetch: () => void;
}

export function isAbortError(err: unknown): boolean {
  if (err instanceof DOMException && err.name === 'AbortError') {
    return true;
  }
  if (err instanceof Error && err.name === 'AbortError') {
    return true;
  }
  return (
    typeof err === 'object' &&
    err !== null &&
    'name' in err &&
    (err as { name?: unknown }).name === 'AbortError'
  );
}

export interface ApiRequestController<T> {
  start: (
    fetcher: (signal: AbortSignal) => Promise<T>,
    options?: { clearData?: boolean },
  ) => Promise<void>;
  dispose: () => void;
  getState: () => ApiRequestState<T>;
}

/**
 * Pure request-lifecycle state machine backing `useApi`.
 * Manages AbortController cancellation, sequence-number stale-response protection,
 * unmount disposal, and refetch vs. dependency-change data handling.
 */
export function createApiRequestController<T>(
  onStateChange: (state: ApiRequestState<T>) => void,
): ApiRequestController<T> {
  let state: ApiRequestState<T> = {
    data: null,
    loading: true,
    error: null,
  };
  let abortController: AbortController | null = null;
  let requestSeq = 0;
  let disposed = false;

  const commit = (next: ApiRequestState<T>) => {
    if (disposed) return;
    if (
      next.data === state.data &&
      next.loading === state.loading &&
      next.error === state.error
    ) {
      return;
    }
    state = next;
    onStateChange(next);
  };

  return {
    start(fetcher, options) {
      if (disposed) {
        return Promise.resolve();
      }

      abortController?.abort();
      const controller = new AbortController();
      abortController = controller;
      const seq = ++requestSeq;

      commit({
        data: options?.clearData ? null : state.data,
        loading: true,
        error: null,
      });

      let promise: Promise<T>;
      try {
        promise = Promise.resolve(fetcher(controller.signal));
      } catch (err: unknown) {
        promise = Promise.reject(err);
      }

      return promise.then(
        (result) => {
          if (disposed || controller.signal.aborted || seq !== requestSeq) {
            return;
          }
          commit({
            data: result,
            loading: false,
            error: null,
          });
        },
        (err: unknown) => {
          if (disposed || seq !== requestSeq) {
            return;
          }
          if (controller.signal.aborted || isAbortError(err)) {
            commit({
              data: state.data,
              loading: false,
              error: state.error,
            });
            return;
          }
          commit({
            data: state.data,
            loading: false,
            error: err instanceof Error ? err.message : 'An error occurred',
          });
        },
      );
    },

    dispose() {
      disposed = true;
      requestSeq++;
      abortController?.abort();
      abortController = null;
    },

    getState() {
      return state;
    },
  };
}

export function useApi<T>(
  fetchFn: (signal: AbortSignal) => Promise<T>,
  deps: DependencyList = [],
): ApiState<T> {
  const [state, setState] = useState<ApiRequestState<T>>({
    data: null,
    loading: true,
    error: null,
  });

  const fetchRef = useRef(fetchFn);
  const controllerRef = useRef<ApiRequestController<T> | null>(null);
  const hasMountedRef = useRef(false);

  // Keep fetchRef in sync with the latest fetchFn (updated in effect, not during render)
  useEffect(() => {
    fetchRef.current = fetchFn;
  }, [fetchFn]);

  useEffect(() => {
    const controller = createApiRequestController<T>((nextState) => {
      setState(nextState);
    });
    controllerRef.current = controller;

    // Clear stale data when dependencies (e.g. mode) change after initial mount;
    // on initial mount data is already null and loading is already true.
    const isDependencyChange = hasMountedRef.current;
    hasMountedRef.current = true;
    void controller.start((signal) => fetchRef.current(signal), {
      clearData: isDependencyChange,
    });

    return () => {
      if (controllerRef.current === controller) {
        controllerRef.current = null;
      }
      controller.dispose();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  const refetch = useCallback(() => {
    void controllerRef.current?.start((signal) => fetchRef.current(signal), {
      clearData: false,
    });
  }, []);

  return { ...state, refetch };
}
