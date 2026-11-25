import test from 'node:test';
import assert from 'node:assert/strict';
import { createApiRequestController, isAbortError } from './useApi.ts';

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

test('1. Pending request is aborted when superseded by a newer request', async () => {
  const states = [];
  const controller = createApiRequestController((s) => states.push(s));

  const signals = [];
  const d1 = deferred();
  const d2 = deferred();

  const p1 = controller.start((signal) => {
    signals.push(signal);
    return d1.promise;
  });

  assert.equal(signals.length, 1);
  assert.equal(signals[0].aborted, false);

  const p2 = controller.start((signal) => {
    signals.push(signal);
    return d2.promise;
  });

  assert.equal(signals.length, 2);
  assert.equal(signals[0].aborted, true);
  assert.equal(signals[1].aborted, false);

  d2.resolve('second');
  await p2;
  d1.reject(new DOMException('Aborted', 'AbortError'));
  await p1;

  assert.deepEqual(controller.getState(), {
    data: 'second',
    loading: false,
    error: null,
  });
});

test('2. Pending request is aborted on unmount (dispose) and prevents post-unmount updates', async () => {
  const states = [];
  const controller = createApiRequestController((s) => states.push(s));

  let capturedSignal;
  const d = deferred();

  const p = controller.start((signal) => {
    capturedSignal = signal;
    return d.promise;
  });

  assert.equal(capturedSignal?.aborted, false);
  const stateCountBeforeDispose = states.length;

  controller.dispose();
  assert.equal(capturedSignal?.aborted, true);

  d.resolve('late-data');
  await p;

  assert.equal(states.length, stateCountBeforeDispose);
});

test('3. Older request resolving after a newer request does not overwrite newer data', async () => {
  const controller = createApiRequestController(() => {});

  // Intentionally ignore AbortSignal in the older request to verify sequence protection
  const d1 = deferred();
  const d2 = deferred();

  const p1 = controller.start(() => d1.promise);
  const p2 = controller.start(() => d2.promise);

  d2.resolve('newer-data');
  await p2;

  assert.equal(controller.getState().data, 'newer-data');
  assert.equal(controller.getState().loading, false);

  d1.resolve('stale-older-data');
  await p1;

  assert.deepEqual(controller.getState(), {
    data: 'newer-data',
    loading: false,
    error: null,
  });
});

test('4. Older request failing after a newer request succeeds does not replace successful state', async () => {
  const controller = createApiRequestController(() => {});

  const d1 = deferred();
  const d2 = deferred();

  const p1 = controller.start(() => d1.promise);
  const p2 = controller.start(() => d2.promise);

  d2.resolve('ok');
  await p2;

  d1.reject(new Error('late network error'));
  await p1;

  assert.deepEqual(controller.getState(), {
    data: 'ok',
    loading: false,
    error: null,
  });
});

test('5. Aborted request does not produce an ordinary error state or stay loading', async () => {
  const controller = createApiRequestController(() => {});

  await controller.start(() =>
    Promise.reject(new DOMException('The user aborted a request.', 'AbortError')),
  );
  assert.deepEqual(controller.getState(), {
    data: null,
    loading: false,
    error: null,
  });

  const errWithAbortName = new Error('aborted');
  errWithAbortName.name = 'AbortError';
  await controller.start(() => Promise.reject(errWithAbortName));
  assert.deepEqual(controller.getState(), {
    data: null,
    loading: false,
    error: null,
  });

  assert.equal(isAbortError(new DOMException('x', 'AbortError')), true);
  assert.equal(isAbortError(errWithAbortName), true);
  assert.equal(isAbortError(new Error('regular')), false);
});

test('6. Retry works after a failed request and clears previous error', async () => {
  const controller = createApiRequestController(() => {});

  await controller.start(() => Promise.reject(new Error('500 Internal Server Error')));
  assert.deepEqual(controller.getState(), {
    data: null,
    loading: false,
    error: '500 Internal Server Error',
  });

  await controller.start(() => Promise.resolve('recovered'));
  assert.deepEqual(controller.getState(), {
    data: 'recovered',
    loading: false,
    error: null,
  });
});

test('7 & 9. Refetch preserves existing data while reloading and updates cleanly', async () => {
  const controller = createApiRequestController(() => {});

  await controller.start(() => Promise.resolve('initial-data'));
  assert.deepEqual(controller.getState(), {
    data: 'initial-data',
    loading: false,
    error: null,
  });

  const d2 = deferred();
  const p2 = controller.start(() => d2.promise, { clearData: false });

  // While refetch is loading, existing data is preserved (no blanking/flickering)
  assert.deepEqual(controller.getState(), {
    data: 'initial-data',
    loading: true,
    error: null,
  });

  d2.resolve('refreshed-data');
  await p2;

  assert.deepEqual(controller.getState(), {
    data: 'refreshed-data',
    loading: false,
    error: null,
  });
});

test('8. Loading state remains true when an older overlapping request settles first', async () => {
  const controller = createApiRequestController(() => {});

  const d1 = deferred();
  const d2 = deferred();

  const p1 = controller.start(() => d1.promise);
  const p2 = controller.start(() => d2.promise);

  // Older request settles while newer request is still pending
  d1.resolve('stale');
  await p1;

  assert.equal(controller.getState().loading, true);
  assert.equal(controller.getState().data, null);

  d2.resolve('fresh');
  await p2;

  assert.deepEqual(controller.getState(), {
    data: 'fresh',
    loading: false,
    error: null,
  });
});

test('10. Mode/dependency change clears stale data and blocks previous-mode overwrite', async () => {
  const controller = createApiRequestController(() => {});

  // Initial mode (e.g. Demo Mode)
  await controller.start(() => Promise.resolve('demo-data'));
  assert.equal(controller.getState().data, 'demo-data');

  // Switch to API Mode with clearData: true, and an overlapping slow previous-mode request
  const slowDemo = deferred();
  const fastApi = deferred();

  const pOld = controller.start(() => slowDemo.promise, { clearData: true });
  // Stale demo-data must be cleared immediately on mode change
  assert.deepEqual(controller.getState(), {
    data: null,
    loading: true,
    error: null,
  });

  const pNew = controller.start(() => fastApi.promise, { clearData: true });
  fastApi.resolve('api-data');
  await pNew;

  slowDemo.resolve('stale-demo-data');
  await pOld;

  assert.deepEqual(controller.getState(), {
    data: 'api-data',
    loading: false,
    error: null,
  });
});
