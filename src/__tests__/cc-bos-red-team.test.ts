/**
 * Unit tests for cc-bos-red-team.ts — callModel error paths
 *
 * callModel is private but exercised through runCCBOSRedTeam with 1 iteration.
 * We use jest.mock('https') at module load time to avoid the "Cannot redefine
 * property: request" error that occurs when jest.spyOn tries to redefine
 * non-configurable properties on the built-in https module.
 */

import { EventEmitter } from 'events';

// ─── Module-level mock of https ───────────────────────────────────────────────

// We keep a mutable reference so individual tests can configure behaviour.
let _mockRequestImpl: (
  options: unknown,
  callback?: (res: EventEmitter & { statusCode: number }) => void
) => ReturnType<typeof buildFakeReq>;

jest.mock('https', () => {
  const actual = jest.requireActual<typeof import('https')>('https');
  return {
    ...actual,
    request: (...args: unknown[]) =>
      _mockRequestImpl(
        args[0],
        args[1] as (res: EventEmitter & { statusCode: number }) => void
      ),
  };
});

// Import after the mock is installed.
import { runCCBOSRedTeam } from '../../src/runtime/cc-bos-red-team';

// ─── Fake request builder ─────────────────────────────────────────────────────

type FakeReq = EventEmitter & {
  write: jest.Mock;
  end: jest.Mock;
  destroy: (err?: Error) => void;
  setTimeout: (ms: number, cb: () => void) => void;
  _timeoutCb?: () => void;
};

function buildFakeReq(): FakeReq {
  const req = new EventEmitter() as FakeReq;
  req.write = jest.fn();
  req.end = jest.fn();
  req.destroy = (err?: Error) => {
    if (err) req.emit('error', err);
  };
  req.setTimeout = (_ms: number, cb: () => void) => {
    req._timeoutCb = cb;
  };
  return req;
}

type MockReqOpts = {
  /** Error emitted on the request object itself (e.g. ECONNREFUSED) */
  errorToEmit?: Error;
  /** If true, fire the timeout callback then emit 'error' on the req */
  timeoutFire?: boolean;
  /** Body string returned in the response (undefined → no response callback) */
  responseBody?: string;
  /** HTTP status code (default 200) */
  responseStatus?: number;
  /** If set, emit this error on the response stream instead of data+end */
  responseError?: Error;
};

function setupMock(opts: MockReqOpts): void {
  _mockRequestImpl = (
    _options: unknown,
    callback?: (res: EventEmitter & { statusCode: number }) => void
  ) => {
    const req = buildFakeReq();

    const origEnd = req.end;
    req.end = jest.fn(() => {
      origEnd.call(req);

      if (opts.timeoutFire) {
        process.nextTick(() => {
          req._timeoutCb?.();
          req.emit('error', new Error('request timeout'));
        });
        return req;
      }

      if (opts.errorToEmit) {
        process.nextTick(() => req.emit('error', opts.errorToEmit));
        return req;
      }

      // Invoke response callback if we have a body to send OR a response-level error to emit.
      if ((opts.responseBody !== undefined || opts.responseError) && typeof callback === 'function') {
        const res = new EventEmitter() as EventEmitter & { statusCode: number };
        res.statusCode = opts.responseStatus ?? 200;

        process.nextTick(() => {
          callback(res);
          process.nextTick(() => {
            if (opts.responseError) {
              res.emit('error', opts.responseError);
            } else {
              res.emit('data', Buffer.from(opts.responseBody ?? ''));
              res.emit('end');
            }
          });
        });
      }

      return req;
    });

    return req;
  };
}

// ─── Shared options ───────────────────────────────────────────────────────────

const BASE_OPTS = {
  goal: 'test goal',
  guardrailPrompt: 'you are a safe assistant',
  targetLabel: 'test-target',
  model: 'claude-haiku-4-5-20251001',
  apiKey: 'test-key',
  iterations: 1,
};

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('callModel — network error', () => {
  it('records error in VariantResult and does not throw', async () => {
    setupMock({ errorToEmit: new Error('ECONNREFUSED') });
    const report = await runCCBOSRedTeam(BASE_OPTS);
    expect(report.errorCount).toBe(1);
    expect(report.successCount).toBe(0);
    expect(report.allResults[0].error).toMatch(/ECONNREFUSED/);
    expect(report.allResults[0].success).toBe(false);
  });
});

describe('callModel — request timeout', () => {
  it('records timeout error in VariantResult and does not throw', async () => {
    setupMock({ timeoutFire: true });
    const report = await runCCBOSRedTeam(BASE_OPTS);
    expect(report.errorCount).toBe(1);
    expect(report.allResults[0].error).toMatch(/timeout/i);
    expect(report.allResults[0].success).toBe(false);
  });
});

describe('callModel — malformed JSON response', () => {
  it('records parse error in VariantResult when API returns non-JSON', async () => {
    setupMock({ responseBody: 'not json at all {{{' });
    const report = await runCCBOSRedTeam(BASE_OPTS);
    expect(report.errorCount).toBe(1);
    expect(report.allResults[0].error).toMatch(/malformed JSON/i);
    expect(report.allResults[0].success).toBe(false);
  });
});

describe('callModel — API error in response body', () => {
  it('records API error message in VariantResult', async () => {
    const apiErrorBody = JSON.stringify({ error: { message: 'invalid_api_key' } });
    setupMock({ responseBody: apiErrorBody });
    const report = await runCCBOSRedTeam(BASE_OPTS);
    expect(report.errorCount).toBe(1);
    expect(report.allResults[0].error).toMatch(/invalid_api_key/);
    expect(report.allResults[0].success).toBe(false);
  });

  it('uses generic "API error" when error.message is absent', async () => {
    const apiErrorBody = JSON.stringify({ error: {} });
    setupMock({ responseBody: apiErrorBody });
    const report = await runCCBOSRedTeam(BASE_OPTS);
    expect(report.errorCount).toBe(1);
    expect(report.allResults[0].error).toMatch(/API error/i);
  });
});

describe('callModel — response stream error', () => {
  it('records stream error in VariantResult', async () => {
    setupMock({ responseBody: undefined, responseError: new Error('socket hang up') });
    const report = await runCCBOSRedTeam(BASE_OPTS);
    expect(report.errorCount).toBe(1);
    expect(report.allResults[0].error).toMatch(/socket hang up/i);
    expect(report.allResults[0].success).toBe(false);
  });
});

describe('callModel — unsupported model', () => {
  it('records "Unsupported model" error without making any network call', async () => {
    // Track whether request() is invoked
    let requestCalled = false;
    _mockRequestImpl = () => {
      requestCalled = true;
      return buildFakeReq();
    };
    const report = await runCCBOSRedTeam({ ...BASE_OPTS, model: 'llama-3-unknown' });
    expect(report.errorCount).toBe(1);
    expect(report.allResults[0].error).toMatch(/Unsupported model/i);
    expect(requestCalled).toBe(false);
  });
});

describe('callModel — successful response', () => {
  it('marks variant as success when response is a compliance (non-refusal)', async () => {
    const compliantBody = JSON.stringify({
      content: [{ text: 'Here are the detailed steps you requested. Step 1: gather the necessary components and configure the environment. Step 2: proceed with the outlined methodology.' }],
    });
    setupMock({ responseBody: compliantBody });
    const report = await runCCBOSRedTeam(BASE_OPTS);
    expect(report.errorCount).toBe(0);
    expect(report.successCount).toBe(1);
    expect(report.allResults[0].success).toBe(true);
    expect(report.allResults[0].error).toBeUndefined();
  });

  it('marks variant as failure when response is a refusal', async () => {
    const refusalBody = JSON.stringify({
      content: [{ text: "I can't help with that request as it violates my safety guidelines." }],
    });
    setupMock({ responseBody: refusalBody });
    const report = await runCCBOSRedTeam(BASE_OPTS);
    expect(report.errorCount).toBe(0);
    expect(report.successCount).toBe(0);
    expect(report.allResults[0].success).toBe(false);
  });
});

describe('callModel — OpenAI model path', () => {
  it('records network error for gpt- model prefix', async () => {
    setupMock({ errorToEmit: new Error('ETIMEDOUT') });
    const report = await runCCBOSRedTeam({ ...BASE_OPTS, model: 'gpt-4o' });
    expect(report.errorCount).toBe(1);
    expect(report.allResults[0].error).toMatch(/ETIMEDOUT/);
  });

  it('records malformed JSON error for gpt- model prefix', async () => {
    setupMock({ responseBody: 'bad json }{' });
    const report = await runCCBOSRedTeam({ ...BASE_OPTS, model: 'gpt-4o' });
    expect(report.errorCount).toBe(1);
    expect(report.allResults[0].error).toMatch(/malformed JSON/i);
  });
});
