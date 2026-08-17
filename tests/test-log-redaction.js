#!/usr/bin/env node
/**
 * Regression test: credentials must never reach the log file.
 *
 * Covers:
 * - request tracker keys are hashed, not the raw API key
 * - logger redacts sensitive keys/values, including nested payloads
 * - log file is created with owner-only permissions
 */

import assert from 'node:assert/strict';
import { readFileSync, statSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const tempDir = mkdtempSync(join(tmpdir(), 'pi-linear-log-'));
const logFile = join(tempDir, 'nested', 'test.log');
process.env.PI_LINEAR_TOOLS_LOG_FILE = logFile;
process.env.LOG_LEVEL = 'debug';

const SECRET = 'lin_api_SECRETVALUE1234567890abcdef';
const OAUTH_SECRET = 'lin_oauth_SECRETVALUE1234567890abcdef';

const { info, debug, error, getLogFilePath } = await import('../src/logger.js');
const { createLinearClient, getClientAuthToken, getClientRequestMetrics } = await import('../src/linear-client.js');

assert.equal(getLogFilePath(), logFile);

// 1) Logger redaction: sensitive keys, sensitive-looking values, nested objects
info('redaction sample', {
  apiKey: SECRET,
  nested: { tokens: { accessToken: OAUTH_SECRET, refreshToken: 'lin_oauth_REFRESH123456789012345', expiresAt: 123 } },
  authorization: `Bearer ${SECRET}`,
  someList: [SECRET, { access_token: OAUTH_SECRET }],
  looksLikeKey: SECRET,
  hasAccessToken: true,
  tokenType: 'Bearer',
  teamKey: 'ENG',
});
debug('debug sample', { token: SECRET });
error('error sample', { err: new Error(`failed with ${SECRET}`) });

// 2) Real client: run one request through the wrapped rawRequest so the usage summary fires
const originalFetch = globalThis.fetch;
globalThis.fetch = async () => new Response(JSON.stringify({ data: { viewer: { id: 'u1' } } }), {
  status: 200,
  headers: {
    'content-type': 'application/json',
    'x-ratelimit-requests-limit': '1500',
    'x-ratelimit-requests-remaining': '1499',
    'x-ratelimit-requests-reset': String(Date.now() + 3600000),
  },
});
let client;
try {
  client = createLinearClient(SECRET);
  await client.client.rawRequest('query { viewer { id } }', {});
} finally {
  globalThis.fetch = originalFetch;
}

assert.equal(getClientRequestMetrics(client).total, 1, 'wrapped rawRequest should be counted');
assert.equal(getClientAuthToken(client), SECRET, 'raw credential still retrievable for authenticated fetches');
assert.notEqual(client.__piLinearTrackerKey, SECRET, 'tracker key must not be the raw credential');
assert.match(client.__piLinearTrackerKey, /^k_[0-9a-f]{16}$/, 'tracker key should be a short hash');

const content = readFileSync(logFile, 'utf8');
assert.ok(content.includes('Linear API usage summary'), 'usage summary should have been logged');
assert.ok(!content.includes(SECRET), `raw API key leaked into log:\n${content}`);
assert.ok(!content.includes(OAUTH_SECRET), 'raw OAuth token leaked into log');
assert.ok(!content.includes('lin_oauth_REFRESH'), 'refresh token leaked into log');
assert.ok(content.includes('"hasAccessToken":true'), 'boolean token flags should survive redaction');
assert.ok(content.includes('"tokenType":"Bearer"'), 'tokenType label should survive redaction');
assert.ok(content.includes('"teamKey":"ENG"'), 'non-sensitive keys should survive redaction');
assert.ok(content.includes('***masked***'), 'masking marker expected');

if (process.platform !== 'win32') {
  const mode = statSync(logFile).mode & 0o777;
  assert.equal(mode, 0o600, `log file mode should be 0600, got ${mode.toString(8)}`);
}

rmSync(tempDir, { recursive: true, force: true });
console.log('✓ tests/test-log-redaction.js passed');
