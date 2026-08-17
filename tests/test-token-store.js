#!/usr/bin/env node
/**
 * Token store tests:
 * - the keychain module the code imports (@github/keytar) actually resolves
 * - keychain path is used when available
 * - file fallback is owner-only (0600) and is tightened on rewrite
 */

import assert from 'node:assert/strict';
import { mkdtemp, stat, chmod, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const tempHome = await mkdtemp(join(tmpdir(), 'pi-linear-token-store-'));
const prevHome = process.env.HOME;
process.env.HOME = tempHome;
delete process.env.LINEAR_ACCESS_TOKEN;
delete process.env.LINEAR_REFRESH_TOKEN;
delete process.env.LINEAR_EXPIRES_AT;

const { storeTokens, getTokens, clearTokens, _setKeytarModuleForTests } = await import('../src/auth/token-store.js');

const record = {
  accessToken: 'lin_oauth_access_0123456789abcdef',
  refreshToken: 'lin_oauth_refresh_0123456789abcdef',
  expiresAt: Date.now() + 3600_000,
  scope: ['read'],
  tokenType: 'Bearer',
};

try {
  // 1) The specifier used by token-store resolves and exposes the keytar API
  const keytar = (await import('@github/keytar')).default;
  assert.equal(typeof keytar.getPassword, 'function');
  assert.equal(typeof keytar.setPassword, 'function');
  assert.equal(typeof keytar.deletePassword, 'function');
  console.log('✓ @github/keytar resolves with keytar-compatible API');

  // 2) Keychain path is used when a keytar implementation is available
  const store = new Map();
  const fakeKeytar = {
    async setPassword(service, account, value) { store.set(`${service}/${account}`, value); return true; },
    async getPassword(service, account) { return store.get(`${service}/${account}`) ?? null; },
    async deletePassword(service, account) { return store.delete(`${service}/${account}`); },
  };
  _setKeytarModuleForTests(fakeKeytar);
  await storeTokens(record);
  assert.equal(store.size, 1, 'tokens should be written to the keychain implementation');
  _setKeytarModuleForTests(fakeKeytar); // drop in-memory cache so the read hits the keychain
  const fromKeychain = await getTokens();
  assert.equal(fromKeychain.accessToken, record.accessToken);
  await clearTokens();
  assert.equal(store.size, 0, 'clearTokens should remove keychain entry');
  console.log('✓ keychain implementation is used when available');

  // 3) File fallback is owner-only
  _setKeytarModuleForTests(false);
  await storeTokens(record);
  const tokenFile = join(tempHome, '.pi', 'agent', 'extensions', 'pi-linear-tools', 'oauth-tokens.json');
  const parsed = JSON.parse(await readFile(tokenFile, 'utf8'));
  assert.equal(parsed.refreshToken, record.refreshToken);
  if (process.platform !== 'win32') {
    assert.equal((await stat(tokenFile)).mode & 0o777, 0o600, 'token file must be 0600');
    await chmod(tokenFile, 0o644);
    await storeTokens(record);
    assert.equal((await stat(tokenFile)).mode & 0o777, 0o600, 'token file must be re-tightened to 0600');
  }
  await clearTokens();
  console.log('✓ file fallback is owner-only');

  console.log('✓ tests/test-token-store.js passed');
} finally {
  _setKeytarModuleForTests(null);
  process.env.HOME = prevHome;
}
