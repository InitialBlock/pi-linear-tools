#!/usr/bin/env node
/**
 * Unit tests for src/url-safety.js (SSRF guards shared by attachment download and image fetch).
 */

import assert from 'node:assert/strict';
import {
  parseHttpUrl,
  isPrivateIp,
  isLocalHostname,
  isLinearUploadHost,
  hostMatchesAllowList,
  assertPublicHttpUrl,
  fetchWithSafeRedirects,
  readBodyWithLimit,
} from '../src/url-safety.js';

// parseHttpUrl
assert.equal(parseHttpUrl('https://uploads.linear.app/x').hostname, 'uploads.linear.app');
assert.throws(() => parseHttpUrl('file:///etc/passwd'), /protocol/);
assert.throws(() => parseHttpUrl('javascript:alert(1)'), /protocol/);
assert.throws(() => parseHttpUrl('not a url'), /Invalid URL/);

// isPrivateIp — IPv4
for (const ip of ['127.0.0.1', '127.255.255.255', '10.1.2.3', '172.16.0.1', '172.31.255.254', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255']) {
  assert.equal(isPrivateIp(ip), true, `${ip} should be private`);
}
for (const ip of ['8.8.8.8', '1.1.1.1', '172.32.0.1', '11.0.0.1', '104.16.0.1']) {
  assert.equal(isPrivateIp(ip), false, `${ip} should be public`);
}
// isPrivateIp — IPv6
for (const ip of ['::1', '::', 'fc00::1', 'fd12:3456::1', 'fe80::1', 'ff02::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1', '::ffff:7f00:1', '[::1]', 'fe80::1%en0', '64:ff9b::7f00:1']) {
  assert.equal(isPrivateIp(ip), true, `${ip} should be private`);
}
for (const ip of ['2001:4860:4860::8888', '2606:4700::1111', '::ffff:8.8.8.8']) {
  assert.equal(isPrivateIp(ip), false, `${ip} should be public`);
}

// isLocalHostname
for (const host of ['localhost', 'LOCALHOST', 'foo.localhost', 'printer.local', 'db.internal', 'metadata.google.internal', '127.0.0.1', '[::1]', '169.254.169.254', '']) {
  assert.equal(isLocalHostname(host), true, `${host} should be local`);
}
for (const host of ['uploads.linear.app', 'example.com', 'localhost.example.com', 'internal.example.com']) {
  assert.equal(isLocalHostname(host), false, `${host} should not be local`);
}

// isLinearUploadHost
assert.equal(isLinearUploadHost('uploads.linear.app'), true);
assert.equal(isLinearUploadHost('UPLOADS.LINEAR.APP'), true);
assert.equal(isLinearUploadHost('eu.uploads.linear.app'), true);
assert.equal(isLinearUploadHost('uploads.linear.app.evil.com'), false);
assert.equal(isLinearUploadHost('evil-uploads.linear.app'), false);
assert.equal(isLinearUploadHost('linear.app'), false);

// hostMatchesAllowList
assert.equal(hostMatchesAllowList('files.example.com', ['files.example.com']), true);
assert.equal(hostMatchesAllowList('FILES.example.com', ['files.example.com']), true);
assert.equal(hostMatchesAllowList('a.cdn.example.org', ['*.cdn.example.org']), true);
assert.equal(hostMatchesAllowList('cdn.example.org', ['*.cdn.example.org']), true);
assert.equal(hostMatchesAllowList('evilcdn.example.org', ['*.cdn.example.org']), false);
assert.equal(hostMatchesAllowList('files.example.com', ['https://files.example.com:8443/path']), true);
assert.equal(hostMatchesAllowList('files.example.com', []), false);
assert.equal(hostMatchesAllowList('files.example.com', ['', null, undefined]), false);

// assertPublicHttpUrl (no DNS)
await assertPublicHttpUrl(new URL('https://example.com/'), { checkDns: false });
await assert.rejects(assertPublicHttpUrl(new URL('http://127.0.0.1/'), { checkDns: false }), /local\/private/);
await assert.rejects(assertPublicHttpUrl(new URL('http://[::1]/'), { checkDns: false }), /local\/private/);
await assert.rejects(assertPublicHttpUrl(new URL('http://169.254.169.254/'), { checkDns: false }), /local\/private/);
await assert.rejects(assertPublicHttpUrl(new URL('http://localhost:8080/'), { checkDns: false }), /local\/private/);
await assert.rejects(assertPublicHttpUrl(new URL('http://user:pw@example.com/'), { checkDns: false }), /embedded credentials/);
// with DNS: loopback names still refused, public host allowed (lookup failure is tolerated)
await assert.rejects(assertPublicHttpUrl(new URL('http://localhost/'), { checkDns: true }), /local\/private/);

// fetchWithSafeRedirects — validates every hop, caps hops, handles relative Location
{
  const seen = [];
  const fetchImpl = async (url, init) => {
    seen.push({ url: String(url), redirect: init.redirect, auth: init.headers?.authorization || null });
    const u = new URL(url);
    if (u.pathname === '/start') return new Response(null, { status: 302, headers: { location: '/second' } });
    if (u.pathname === '/second') return new Response(null, { status: 307, headers: { location: 'https://other.example.net/final' } });
    return new Response('done', { status: 200 });
  };
  const validated = [];
  const { response, url, hops } = await fetchWithSafeRedirects('https://a.example.com/start', {
    fetchImpl,
    validate: (u, hop) => { validated.push(`${hop}:${u.hostname}`); },
    headersFor: (u) => (u.hostname === 'a.example.com' ? { authorization: 'secret' } : {}),
  });
  assert.equal(await response.text(), 'done');
  assert.equal(url.hostname, 'other.example.net');
  assert.equal(hops, 2);
  assert.deepEqual(validated, ['0:a.example.com', '1:a.example.com', '2:other.example.net']);
  assert.ok(seen.every((s) => s.redirect === 'manual'));
  assert.deepEqual(seen.map((s) => s.auth), ['secret', 'secret', null], 'auth header must not leak to other hosts');
}
{
  // hop rejected by validator → nothing fetched beyond the redirect response
  let fetches = 0;
  const fetchImpl = async () => { fetches += 1; return new Response(null, { status: 302, headers: { location: 'http://127.0.0.1/' } }); };
  await assert.rejects(
    fetchWithSafeRedirects('https://a.example.com/start', {
      fetchImpl,
      validate: async (u) => assertPublicHttpUrl(u, { checkDns: false }),
    }),
    /local\/private/
  );
  assert.equal(fetches, 1);
}
{
  // redirect loop is capped
  const fetchImpl = async () => new Response(null, { status: 301, headers: { location: '/again' } });
  await assert.rejects(
    fetchWithSafeRedirects('https://a.example.com/again', { fetchImpl, validate: () => {}, maxRedirects: 3 }),
    /Too many redirects/
  );
}
{
  // non-http redirect target refused
  const fetchImpl = async () => new Response(null, { status: 302, headers: { location: 'file:///etc/passwd' } });
  await assert.rejects(
    fetchWithSafeRedirects('https://a.example.com/x', { fetchImpl, validate: () => {} }),
    /non-http/
  );
}

// readBodyWithLimit — streams and aborts past the limit, ignores lying content-length
{
  const big = new Response(new ReadableStream({
    start(controller) {
      for (let i = 0; i < 10; i += 1) controller.enqueue(new Uint8Array(1024));
      controller.close();
    },
  }), { status: 200 });
  await assert.rejects(readBodyWithLimit(big, 4096), /exceeds maxBytes/);

  const small = new Response('hello', { status: 200, headers: { 'content-length': '999999' } });
  await assert.rejects(readBodyWithLimit(small, 100), /exceeds maxBytes/);

  const ok = new Response('hello', { status: 200 });
  assert.equal((await readBodyWithLimit(ok, 100)).toString(), 'hello');
}

console.log('✓ tests/test-url-safety.js passed');
