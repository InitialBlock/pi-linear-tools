#!/usr/bin/env node
/**
 * Image fetch hardening:
 * - markdown/html image extraction is linear-time on hostile input
 * - private/loopback targets and redirects to them are refused
 * - auth header only goes to uploads.linear.app, never to redirect targets elsewhere
 * - body size is enforced while streaming
 */

import assert from 'node:assert/strict';
import { extractMarkdownImages, fetchImageUrl, fetchIssueImages } from '../src/linear.js';

// 1) ReDoS regression: crafted inputs that used to be cubic/quadratic
{
  const cases = [
    ["<img src='a' ".repeat(4000), 'html img attribute stuffing'],
    ['![]('.repeat(40000), 'markdown image opener stuffing'],
    ['<img '.repeat(20000) + '>', 'html img open tag stuffing'],
    ['![' + 'x'.repeat(200000) + '](', 'unterminated alt'],
  ];
  for (const [input, label] of cases) {
    const started = process.hrtime.bigint();
    extractMarkdownImages(input, 'test');
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    assert.ok(elapsedMs < 250, `${label}: extraction took ${elapsedMs.toFixed(0)}ms on ${input.length} chars`);
  }
  console.log('✓ image extraction is fast on hostile input');
}

// 2) Extraction still works for normal content
{
  const md = [
    'Intro ![shot](https://uploads.linear.app/ws/a.png "title") text',
    '<img alt="x" src="https://cdn.example.com/b.jpg" width=10>',
    "<IMG SRC='https://cdn.example.com/c.gif'>",
    '![no-url]() ![](https://cdn.example.com/d.webp)',
  ].join('\n');
  const found = extractMarkdownImages(md, 'description').map((i) => i.url);
  assert.deepEqual(found, [
    'https://uploads.linear.app/ws/a.png',
    'https://cdn.example.com/d.webp',
    'https://cdn.example.com/b.jpg',
    'https://cdn.example.com/c.gif',
  ]);
  console.log('✓ image extraction still finds markdown and html images');
}

const client = { apiKey: 'lin_api_test_key_000000000000' };
const png = () => new Response(Buffer.from('png'), { status: 200, headers: { 'content-type': 'image/png' } });

// 3) Private / loopback targets refused without any fetch
{
  let fetches = 0;
  const fetchImpl = async () => { fetches += 1; return png(); };
  for (const url of ['http://127.0.0.1/x.png', 'http://localhost:8080/x.png', 'http://169.254.169.254/latest/meta-data', 'http://[::1]/x.png', 'http://10.0.0.5/x.png']) {
    await assert.rejects(fetchImageUrl(client, url, { fetchImpl }), /local\/private/);
  }
  assert.equal(fetches, 0);
  console.log('✓ private image URLs are refused before fetching');
}

// 4) Redirect from a public host to a private one is refused; auth never leaves uploads.linear.app
{
  const seen = [];
  const fetchImpl = async (url, init) => {
    seen.push({ url: String(url), auth: init.headers?.authorization || null, redirect: init.redirect });
    if (String(url).startsWith('https://uploads.linear.app/')) {
      return new Response(null, { status: 302, headers: { location: 'http://127.0.0.1:9000/steal' } });
    }
    return png();
  };
  await assert.rejects(fetchImageUrl(client, 'https://uploads.linear.app/ws/x.png', { fetchImpl }), /local\/private.*redirect hop 1/);
  assert.ok(seen.length >= 1);
  assert.ok(seen.every((s) => s.url.startsWith('https://uploads.linear.app/')), 'private redirect target must not be fetched');
  assert.ok(seen.every((s) => s.redirect === 'manual'));
  console.log('✓ redirect to private address is refused');
}
{
  const seen = [];
  const fetchImpl = async (url, init) => {
    seen.push({ url: String(url), auth: init.headers?.authorization || null });
    if (String(url) === 'https://uploads.linear.app/ws/x.png') {
      // unauthenticated attempt gets 401, authenticated attempt is redirected to a public CDN
      if (!init.headers?.authorization) return new Response('nope', { status: 401 });
      return new Response(null, { status: 302, headers: { location: 'https://cdn.example.com/signed.png' } });
    }
    assert.equal(String(url), 'https://cdn.example.com/signed.png');
    return png();
  };
  const image = await fetchImageUrl(client, 'https://uploads.linear.app/ws/x.png', { fetchImpl });
  assert.equal(image.mimeType, 'image/png');
  const cdnCalls = seen.filter((s) => s.url.startsWith('https://cdn.example.com/'));
  assert.ok(cdnCalls.length >= 1);
  assert.ok(cdnCalls.every((s) => s.auth === null), 'authorization must not be forwarded off uploads.linear.app');
  assert.ok(seen.some((s) => s.url.startsWith('https://uploads.linear.app/') && s.auth === client.apiKey), 'raw auth attempt expected');
  console.log('✓ auth header stays on uploads.linear.app across redirects');
}

// 5) Streaming size cap (no content-length)
{
  const fetchImpl = async () => new Response(new ReadableStream({
    start(controller) {
      for (let i = 0; i < 64; i += 1) controller.enqueue(new Uint8Array(64 * 1024));
      controller.close();
    },
  }), { status: 200, headers: { 'content-type': 'image/png' } });
  await assert.rejects(fetchImageUrl(client, 'https://cdn.example.com/huge.png', { fetchImpl, maxBytes: 1024 * 1024 }), /too large/);
  console.log('✓ oversized streamed image is rejected');
}

// 6) fetchIssueImages surfaces refusals as per-image failures, not a crash
{
  const issueId = '99999999-1234-1234-1234-123456789abe';
  const mockClient = {
    apiKey: 'lin_api_test_key_000000000000',
    rawRequest: async () => ({
      data: {
        issue: {
          id: issueId,
          identifier: 'ENG-1',
          title: 'Images',
          description: 'ok ![a](https://cdn.example.com/a.png) bad ![b](http://169.254.169.254/latest)',
          url: 'https://linear.app/example/issue/ENG-1',
          state: { id: 's', name: 'Backlog', color: '#ccc', type: 'backlog' },
          team: { id: 't', key: 'ENG', name: 'Engineering' },
          labels: { nodes: [] },
          children: { nodes: [] },
          attachments: { nodes: [] },
          comments: { nodes: [] },
        },
      },
      headers: new Headers(),
    }),
  };
  const fetchImpl = async (url) => {
    assert.equal(String(url), 'https://cdn.example.com/a.png', 'only the public image should be fetched');
    return png();
  };
  const result = await fetchIssueImages(mockClient, issueId, { fetchImpl });
  assert.equal(result.images.length, 1);
  assert.equal(result.failures.length, 1);
  assert.match(result.failures[0].error, /local\/private/);
  console.log('✓ fetchIssueImages reports refused URLs as failures');
}

console.log('✓ tests/test-image-fetch.js passed');
