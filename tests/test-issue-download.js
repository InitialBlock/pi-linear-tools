#!/usr/bin/env node

import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, mkdir, symlink, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { executeIssueDownload, issueDownloadInternals } from '../src/handlers.js';

function createMockClient(attachments) {
  return {
    async issue(identifier) {
      return {
        id: 'issue-1',
        identifier,
        title: 'Download test issue',
        description: 'Issue with attachments',
        url: `https://linear.app/test/issue/${identifier}/download-test`,
        branchName: 'test/download',
        priority: 0,
        estimate: null,
        createdAt: '2026-01-01T00:00:00.000Z',
        updatedAt: '2026-01-01T00:00:00.000Z',
        state: Promise.resolve({ name: 'Todo', color: '#ccc', type: 'unstarted' }),
        team: Promise.resolve({ id: 'team-1', key: 'TST', name: 'Test' }),
        project: Promise.resolve(null),
        projectMilestone: Promise.resolve(null),
        assignee: Promise.resolve(null),
        creator: Promise.resolve(null),
        labels: async () => ({ nodes: [] }),
        parent: Promise.resolve(null),
        children: async () => ({ nodes: [] }),
        attachments: async () => ({ nodes: attachments }),
      };
    },
  };
}

function createFetch(body, headers = {}) {
  return async () => new Response(body, {
    status: 200,
    headers,
  });
}

async function withTempDir(fn) {
  const dir = await mkdtemp(path.join(tmpdir(), 'pi-linear-tools-download-test-'));
  await fn(dir);
}

async function testSuccessfulDownload() {
  await withTempDir(async (cwd) => {
    const client = createMockClient([
      {
        id: 'att-1',
        title: 'Spec File.txt',
        url: 'https://uploads.linear.app/ws/spec.txt',
        subtitle: 'docs',
        sourceType: 'upload',
        createdAt: '2026-01-01T00:00:00.000Z',
      },
    ]);

    const result = await executeIssueDownload(client, {
      issue: 'TST-1',
      directory: 'downloads',
    }, {
      cwd,
      settings: { allow_overwrite_files: false },
      fetchImpl: createFetch('hello world', { 'content-length': '11' }),
    });

    assert.match(result.content[0].text, /Downloaded \*\*Spec File\.txt\*\*/);
    assert.equal(result.details.bytesWritten, 11);
    assert.equal(result.details.relativePath, path.join('downloads', 'Spec File.txt'));
    assert.equal(await readFile(path.join(cwd, 'downloads', 'Spec File.txt'), 'utf-8'), 'hello world');
  });
}

async function testOverwriteGuardAndExistingFileBehavior() {
  await withTempDir(async (cwd) => {
    const client = createMockClient([
      { id: 'att-1', title: 'same.txt', url: 'https://uploads.linear.app/ws/same.txt' },
    ]);
    const downloads = path.join(cwd, 'downloads');
    await writeFile(path.join(cwd, 'placeholder'), 'x');
    await import('node:fs/promises').then(fs => fs.mkdir(downloads, { recursive: true }));
    await writeFile(path.join(downloads, 'same.txt'), 'old');

    await assert.rejects(
      executeIssueDownload(client, {
        issue: 'TST-1',
        directory: 'downloads',
        overwrite: true,
      }, {
        cwd,
        settings: { allow_overwrite_files: false },
        fetchImpl: createFetch('new'),
      }),
      /allow_overwrite_files=true/
    );

    await assert.rejects(
      executeIssueDownload(client, {
        issue: 'TST-1',
        directory: 'downloads',
      }, {
        cwd,
        settings: { allow_overwrite_files: false },
        fetchImpl: createFetch('new'),
      }),
      /already exists/
    );

    await executeIssueDownload(client, {
      issue: 'TST-1',
      directory: 'downloads',
      overwrite: true,
    }, {
      cwd,
      settings: { allow_overwrite_files: true },
      fetchImpl: createFetch('new'),
    });

    assert.equal(await readFile(path.join(downloads, 'same.txt'), 'utf-8'), 'new');
  });
}

async function testPathSafetyAndFilenameSanitization() {
  const { resolveSafeRelativeDirectory, sanitizeDownloadFilename, selectIssueAttachment } = issueDownloadInternals;
  assert.throws(() => resolveSafeRelativeDirectory('/tmp'), /relative/);
  assert.throws(() => resolveSafeRelativeDirectory('../outside', '/tmp/base'), /current working directory/);
  // Hidden directories are never valid download targets (tooling auto-loads from some of them)
  assert.throws(() => resolveSafeRelativeDirectory('.pi/extensions', '/tmp/base'), /hidden/);
  assert.throws(() => resolveSafeRelativeDirectory('.git/hooks', '/tmp/base'), /hidden/);
  assert.throws(() => resolveSafeRelativeDirectory('docs/.claude', '/tmp/base'), /hidden/);
  assert.equal(resolveSafeRelativeDirectory('.', '/tmp/base'), path.resolve('/tmp/base'));
  assert.equal(resolveSafeRelativeDirectory('docs/assets', '/tmp/base'), path.resolve('/tmp/base', 'docs/assets'));
  assert.equal(sanitizeDownloadFilename('../bad:name?.txt'), 'bad_name_.txt');

  assert.equal(
    selectIssueAttachment([
      { id: 'att-1', title: 'A' },
      { id: 'att-2', title: 'B' },
    ], { attachmentIndex: 2 }).id,
    'att-2'
  );
  assert.throws(
    () => selectIssueAttachment([{ id: 'a', title: 'Same' }, { id: 'b', title: 'Same' }], { attachmentTitle: 'same' }),
    /Multiple attachments/
  );
}

async function testMaxBytesGuards() {
  await withTempDir(async (cwd) => {
    const client = createMockClient([
      { id: 'att-1', title: 'large.bin', url: 'https://uploads.linear.app/ws/large.bin' },
    ]);

    await assert.rejects(
      executeIssueDownload(client, {
        issue: 'TST-1',
        directory: 'downloads',
        maxBytes: 2,
      }, {
        cwd,
        settings: {},
        fetchImpl: createFetch('abc', { 'content-length': '3' }),
      }),
      /exceeds maxBytes/
    );

    await assert.rejects(
      executeIssueDownload(client, {
        issue: 'TST-1',
        directory: 'downloads',
        maxBytes: 2,
        filename: 'stream.bin',
      }, {
        cwd,
        settings: {},
        fetchImpl: createFetch('abc'),
      }),
      /exceeds maxBytes/
    );
  });
}

async function testUrlAllowListAndRedirects() {
  const { assertAllowedDownloadUrl } = issueDownloadInternals;

  // Default policy: only Linear's upload host
  await assertAllowedDownloadUrl('https://uploads.linear.app/ws/file.bin', {});
  await assert.rejects(assertAllowedDownloadUrl('https://example.com/file.bin', {}), /only uploads.linear.app/);
  await assert.rejects(assertAllowedDownloadUrl('http://127.0.0.1:8080/x', {}), /only uploads.linear.app/);
  await assert.rejects(assertAllowedDownloadUrl('http://169.254.169.254/latest/meta-data', {}), /only uploads.linear.app/);
  await assert.rejects(assertAllowedDownloadUrl('ftp://uploads.linear.app/x', {}), /protocol/);
  await assert.rejects(assertAllowedDownloadUrl('https://uploads.linear.app.evil.com/x', {}), /only uploads.linear.app/);
  await assert.rejects(assertAllowedDownloadUrl('https://user:pw@uploads.linear.app/x', {}), /embedded credentials/);

  // User allow-list (exact + wildcard), private targets still refused unless allow-listed explicitly
  const settings = { download_allowed_hosts: ['files.example.com', '*.cdn.example.org'] };
  await assertAllowedDownloadUrl('https://files.example.com/a', settings);
  await assertAllowedDownloadUrl('https://eu.cdn.example.org/a', settings);
  await assert.rejects(assertAllowedDownloadUrl('https://other.example.com/a', settings), /only uploads.linear.app/);
  await assert.rejects(assertAllowedDownloadUrl('http://localhost:3000/a', settings), /only uploads.linear.app/);

  // End-to-end: redirect from Linear to a non-allowed host is refused, nothing written
  await withTempDir(async (cwd) => {
    const client = createMockClient([
      { id: 'att-1', title: 'redir.txt', url: 'https://uploads.linear.app/ws/redir.txt' },
    ]);
    const calls = [];
    const fetchImpl = async (url, options) => {
      calls.push({ url: String(url), redirect: options?.redirect });
      if (String(url).startsWith('https://uploads.linear.app/')) {
        return new Response(null, { status: 302, headers: { location: 'http://169.254.169.254/latest/meta-data' } });
      }
      return new Response('secret', { status: 200 });
    };
    await assert.rejects(
      executeIssueDownload(client, { action: 'download', issue: 'TST-1', directory: 'downloads' }, { cwd, settings: {}, fetchImpl }),
      /redirect target \(hop 1\)/
    );
    assert.equal(calls.length, 1, 'redirect target must not be fetched');
    assert.equal(calls[0].redirect, 'manual', 'redirects must be handled manually');
    await assert.rejects(readFile(path.join(cwd, 'downloads', 'redir.txt')), /ENOENT/);
  });

  // End-to-end: redirect within allowed hosts is followed
  await withTempDir(async (cwd) => {
    const client = createMockClient([
      { id: 'att-1', title: 'ok.txt', url: 'https://uploads.linear.app/ws/ok.txt' },
    ]);
    const fetchImpl = async (url) => {
      if (String(url) === 'https://uploads.linear.app/ws/ok.txt') {
        return new Response(null, { status: 302, headers: { location: '/ws/ok-signed.txt' } });
      }
      assert.equal(String(url), 'https://uploads.linear.app/ws/ok-signed.txt');
      return new Response('payload', { status: 200 });
    };
    const result = await executeIssueDownload(client, { action: 'download', issue: 'TST-1', directory: 'downloads' }, { cwd, settings: {}, fetchImpl });
    assert.equal(result.details.bytesWritten, 7);
    assert.equal(await readFile(path.join(cwd, 'downloads', 'ok.txt'), 'utf-8'), 'payload');
  });

  // End-to-end: non-Linear attachment URL refused before any filesystem side effect
  await withTempDir(async (cwd) => {
    const client = createMockClient([
      { id: 'att-1', title: 'ext.txt', url: 'https://example.com/ext.txt' },
    ]);
    let fetched = false;
    await assert.rejects(
      executeIssueDownload(client, { action: 'download', issue: 'TST-1', directory: 'downloads' }, { cwd, settings: {}, fetchImpl: async () => { fetched = true; return new Response('x'); } }),
      /only uploads.linear.app/
    );
    assert.equal(fetched, false);
    await assert.rejects(readFile(path.join(cwd, 'downloads')), /ENOENT/);
  });
}

async function testSymlinkContainment() {
  if (process.platform === 'win32') return;
  await withTempDir(async (cwd) => {
    const outside = await mkdtemp(path.join(tmpdir(), 'pi-linear-tools-download-outside-'));
    await symlink(outside, path.join(cwd, 'escape'));
    const client = createMockClient([
      { id: 'att-1', title: 'leak.txt', url: 'https://uploads.linear.app/ws/leak.txt' },
    ]);
    await assert.rejects(
      executeIssueDownload(client, { action: 'download', issue: 'TST-1', directory: 'escape/sub' }, { cwd, settings: {}, fetchImpl: createFetch('x') }),
      /outside the current working directory/
    );
    await assert.rejects(readFile(path.join(outside, 'sub', 'leak.txt')), /ENOENT/);

    // Overwrite through a symlinked file is refused even with allow_overwrite_files
    const downloads = path.join(cwd, 'downloads');
    await mkdir(downloads, { recursive: true });
    const target = path.join(outside, 'victim.txt');
    await writeFile(target, 'original');
    await symlink(target, path.join(downloads, 'leak.txt'));
    await assert.rejects(
      executeIssueDownload(client, { action: 'download', issue: 'TST-1', directory: 'downloads', overwrite: true }, { cwd, settings: { allow_overwrite_files: true }, fetchImpl: createFetch('pwned') }),
      /symlink/
    );
    assert.equal(await readFile(target, 'utf-8'), 'original');
  });
}

async function main() {
  await testSuccessfulDownload();
  await testOverwriteGuardAndExistingFileBehavior();
  await testPathSafetyAndFilenameSanitization();
  await testMaxBytesGuards();
  await testUrlAllowListAndRedirects();
  await testSymlinkContainment();
  console.log('✓ tests/test-issue-download.js passed');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
