/**
 * URL safety helpers for outbound fetches driven by Linear-controlled data
 * (attachment URLs, image URLs embedded in issue/comment markdown).
 *
 * Any workspace member can put arbitrary URLs into Linear, so these helpers
 * exist to keep the agent from being turned into an SSRF proxy against
 * localhost, private networks, or cloud metadata endpoints, and to make sure
 * redirects are re-validated hop by hop.
 */

import { isIP } from 'node:net';
import { lookup } from 'node:dns/promises';

export const LINEAR_UPLOAD_HOST = 'uploads.linear.app';
export const DEFAULT_MAX_REDIRECTS = 5;

/**
 * Parse a URL and require http(s).
 * @param {string} value
 * @returns {URL}
 */
export function parseHttpUrl(value) {
  let parsed;
  try {
    parsed = new URL(String(value));
  } catch {
    throw new Error(`Invalid URL: ${String(value)}`);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Unsupported URL protocol "${parsed.protocol}" (only http/https allowed)`);
  }
  return parsed;
}

/**
 * True when the hostname is Linear's upload CDN (or a subdomain of it).
 * @param {string} hostname
 */
export function isLinearUploadHost(hostname) {
  const host = String(hostname || '').toLowerCase();
  return host === LINEAR_UPLOAD_HOST || host.endsWith(`.${LINEAR_UPLOAD_HOST}`);
}

function ipv4ToInt(ip) {
  const parts = ip.split('.').map((part) => Number.parseInt(part, 10));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return null;
  }
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function inCidrV4(ip, cidr) {
  const [base, bitsText] = cidr.split('/');
  const bits = Number.parseInt(bitsText, 10);
  const ipInt = ipv4ToInt(ip);
  const baseInt = ipv4ToInt(base);
  if (ipInt === null || baseInt === null) return false;
  if (bits === 0) return true;
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

// Non-public IPv4 ranges: loopback, link-local (incl. cloud metadata 169.254.169.254),
// RFC1918, CGNAT, "this network", broadcast/multicast/reserved.
const PRIVATE_V4_CIDRS = [
  '0.0.0.0/8',
  '10.0.0.0/8',
  '100.64.0.0/10',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '172.16.0.0/12',
  '192.0.0.0/24',
  '192.0.2.0/24',
  '192.168.0.0/16',
  '198.18.0.0/15',
  '198.51.100.0/24',
  '203.0.113.0/24',
  '224.0.0.0/4',
  '240.0.0.0/4',
];

/**
 * True for loopback, link-local, private, CGNAT, multicast, reserved and unspecified addresses.
 * @param {string} ip - IPv4 or IPv6 literal (may be bracketed)
 */
export function isPrivateIp(ip) {
  let address = String(ip || '').trim();
  if (address.startsWith('[') && address.endsWith(']')) {
    address = address.slice(1, -1);
  }
  const zoneIndex = address.indexOf('%');
  if (zoneIndex >= 0) address = address.slice(0, zoneIndex);

  const version = isIP(address);
  if (version === 4) {
    return PRIVATE_V4_CIDRS.some((cidr) => inCidrV4(address, cidr));
  }
  if (version === 6) {
    const lower = address.toLowerCase();
    // IPv4-mapped / IPv4-compatible: ::ffff:a.b.c.d or ::a.b.c.d
    const mapped = lower.match(/^(?:0*:)*(?:ffff:)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
    if (mapped) return isPrivateIp(mapped[1]);
    // ::ffff:xxxx:xxxx hex form of IPv4-mapped
    const mappedHex = lower.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (mappedHex) {
      const hi = Number.parseInt(mappedHex[1], 16);
      const lo = Number.parseInt(mappedHex[2], 16);
      return isPrivateIp(`${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`);
    }
    if (lower === '::' || lower === '::1') return true;
    if (/^f[cd][0-9a-f]{2}:/.test(lower)) return true; // fc00::/7 unique local
    if (/^fe[89ab][0-9a-f]:/.test(lower)) return true; // fe80::/10 link-local
    if (/^ff[0-9a-f]{2}:/.test(lower)) return true; // ff00::/8 multicast
    if (/^64:ff9b:/.test(lower)) {
      // NAT64 well-known prefix; the embedded IPv4 decides
      const tail = lower.split(':').slice(-2);
      if (tail.length === 2 && tail.every((part) => /^[0-9a-f]{1,4}$/.test(part))) {
        const hi = Number.parseInt(tail[0], 16);
        const lo = Number.parseInt(tail[1], 16);
        return isPrivateIp(`${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`);
      }
      return true;
    }
    return false;
  }
  return false;
}

/**
 * Hostnames that always mean "this machine / this network" without a DNS lookup.
 * @param {string} hostname
 */
export function isLocalHostname(hostname) {
  const host = String(hostname || '').toLowerCase().replace(/\.$/, '');
  if (!host) return true;
  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  if (host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.localdomain')) return true;
  if (host === 'metadata.google.internal' || host === 'metadata') return true;
  const bare = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
  if (isIP(bare)) return isPrivateIp(bare);
  return false;
}

/**
 * Resolve a hostname and report whether any answer is a non-public address.
 * Best-effort: DNS failures are reported as "not private" so the fetch can
 * surface the real error; DNS rebinding between this check and the fetch is
 * not covered.
 * @param {string} hostname
 * @returns {Promise<boolean>}
 */
export async function resolvesToPrivateAddress(hostname) {
  const host = String(hostname || '');
  const bare = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
  if (isIP(bare)) return isPrivateIp(bare);
  try {
    const answers = await lookup(bare, { all: true, verbatim: true });
    return answers.some((answer) => isPrivateIp(answer.address));
  } catch {
    return false;
  }
}

/**
 * Normalize an allow-list entry: lowercase hostname, optional leading "*." wildcard.
 * @param {unknown} entry
 * @returns {string|null}
 */
export function normalizeHostPattern(entry) {
  const text = String(entry ?? '').trim().toLowerCase();
  if (!text) return null;
  // Accept full URLs and strip to hostname for convenience.
  if (text.includes('://')) {
    try {
      return new URL(text).hostname || null;
    } catch {
      return null;
    }
  }
  return text.replace(/\/.*$/, '').replace(/:\d+$/, '') || null;
}

/**
 * True when hostname matches an allow-list of exact hosts / "*.suffix" patterns.
 * @param {string} hostname
 * @param {string[]} patterns
 */
export function hostMatchesAllowList(hostname, patterns) {
  const host = String(hostname || '').toLowerCase().replace(/\.$/, '');
  for (const raw of patterns || []) {
    const pattern = normalizeHostPattern(raw);
    if (!pattern) continue;
    if (pattern.startsWith('*.')) {
      const suffix = pattern.slice(2);
      if (host === suffix || host.endsWith(`.${suffix}`)) return true;
    } else if (host === pattern) {
      return true;
    }
  }
  return false;
}

/**
 * Reject URLs that point at local/private infrastructure.
 * @param {URL} url
 * @param {{ checkDns?: boolean }} [options]
 */
export async function assertPublicHttpUrl(url, options = {}) {
  const { checkDns = true } = options;
  const parsed = url instanceof URL ? url : parseHttpUrl(url);
  if (parsed.username || parsed.password) {
    throw new Error(`Refusing URL with embedded credentials: ${parsed.hostname}`);
  }
  if (isLocalHostname(parsed.hostname)) {
    throw new Error(`Refusing to fetch local/private address: ${parsed.hostname}`);
  }
  if (checkDns && await resolvesToPrivateAddress(parsed.hostname)) {
    throw new Error(`Refusing to fetch host that resolves to a private address: ${parsed.hostname}`);
  }
  return parsed;
}

function isRedirectStatus(status) {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
}

/**
 * fetch() with manual redirect handling so every hop is validated.
 *
 * @param {string|URL} url
 * @param {object} options
 * @param {Function} [options.fetchImpl] - fetch implementation (default globalThis.fetch)
 * @param {number} [options.maxRedirects]
 * @param {(url: URL, hop: number) => Promise<void>|void} options.validate - throws to reject a hop
 * @param {(url: URL) => Record<string,string>} [options.headersFor] - per-hop headers (e.g. auth only for trusted hosts)
 * @param {object} [options.init] - extra fetch init (method, signal, ...)
 * @returns {Promise<{ response: Response, url: URL, hops: number }>}
 */
export async function fetchWithSafeRedirects(url, options) {
  const {
    fetchImpl = globalThis.fetch,
    maxRedirects = DEFAULT_MAX_REDIRECTS,
    validate,
    headersFor = () => ({}),
    init = {},
  } = options || {};

  if (typeof fetchImpl !== 'function') {
    throw new Error('Fetch API is not available in this Node.js runtime');
  }
  if (typeof validate !== 'function') {
    throw new Error('fetchWithSafeRedirects requires a validate() callback');
  }

  let current = url instanceof URL ? url : parseHttpUrl(url);
  for (let hop = 0; hop <= maxRedirects; hop += 1) {
    await validate(current, hop);
    const response = await fetchImpl(current.toString(), {
      ...init,
      headers: headersFor(current) || {},
      redirect: 'manual',
    });

    const status = response?.status ?? 0;
    const location = response?.headers?.get?.('location');
    if (!isRedirectStatus(status) || !location) {
      return { response, url: current, hops: hop };
    }

    // Drain the redirect body so the socket can be reused.
    try {
      await response.body?.cancel?.();
    } catch {
      // ignore
    }

    let next;
    try {
      next = new URL(location, current);
    } catch {
      throw new Error(`Invalid redirect location from ${current.hostname}: ${location}`);
    }
    if (next.protocol !== 'http:' && next.protocol !== 'https:') {
      throw new Error(`Refusing redirect to non-http(s) URL: ${next.protocol}`);
    }
    if (hop === maxRedirects) {
      throw new Error(`Too many redirects (limit ${maxRedirects}) fetching ${url}`);
    }
    current = next;
  }

  throw new Error(`Too many redirects (limit ${maxRedirects}) fetching ${url}`);
}

/**
 * Read a Response body into a Buffer, aborting once maxBytes is exceeded
 * (does not trust content-length).
 * @param {Response} response
 * @param {number} maxBytes
 * @returns {Promise<Buffer>}
 */
export async function readBodyWithLimit(response, maxBytes) {
  const declared = Number.parseInt(response?.headers?.get?.('content-length') || '', 10);
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new Error(`Response exceeds maxBytes (${maxBytes} bytes)`);
  }

  if (!response?.body || typeof response.body.getReader !== 'function') {
    const buffer = Buffer.from(await response.arrayBuffer());
    if (buffer.length > maxBytes) {
      throw new Error(`Response exceeds maxBytes (${maxBytes} bytes)`);
    }
    return buffer;
  }

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        throw new Error(`Response exceeds maxBytes (${maxBytes} bytes)`);
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    try {
      await reader.cancel?.();
    } catch {
      // ignore
    }
  }
  return Buffer.concat(chunks, total);
}
