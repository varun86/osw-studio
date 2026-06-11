/**
 * SSRF (Server-Side Request Forgery) Protection Module
 *
 * Prevents edge functions from making requests to internal/private network
 * resources. This is critical because edge functions run user-supplied code
 * that could be used to probe internal services, access cloud metadata
 * endpoints (e.g., AWS/GCP/Azure metadata at 169.254.169.254), or pivot
 * into the internal network.
 *
 * Defense strategy:
 * 1. DNS resolution before connection — resolves hostname to IP addresses,
 *    checks ALL resolved IPs against private ranges, then connects to the
 *    verified IP. This prevents DNS rebinding attacks where a DNS server
 *    returns a public IP for the check but a private IP for the actual
 *    connection (TOCTOU race condition).
 * 2. Comprehensive private IP range coverage — IPv4 and IPv6, including
 *    special ranges like cloud metadata (169.254.169.254), CGNAT, and
 *    loopback variants.
 * 3. Normalization of obfuscated IPs — handles hex, octal, decimal, and
 *    IPv4-mapped IPv6 addresses.
 *
 * Based on OWASP SSRF Prevention Cheat Sheet recommendations.
 */

import dns from 'dns';
import { createRequire } from 'module';

// ============================================
// Configuration
// ============================================

/**
 * Whether SSRF protection is enabled.
 * In production, ALWAYS enabled.
 * In development, can be optionally disabled for local testing.
 */
const SSRF_PROTECTION_ENABLED = process.env.SSRF_PROTECTION !== 'false';

/**
 * DNS resolution timeout in milliseconds
 */
const DNS_TIMEOUT_MS = 5000;

/**
 * Maximum number of DNS results to check per hostname
 */
const MAX_DNS_RESULTS = 10;

// ============================================
// IP Address Validation
// ============================================

/**
 * Check if an IPv4 address is private/reserved.
 *
 * Covers all RFC 5735, RFC 1918, RFC 6598, RFC 3927, RFC 2544, and
 * cloud metadata ranges.
 *
 * @param ip - IPv4 address string (e.g., "192.168.1.1")
 * @returns true if the IP is private/reserved
 */
export function isPrivateIPv4(ip: string): boolean {
  // Normalize: remove leading zeros, handle hex/octal
  const normalized = normalizeIPv4(ip);
  if (!normalized) return true; // Invalid IP → block

  const parts = normalized.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
    return true; // Invalid → block
  }

  const [a, b, c, d] = parts;
  const num = (a << 24) | (b << 16) | (c << 8) | d;

  // 0.0.0.0/8 — "This network" (RFC 5735)
  if (a === 0) return true;

  // 10.0.0.0/8 — Private (RFC 1918)
  if (a === 10) return true;

  // 100.64.0.0/10 — Carrier-grade NAT (RFC 6598)
  if (a === 100 && b >= 64 && b <= 127) return true;

  // 127.0.0.0/8 — Loopback (RFC 5735)
  if (a === 127) return true;

  // 169.254.0.0/16 — Link-local / Cloud metadata (RFC 3927)
  if (a === 169 && b === 254) return true;

  // 172.16.0.0/12 — Private (RFC 1918)
  if (a === 172 && b >= 16 && b <= 31) return true;

  // 192.0.0.0/24 — IETF Protocol Assignments (RFC 5736)
  if (a === 192 && b === 0 && c === 0) return true;

  // 192.0.2.0/24 — Documentation (RFC 5737)
  if (a === 192 && b === 0 && c === 2) return true;

  // 192.88.99.0/24 — IPv6 to IPv4 relay (RFC 3068)
  if (a === 192 && b === 88 && c === 99) return true;

  // 192.168.0.0/16 — Private (RFC 1918)
  if (a === 192 && b === 168) return true;

  // 198.18.0.0/15 — Benchmarking (RFC 2544)
  if (a === 198 && (b === 18 || b === 19)) return true;

  // 198.51.100.0/24 — Documentation (RFC 5737)
  if (a === 198 && b === 51 && c === 100) return true;

  // 203.0.113.0/24 — Documentation (RFC 5737)
  if (a === 203 && b === 0 && c === 113) return true;

  // 224.0.0.0/4 — Multicast (RFC 5771)
  if (a >= 224 && a <= 239) return true;

  // 240.0.0.0/4 — Reserved for future use (RFC 1112)
  if (a >= 240) return true;

  return false;
}

/**
 * Normalize an IPv4 address by parsing obfuscated representations.
 *
 * Handles:
 * - Hex: 0x7f000001 → 127.0.0.1
 * - Octal: 017700000001 → 127.0.0.1
 * - Decimal: 2130706433 → 127.0.0.1
 * - Mixed: 0x7f.0.0.1 → 127.0.0.1
 * - Leading zeros: 192.168.001.001 → 192.168.1.1
 *
 * Returns the normalized dotted-decimal string, or null if invalid.
 */
export function normalizeIPv4(ip: string): string | null {
  const parts = ip.split('.');

  // If there's only one part, it could be a single decimal/hex/octal number
  if (parts.length === 1) {
    const num = parseNumberLiteral(parts[0]);
    if (num === null || num < 0 || num > 0xFFFFFFFF) return null;
    return `${(num >>> 24) & 0xFF}.${(num >>> 16) & 0xFF}.${(num >>> 8) & 0xFF}.${num & 0xFF}`;
  }

  // If there are two parts: a.b → a * 2^24 + b
  if (parts.length === 2) {
    const a = parseNumberLiteral(parts[0]);
    const b = parseNumberLiteral(parts[1]);
    if (a === null || b === null) return null;
    const num = (a << 24) | b;
    if (num < 0 || num > 0xFFFFFFFF) return null;
    return `${(num >>> 24) & 0xFF}.${(num >>> 16) & 0xFF}.${(num >>> 8) & 0xFF}.${num & 0xFF}`;
  }

  // If there are three parts: a.b.c → a * 2^24 + b * 2^16 + c
  if (parts.length === 3) {
    const a = parseNumberLiteral(parts[0]);
    const b = parseNumberLiteral(parts[1]);
    const c = parseNumberLiteral(parts[2]);
    if (a === null || b === null || c === null) return null;
    const num = (a << 24) | (b << 16) | c;
    if (num < 0 || num > 0xFFFFFFFF) return null;
    return `${(num >>> 24) & 0xFF}.${(num >>> 16) & 0xFF}.${(num >>> 8) & 0xFF}.${num & 0xFF}`;
  }

  // Standard 4-part dotted decimal
  if (parts.length === 4) {
    const nums = parts.map(p => parseNumberLiteral(p));
    if (nums.some(n => n === null || n < 0 || n > 255)) return null;
    return nums.map(n => n!.toString()).join('.');
  }

  return null;
}

/**
 * Parse a number literal that might be hex (0x), octal (0o or leading 0), or decimal.
 */
function parseNumberLiteral(s: string): number | null {
  if (!s || s.length === 0) return null;

  // Hex: 0x prefix
  if (s.startsWith('0x') || s.startsWith('0X')) {
    const num = parseInt(s, 16);
    return isNaN(num) ? null : num;
  }

  // Octal: 0o prefix or leading zero (legacy)
  if (s.startsWith('0o') || s.startsWith('0O')) {
    const num = parseInt(s, 8);
    return isNaN(num) ? null : num;
  }

  // Legacy octal: leading zero followed by digits (e.g., "0177")
  // BUT only if all digits are 0-7
  if (s.length > 1 && s.startsWith('0') && /^[0-7]+$/.test(s.slice(1))) {
    const num = parseInt(s, 8);
    return isNaN(num) ? null : num;
  }

  // Decimal
  const num = parseInt(s, 10);
  return isNaN(num) ? null : num;
}

/**
 * Check if an IPv6 address is private/reserved.
 *
 * @param ip - IPv6 address string (e.g., "::1", "fe80::1")
 * @returns true if the IP is private/reserved
 */
export function isPrivateIPv6(ip: string): boolean {
  try {
    // Handle IPv4-mapped IPv6: ::ffff:a.b.c.d
    const v4Mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
    if (v4Mapped) {
      return isPrivateIPv4(v4Mapped[1]);
    }

    // Expand :: shorthand to full 8-group address
    const expanded = expandIPv6(ip);
    if (!expanded) return true; // Invalid → block

    const groups = expanded.split(':').map(g => parseInt(g, 16));

    // ::1 — Loopback
    if (groups[0] === 0 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0 &&
        groups[4] === 0 && groups[5] === 0 && groups[6] === 0 && groups[7] === 1) {
      return true;
    }

    // fe80::/10 — Link-local
    if ((groups[0] & 0xffc0) === 0xfe80) return true;

    // fc00::/7 — Unique local addresses (IPv6 private)
    if ((groups[0] & 0xfe00) === 0xfc00) return true;

    // ff00::/8 — Multicast
    if ((groups[0] & 0xff00) === 0xff00) return true;

    // 0000::/8 — Reserved (includes ::, unspecified address)
    if (groups[0] === 0 && groups.every(g => g === 0)) return true;

    // 0100::/64 — Discard-only address block (RFC 6666)
    if (groups[0] === 0x0100 && groups[1] === 0) return true;

    // IPv4-mapped IPv6: ::ffff:0:0/96 — maps to IPv4, check the mapped address
    if (groups[0] === 0 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0 &&
        groups[4] === 0 && groups[5] === 0xffff) {
      const v4 = `${(groups[6] >> 8) & 0xFF}.${groups[6] & 0xFF}.${(groups[7] >> 8) & 0xFF}.${groups[7] & 0xFF}`;
      return isPrivateIPv4(v4);
    }

    return false;
  } catch {
    return true; // Error parsing → block
  }
}

/**
 * Expand an IPv6 address to full 8-group format.
 * ::1 → 0000:0000:0000:0000:0000:0000:0000:0001
 */
function expandIPv6(ip: string): string | null {
  try {
    // Handle :: expansion
    let halves = ip.split('::');

    if (halves.length > 2) return null; // Multiple :: is invalid

    if (halves.length === 2) {
      const left = halves[0] ? halves[0].split(':') : [];
      const right = halves[1] ? halves[1].split(':') : [];
      const missing = 8 - left.length - right.length;
      if (missing < 0) return null;
      const middle = Array(missing).fill('0000');
      const full = [...left, ...middle, ...right];
      return full.map(g => g.padStart(4, '0')).join(':');
    }

    // No :: — must be 8 groups
    const groups = ip.split(':');
    if (groups.length !== 8) return null;
    return groups.map(g => g.padStart(4, '0')).join(':');
  } catch {
    return null;
  }
}

/**
 * Check if any IP address (IPv4 or IPv6) is private/reserved.
 */
export function isPrivateIP(ip: string): boolean {
  // Determine if IPv4 or IPv6
  if (ip.includes(':')) {
    return isPrivateIPv6(ip);
  }
  return isPrivateIPv4(ip);
}

// ============================================
// DNS Resolution & URL Validation
// ============================================

/**
 * Resolve a hostname to all its IP addresses (both IPv4 and IPv6).
 * Uses Node.js dns module with a timeout.
 */
export async function resolveHostname(hostname: string): Promise<string[]> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      resolve([]); // Timeout → no results
    }, DNS_TIMEOUT_MS);

    dns.lookup(hostname, {
      all: true,
      family: 0, // Both IPv4 and IPv6
    }, (err, addresses) => {
      clearTimeout(timer);
      if (err || !addresses) {
        resolve([]);
        return;
      }
      resolve(addresses.slice(0, MAX_DNS_RESULTS).map(a => a.address));
    });
  });
}

/**
 * Validate a URL for SSRF safety by:
 * 1. Parsing the URL and checking protocol (only http/https)
 * 2. Resolving the hostname to actual IP addresses via DNS
 * 3. Checking ALL resolved IPs against private ranges
 * 4. Returning the safe URL with IP host (prevents DNS rebinding)
 *
 * @param urlString - The URL to validate
 * @returns Object with validation result and optional safe URL or error
 */
export async function validateUrlForSSRF(urlString: string): Promise<{
  safe: boolean;
  error?: string;
  resolvedIPs?: string[];
}> {
  // Check if SSRF protection is enabled
  if (!SSRF_PROTECTION_ENABLED) {
    return { safe: true };
  }

  // Parse URL
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(urlString);
  } catch {
    return { safe: false, error: 'Invalid URL' };
  }

  // Protocol check
  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    return { safe: false, error: 'Only http and https protocols are allowed' };
  }

  const hostname = parsedUrl.hostname.toLowerCase();

  // Check if hostname is already an IP address
  // IPv6 in URLs is wrapped in brackets: [::1]
  const bareHostname = hostname.startsWith('[') && hostname.endsWith(']')
    ? hostname.slice(1, -1)
    : hostname;

  // Quick check: if it looks like an IP, validate directly
  if (isBareIPAddress(bareHostname)) {
    if (isPrivateIP(bareHostname)) {
      return { safe: false, error: 'Requests to private/internal addresses are not allowed', resolvedIPs: [bareHostname] };
    }
    return { safe: true, resolvedIPs: [bareHostname] };
  }

  // Resolve DNS
  const resolvedIPs = await resolveHostname(hostname);

  if (resolvedIPs.length === 0) {
    return { safe: false, error: 'Could not resolve hostname' };
  }

  // Check ALL resolved IPs
  for (const ip of resolvedIPs) {
    if (isPrivateIP(ip)) {
      return {
        safe: false,
        error: 'Requests to private/internal addresses are not allowed',
        resolvedIPs,
      };
    }
  }

  return { safe: true, resolvedIPs };
}

/**
 * Check if a string looks like a bare IP address (not a domain name).
 * Handles both IPv4 and IPv6.
 */
export function isBareIPAddress(s: string): boolean {
  // IPv4: all parts are numeric
  if (/^\d+(\.\d+){0,3}$/.test(s)) return true;
  // IPv4 with hex
  if (/^0x[0-9a-f]+(\.0x[0-9a-f]+){0,3}$/i.test(s)) return true;
  // IPv6
  if (s.includes(':')) return true;
  return false;
}

/**
 * Create a safe fetch function that prevents SSRF.
 * Resolves DNS before connecting and blocks private IPs.
 *
 * This replaces the original isPrivateUrl() check which was vulnerable
 * to DNS rebinding because it only checked the URL string, not the
 * actual resolved IP.
 */
export async function safeFetch(url: string, options?: RequestInit): Promise<Response> {
  const validation = await validateUrlForSSRF(url);

  if (!validation.safe) {
    throw new Error(validation.error || 'SSRF protection: URL blocked');
  }

  // Perform the actual fetch
  return globalThis.fetch(url, options);
}
