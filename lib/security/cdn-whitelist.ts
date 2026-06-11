/**
 * CDN Domain Whitelist for Dynamic Imports
 *
 * Prevents arbitrary code execution via dynamic import() of untrusted URLs.
 * The esbuild-bundler uses dynamic imports to load CDN-hosted compilers
 * (Svelte, Vue). Without a whitelist, an attacker could inject a malicious
 * CDN URL to execute arbitrary code in the Node.js context.
 *
 * Only URLs from explicitly allowed CDN domains may be dynamically imported.
 */

/**
 * Allowed CDN domains for dynamic imports.
 * These are the CDNs used by the esbuild-bundler for framework compilers.
 *
 * To add a new CDN, append its hostname to this array.
 */
const ALLOWED_CDN_DOMAINS: readonly string[] = [
  'esm.sh',
  'cdn.jsdelivr.net',
  // Allow local development CDN overrides
  'localhost',
  '127.0.0.1',
];

/**
 * Validate that a URL points to an allowed CDN domain.
 *
 * @param url - The URL to validate
 * @returns true if the URL's hostname is in the allowed CDN list
 * @throws Error if the URL is invalid or points to a disallowed domain
 */
export function isCdnUrlAllowed(url: string): boolean {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();

    return ALLOWED_CDN_DOMAINS.some(allowed =>
      hostname === allowed || hostname.endsWith(`.${allowed}`)
    );
  } catch {
    return false;
  }
}

/**
 * Validate a CDN URL and throw on disallowed domains.
 *
 * @param url - The URL to validate
 * @throws Error if the URL is not from an allowed CDN domain
 */
export function validateCdnUrl(url: string): void {
  if (!isCdnUrlAllowed(url)) {
    let hostname = '(invalid URL)';
    try {
      hostname = new URL(url).hostname;
    } catch {
      // Keep the default
    }
    throw new Error(
      `CDN import rejected: "${hostname}" is not an allowed CDN domain. ` +
      `Allowed domains: ${ALLOWED_CDN_DOMAINS.join(', ')}`
    );
  }
}

/**
 * Get the list of allowed CDN domains (for testing/display purposes).
 */
export function getAllowedCdnDomains(): readonly string[] {
  return ALLOWED_CDN_DOMAINS;
}
