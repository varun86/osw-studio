/**
 * Tests for CDN Domain Whitelist
 *
 * Validates that only allowed CDN domains can be used for dynamic imports,
 * preventing arbitrary code execution via import() of untrusted URLs.
 */

import { describe, it, expect } from 'vitest';
import { isCdnUrlAllowed, validateCdnUrl, getAllowedCdnDomains } from '../cdn-whitelist';

describe('isCdnUrlAllowed', () => {
  it('should allow esm.sh CDN URLs', () => {
    expect(isCdnUrlAllowed('https://esm.sh/svelte@4.2.0')).toBe(true);
    expect(isCdnUrlAllowed('https://esm.sh/vue@3.4.0')).toBe(true);
    expect(isCdnUrlAllowed('https://esm.sh/@vue/compiler-sfc@3.4.0')).toBe(true);
  });

  it('should allow cdn.jsdelivr.net CDN URLs', () => {
    expect(isCdnUrlAllowed('https://cdn.jsdelivr.net/npm/svelte@4.2.0/compiler.mjs')).toBe(true);
  });

  it('should allow subdomains of allowed CDN domains', () => {
    expect(isCdnUrlAllowed('https://cdn.esm.sh/svelte@4')).toBe(true);
    expect(isCdnUrlAllowed('https://fastly.cdn.jsdelivr.net/vue@3')).toBe(true);
  });

  it('should allow localhost for development', () => {
    expect(isCdnUrlAllowed('http://localhost:3000/compiler.js')).toBe(true);
    expect(isCdnUrlAllowed('http://127.0.0.1:3000/compiler.js')).toBe(true);
  });

  it('should reject arbitrary HTTPS URLs', () => {
    expect(isCdnUrlAllowed('https://evil.com/malware.js')).toBe(false);
    expect(isCdnUrlAllowed('https://attacker.net/payload.mjs')).toBe(false);
  });

  it('should reject attacker-controlled domains that look similar', () => {
    expect(isCdnUrlAllowed('https://esm.sh.evil.com/svelte')).toBe(false);
    expect(isCdnUrlAllowed('https://fake-esm.sh/evil')).toBe(false);
    expect(isCdnUrlAllowed('https://cdn.jsdelivr.net.evil.com/payload')).toBe(false);
  });

  it('should reject data: URLs', () => {
    expect(isCdnUrlAllowed('data:text/javascript,alert(1)')).toBe(false);
  });

  it('should reject blob: URLs', () => {
    expect(isCdnUrlAllowed('blob:https://example.com/123')).toBe(false);
  });

  it('should reject file: URLs', () => {
    expect(isCdnUrlAllowed('file:///etc/passwd')).toBe(false);
  });

  it('should reject invalid URLs', () => {
    expect(isCdnUrlAllowed('not-a-url')).toBe(false);
    expect(isCdnUrlAllowed('')).toBe(false);
  });

  it('should reject HTTP URLs to non-localhost', () => {
    expect(isCdnUrlAllowed('http://evil.com/compiler.js')).toBe(false);
  });
});

describe('validateCdnUrl', () => {
  it('should not throw for allowed CDN URLs', () => {
    expect(() => validateCdnUrl('https://esm.sh/svelte@4.2.0')).not.toThrow();
    expect(() => validateCdnUrl('https://cdn.jsdelivr.net/npm/vue@3')).not.toThrow();
  });

  it('should throw for disallowed CDN URLs', () => {
    expect(() => validateCdnUrl('https://evil.com/malware.js')).toThrow('CDN import rejected');
  });

  it('should include the hostname in the error message', () => {
    try {
      validateCdnUrl('https://evil.com/malware.js');
      expect.unreachable('Should have thrown');
    } catch (e) {
      expect((e as Error).message).toContain('evil.com');
      expect((e as Error).message).toContain('not an allowed CDN domain');
    }
  });

  it('should list allowed domains in the error message', () => {
    try {
      validateCdnUrl('https://evil.com/malware.js');
      expect.unreachable('Should have thrown');
    } catch (e) {
      expect((e as Error).message).toContain('esm.sh');
      expect((e as Error).message).toContain('cdn.jsdelivr.net');
    }
  });

  it('should handle invalid URLs gracefully', () => {
    expect(() => validateCdnUrl('not-a-url')).toThrow('CDN import rejected');
  });
});

describe('getAllowedCdnDomains', () => {
  it('should return the list of allowed domains', () => {
    const domains = getAllowedCdnDomains();
    expect(domains).toContain('esm.sh');
    expect(domains).toContain('cdn.jsdelivr.net');
    expect(domains).toContain('localhost');
  });

  it('should return a readonly array', () => {
    const domains = getAllowedCdnDomains();
    expect(Array.isArray(domains)).toBe(true);
    expect(domains.length).toBeGreaterThan(0);
  });
});

describe('Blueprint Step 6 test case: import("https://evil.com/malware.js")', () => {
  it('should reject import of malware from evil.com', () => {
    expect(() => validateCdnUrl('https://evil.com/malware.js')).toThrow('CDN import rejected');
  });

  it('should reject import from attacker-controlled subdomains', () => {
    expect(() => validateCdnUrl('https://evil.esm.sh.attacker.com/payload')).toThrow('CDN import rejected');
  });

  it('should allow import from legitimate esm.sh CDN', () => {
    expect(() => validateCdnUrl('https://esm.sh/svelte@4.2.0')).not.toThrow();
  });

  it('should allow import from legitimate jsdelivr CDN', () => {
    expect(() => validateCdnUrl('https://cdn.jsdelivr.net/npm/vue@3.4.0')).not.toThrow();
  });
});
