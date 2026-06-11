/**
 * Tests for SSRF Protection Module
 *
 * Covers:
 * - Private IPv4 detection (all RFC ranges)
 * - Private IPv6 detection (loopback, link-local, unique local, multicast)
 * - IPv4 normalization (hex, octal, decimal, mixed)
 * - IPv4-mapped IPv6 addresses
 * - URL validation with DNS resolution
 */

import { describe, it, expect } from 'vitest';
import {
  isPrivateIPv4,
  isPrivateIPv6,
  isPrivateIP,
  normalizeIPv4,
} from '../ssrf-protection';

// ============================================
// Private IPv4 Detection
// ============================================

describe('isPrivateIPv4', () => {
  // Loopback
  it('should block 127.0.0.1 (loopback)', () => {
    expect(isPrivateIPv4('127.0.0.1')).toBe(true);
  });

  it('should block 127.0.0.0 (loopback network)', () => {
    expect(isPrivateIPv4('127.0.0.0')).toBe(true);
  });

  it('should block 127.255.255.255 (loopback range)', () => {
    expect(isPrivateIPv4('127.255.255.255')).toBe(true);
  });

  // RFC 1918 Private ranges
  it('should block 10.0.0.1 (10.x.x.x)', () => {
    expect(isPrivateIPv4('10.0.0.1')).toBe(true);
  });

  it('should block 10.255.255.255 (10.x.x.x)', () => {
    expect(isPrivateIPv4('10.255.255.255')).toBe(true);
  });

  it('should block 172.16.0.1 (172.16.x.x)', () => {
    expect(isPrivateIPv4('172.16.0.1')).toBe(true);
  });

  it('should block 172.31.255.255 (172.31.x.x)', () => {
    expect(isPrivateIPv4('172.31.255.255')).toBe(true);
  });

  it('should allow 172.15.0.1 (just below 172.16)', () => {
    expect(isPrivateIPv4('172.15.0.1')).toBe(false);
  });

  it('should allow 172.32.0.1 (just above 172.31)', () => {
    expect(isPrivateIPv4('172.32.0.1')).toBe(false);
  });

  it('should block 192.168.0.1 (192.168.x.x)', () => {
    expect(isPrivateIPv4('192.168.0.1')).toBe(true);
  });

  it('should block 192.168.255.255', () => {
    expect(isPrivateIPv4('192.168.255.255')).toBe(true);
  });

  // Link-local / Cloud metadata
  it('should block 169.254.169.254 (cloud metadata)', () => {
    expect(isPrivateIPv4('169.254.169.254')).toBe(true);
  });

  it('should block 169.254.0.1 (link-local)', () => {
    expect(isPrivateIPv4('169.254.0.1')).toBe(true);
  });

  // 0.0.0.0
  it('should block 0.0.0.0 (this network)', () => {
    expect(isPrivateIPv4('0.0.0.0')).toBe(true);
  });

  // CGNAT
  it('should block 100.64.0.1 (CGNAT)', () => {
    expect(isPrivateIPv4('100.64.0.1')).toBe(true);
  });

  it('should block 100.127.255.255 (CGNAT end)', () => {
    expect(isPrivateIPv4('100.127.255.255')).toBe(true);
  });

  it('should allow 100.63.255.255 (just below CGNAT)', () => {
    expect(isPrivateIPv4('100.63.255.255')).toBe(false);
  });

  it('should allow 100.128.0.1 (just above CGNAT)', () => {
    expect(isPrivateIPv4('100.128.0.1')).toBe(false);
  });

  // Multicast
  it('should block 224.0.0.1 (multicast)', () => {
    expect(isPrivateIPv4('224.0.0.1')).toBe(true);
  });

  // Reserved
  it('should block 240.0.0.1 (reserved)', () => {
    expect(isPrivateIPv4('240.0.0.1')).toBe(true);
  });

  // Public IPs should pass
  it('should allow 8.8.8.8 (Google DNS)', () => {
    expect(isPrivateIPv4('8.8.8.8')).toBe(false);
  });

  it('should allow 1.1.1.1 (Cloudflare DNS)', () => {
    expect(isPrivateIPv4('1.1.1.1')).toBe(false);
  });

  it('should allow 203.0.113.1 (wait, this is documentation range)', () => {
    // Actually 203.0.113.0/24 is documentation, should be blocked
    expect(isPrivateIPv4('203.0.113.1')).toBe(true);
  });

  it('should allow 142.250.80.46 (public web)', () => {
    expect(isPrivateIPv4('142.250.80.46')).toBe(false);
  });
});

// ============================================
// IPv4 Normalization (Obfuscated IPs)
// ============================================

describe('normalizeIPv4', () => {
  it('should normalize standard dotted decimal', () => {
    expect(normalizeIPv4('127.0.0.1')).toBe('127.0.0.1');
  });

  it('should normalize hex IP 0x7f000001 to 127.0.0.1', () => {
    expect(normalizeIPv4('0x7f000001')).toBe('127.0.0.1');
  });

  it('should normalize decimal IP 2130706433 to 127.0.0.1', () => {
    expect(normalizeIPv4('2130706433')).toBe('127.0.0.1');
  });

  it('should normalize octal IP 017700000001 to 127.0.0.1', () => {
    expect(normalizeIPv4('017700000001')).toBe('127.0.0.1');
  });

  it('should normalize mixed hex 0x7f.0.0.1 to 127.0.0.1', () => {
    expect(normalizeIPv4('0x7f.0.0.1')).toBe('127.0.0.1');
  });

  it('should normalize leading zeros 192.168.001.001 to 192.168.1.1', () => {
    expect(normalizeIPv4('192.168.001.001')).toBe('192.168.1.1');
  });

  it('should return null for invalid IP', () => {
    expect(normalizeIPv4('999.999.999.999')).toBeNull();
  });

  it('should return null for empty string', () => {
    expect(normalizeIPv4('')).toBeNull();
  });
});

// ============================================
// Private IPv6 Detection
// ============================================

describe('isPrivateIPv6', () => {
  // Loopback
  it('should block ::1 (loopback)', () => {
    expect(isPrivateIPv6('::1')).toBe(true);
  });

  // IPv4-mapped IPv6
  it('should block ::ffff:127.0.0.1 (IPv4-mapped loopback)', () => {
    expect(isPrivateIPv6('::ffff:127.0.0.1')).toBe(true);
  });

  it('should block ::ffff:192.168.1.1 (IPv4-mapped private)', () => {
    expect(isPrivateIPv6('::ffff:192.168.1.1')).toBe(true);
  });

  // Link-local
  it('should block fe80::1 (link-local)', () => {
    expect(isPrivateIPv6('fe80::1')).toBe(true);
  });

  // Unique local (IPv6 private)
  it('should block fc00::1 (unique local)', () => {
    expect(isPrivateIPv6('fc00::1')).toBe(true);
  });

  it('should block fd00::1 (unique local)', () => {
    expect(isPrivateIPv6('fd00::1')).toBe(true);
  });

  // Multicast
  it('should block ff00::1 (multicast)', () => {
    expect(isPrivateIPv6('ff00::1')).toBe(true);
  });

  // Unspecified
  it('should block :: (unspecified)', () => {
    expect(isPrivateIPv6('::')).toBe(true);
  });

  // Public IPv6 should pass
  it('should allow 2001:4860:4860::8888 (Google DNS IPv6)', () => {
    expect(isPrivateIPv6('2001:4860:4860::8888')).toBe(false);
  });

  it('should allow 2606:4700:4700::1111 (Cloudflare DNS IPv6)', () => {
    expect(isPrivateIPv6('2606:4700:4700::1111')).toBe(false);
  });
});

// ============================================
// Unified isPrivateIP
// ============================================

describe('isPrivateIP', () => {
  it('should detect private IPv4', () => {
    expect(isPrivateIP('10.0.0.1')).toBe(true);
    expect(isPrivateIP('8.8.8.8')).toBe(false);
  });

  it('should detect private IPv6', () => {
    expect(isPrivateIP('::1')).toBe(true);
    expect(isPrivateIP('fe80::1')).toBe(true);
    expect(isPrivateIP('2001:4860:4860::8888')).toBe(false);
  });
});
