/**
 * Tests for ZIP Bomb Protection
 *
 * Verifies that ZIP bomb detection catches:
 * - Individual files exceeding the 50MB limit
 * - Total uncompressed size exceeding the 500MB limit
 * - Suspicious compression ratios (>1000:1)
 */

import { describe, it, expect } from 'vitest';
import {
  validateZipEntries,
  MAX_ZIP_ENTRY_SIZE,
  MAX_ZIP_TOTAL_SIZE,
  type ZipEntryInfo,
} from '@/lib/security/zip-bomb-protection';

describe('validateZipEntries', () => {
  it('should allow normal-sized entries', () => {
    const entries: ZipEntryInfo[] = [
      { name: 'template.json', uncompressedSize: 1024, compressedSize: 512, date: null },
      { name: 'index.html', uncompressedSize: 5000, compressedSize: 2000, date: null },
    ];

    expect(() => validateZipEntries(entries)).not.toThrow();
  });

  it('should reject a single file exceeding 50MB uncompressed', () => {
    const entries: ZipEntryInfo[] = [
      { name: 'huge-file.txt', uncompressedSize: 60 * 1024 * 1024, compressedSize: 1024, date: null },
    ];

    expect(() => validateZipEntries(entries)).toThrow(/too large when uncompressed/);
    expect(() => validateZipEntries(entries)).toThrow(/ZIP bomb/);
  });

  it('should reject total uncompressed size exceeding 500MB', () => {
    const entries: ZipEntryInfo[] = Array.from({ length: 11 }, (_, i) => ({
      name: `file-${i}.txt`,
      uncompressedSize: 50 * 1024 * 1024 - 1, // Just under 50MB each
      compressedSize: 25 * 1024 * 1024, // Reasonable compression ratio
      date: null,
    }));

    // 11 * ~50MB = ~550MB > 500MB
    expect(() => validateZipEntries(entries)).toThrow(/Total uncompressed size/);
    expect(() => validateZipEntries(entries)).toThrow(/ZIP bomb/);
  });

  it('should reject entries with suspicious compression ratio (>1000:1)', () => {
    const entries: ZipEntryInfo[] = [
      { name: 'bomb.txt', uncompressedSize: 10 * 1024 * 1024, compressedSize: 100, date: null },
      // 10MB uncompressed, 100B compressed = 100,000:1 ratio
    ];

    expect(() => validateZipEntries(entries)).toThrow(/suspicious compression ratio/);
    expect(() => validateZipEntries(entries)).toThrow(/ZIP bomb/);
  });

  it('should allow entries with reasonable compression ratio', () => {
    const entries: ZipEntryInfo[] = [
      { name: 'data.json', uncompressedSize: 100 * 1024, compressedSize: 10 * 1024, date: null },
      // 100KB uncompressed, 10KB compressed = 10:1 ratio
    ];

    expect(() => validateZipEntries(entries)).not.toThrow();
  });

  it('should allow entries with zero compressed size', () => {
    const entries: ZipEntryInfo[] = [
      { name: 'empty.txt', uncompressedSize: 0, compressedSize: 0, date: null },
    ];

    expect(() => validateZipEntries(entries)).not.toThrow();
  });

  it('should allow exactly 50MB uncompressed', () => {
    const entries: ZipEntryInfo[] = [
      { name: 'max-size.txt', uncompressedSize: MAX_ZIP_ENTRY_SIZE, compressedSize: MAX_ZIP_ENTRY_SIZE / 2, date: null },
    ];

    expect(() => validateZipEntries(entries)).not.toThrow();
  });

  it('should allow exactly 500MB total uncompressed', () => {
    const entries: ZipEntryInfo[] = Array.from({ length: 10 }, (_, i) => ({
      name: `file-${i}.txt`,
      uncompressedSize: MAX_ZIP_ENTRY_SIZE, // 50MB each = 500MB total
      compressedSize: MAX_ZIP_ENTRY_SIZE / 2,
      date: null,
    }));

    expect(() => validateZipEntries(entries)).not.toThrow();
  });

  it('should reject blueprint test case: ZIP bomb', () => {
    // Blueprint: "Upload a ZIP bomb → Should be rejected before extraction"
    const entries: ZipEntryInfo[] = [
      { name: 'bomb.txt', uncompressedSize: 4 * 1024 * 1024 * 1024, compressedSize: 42 * 1024, date: null },
      // Classic ZIP bomb: 42KB → 4.5GB
    ];

    expect(() => validateZipEntries(entries)).toThrow();
  });
});
