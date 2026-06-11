/**
 * Tests for Path Safety utilities
 */

import { describe, it, expect } from 'vitest';
import path from 'path';
import { validateSafePath, sanitizeFilePath, isPathSafe } from '../path-safety';

describe('validateSafePath', () => {
  const baseDir = '/app/data/deployments/abc123';

  it('should allow safe relative paths', () => {
    const result = validateSafePath('index.html', baseDir);
    expect(result).toBe(path.resolve(baseDir, 'index.html'));
  });

  it('should allow nested safe paths', () => {
    const result = validateSafePath('assets/images/logo.png', baseDir);
    expect(result).toBe(path.resolve(baseDir, 'assets/images/logo.png'));
  });

  it('should reject path traversal with ..', () => {
    expect(() => validateSafePath('../../etc/passwd', baseDir)).toThrow('Path traversal detected');
  });

  it('should reject single parent traversal', () => {
    expect(() => validateSafePath('../secret', baseDir)).toThrow('Path traversal detected');
  });

  it('should reject traversal hidden in deeper path', () => {
    expect(() => validateSafePath('assets/../../etc/shadow', baseDir)).toThrow('Path traversal detected');
  });

  it('should reject null byte injection', () => {
    expect(() => validateSafePath('file.txt\0.jpg', baseDir)).toThrow('null byte');
  });

  it('should reject absolute paths', () => {
    expect(() => validateSafePath('/etc/passwd', baseDir)).toThrow('Absolute paths are not allowed');
  });
});

describe('sanitizeFilePath', () => {
  const baseDir = '/app/data/deployments/abc123';

  it('should remove leading slash and validate', () => {
    const result = sanitizeFilePath('/index.html', baseDir);
    expect(result).toBe(path.resolve(baseDir, 'index.html'));
  });

  it('should remove null bytes and validate', () => {
    const result = sanitizeFilePath('file\0.txt', baseDir);
    expect(result).toBe(path.resolve(baseDir, 'file.txt'));
  });

  it('should still reject traversal after sanitization', () => {
    expect(() => sanitizeFilePath('/../../etc/passwd', baseDir)).toThrow('Path traversal detected');
  });

  it('should handle paths with leading slash and no traversal', () => {
    const result = sanitizeFilePath('/assets/style.css', baseDir);
    expect(result).toBe(path.resolve(baseDir, 'assets/style.css'));
  });
});

describe('isPathSafe', () => {
  it('should return true for safe paths', () => {
    expect(isPathSafe('index.html')).toBe(true);
    expect(isPathSafe('assets/images/logo.png')).toBe(true);
    expect(isPathSafe('a/b/c/d/file.js')).toBe(true);
  });

  it('should return false for traversal paths', () => {
    expect(isPathSafe('../secret')).toBe(false);
    expect(isPathSafe('assets/../../etc/passwd')).toBe(false);
    expect(isPathSafe('..')).toBe(false);
  });

  it('should return false for null bytes', () => {
    expect(isPathSafe('file\0.txt')).toBe(false);
  });

  it('should handle Windows-style backslash traversal', () => {
    expect(isPathSafe('..\\secret')).toBe(false);
  });
});
