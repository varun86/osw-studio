/**
 * Tests for Path Traversal Protection in Static Builder
 *
 * Validates that the static builder correctly rejects malicious file paths
 * that attempt to write outside the deployment output directory.
 *
 * These tests cover the defense-in-depth approach:
 *   1. isPathSafe() pre-check rejects obvious traversal patterns
 *   2. sanitizeFilePath() resolves and validates the full path
 *   3. validateDeploymentId() ensures the deployment ID is safe
 */

import { describe, it, expect } from 'vitest';
import path from 'path';
import { validateSafePath, sanitizeFilePath, isPathSafe } from '@/lib/security/path-safety';

// ─── validateDeploymentId equivalent tests (inline since function is private) ───

describe('Deployment ID Validation (static-builder)', () => {
  // Mirrors the validateDeploymentId() function in static-builder.ts
  function validateDeploymentId(deploymentId: string): void {
    if (!deploymentId || typeof deploymentId !== 'string') {
      throw new Error('Invalid deployment ID: must be a non-empty string');
    }
    if (!/^[a-zA-Z0-9_-]+$/.test(deploymentId)) {
      throw new Error(
        `Invalid deployment ID: "${deploymentId}" contains disallowed characters. ` +
        'Only alphanumeric characters, hyphens, and underscores are permitted.'
      );
    }
  }

  it('should accept valid alphanumeric deployment IDs', () => {
    expect(() => validateDeploymentId('abc123')).not.toThrow();
    expect(() => validateDeploymentId('deploy-001')).not.toThrow();
    expect(() => validateDeploymentId('my_deployment')).not.toThrow();
    expect(() => validateDeploymentId('ABC-xyz_123')).not.toThrow();
  });

  it('should reject empty deployment ID', () => {
    expect(() => validateDeploymentId('')).toThrow('must be a non-empty string');
  });

  it('should reject deployment ID with path traversal', () => {
    expect(() => validateDeploymentId('../etc')).toThrow('disallowed characters');
    expect(() => validateDeploymentId('..')).toThrow('disallowed characters');
    expect(() => validateDeploymentId('deploy/../../etc')).toThrow('disallowed characters');
  });

  it('should reject deployment ID with path separators', () => {
    expect(() => validateDeploymentId('deploy/evil')).toThrow('disallowed characters');
    expect(() => validateDeploymentId('deploy\\evil')).toThrow('disallowed characters');
  });

  it('should reject deployment ID with special characters', () => {
    expect(() => validateDeploymentId('deploy;rm -rf')).toThrow('disallowed characters');
    expect(() => validateDeploymentId('deploy$(cmd)')).toThrow('disallowed characters');
    expect(() => validateDeploymentId('deploy\x00evil')).toThrow('disallowed characters');
  });
});

// ─── isPathSafe pre-check tests for VFS file paths ───

describe('isPathSafe pre-check for static builder file paths', () => {
  it('should accept safe file paths', () => {
    expect(isPathSafe('index.html')).toBe(true);
    expect(isPathSafe('assets/style.css')).toBe(true);
    expect(isPathSafe('js/app.min.js')).toBe(true);
    expect(isPathSafe('images/logo.png')).toBe(true);
    expect(isPathSafe('a/b/c/d/file.txt')).toBe(true);
  });

  it('should reject path traversal with ..', () => {
    expect(isPathSafe('../../../tmp/evil')).toBe(false);
    expect(isPathSafe('../secret')).toBe(false);
    expect(isPathSafe('assets/../../etc/passwd')).toBe(false);
    expect(isPathSafe('..')).toBe(false);
  });

  it('should reject null byte injection', () => {
    expect(isPathSafe('file.txt\x00.jpg')).toBe(false);
  });

  it('should reject Windows-style backslash traversal', () => {
    expect(isPathSafe('..\\secret')).toBe(false);
    expect(isPathSafe('assets\\..\\..\\etc')).toBe(false);
  });
});

// ─── sanitizeFilePath integration with deployment output directory ───

describe('sanitizeFilePath with deployment output directory', () => {
  const outputDir = '/app/public/deployments/abc-123';

  it('should resolve safe file paths within the output directory', () => {
    const result = sanitizeFilePath('index.html', outputDir);
    expect(result).toBe(path.resolve(outputDir, 'index.html'));

    const nested = sanitizeFilePath('assets/images/logo.png', outputDir);
    expect(nested).toBe(path.resolve(outputDir, 'assets/images/logo.png'));
  });

  it('should handle VFS paths that start with / (common pattern)', () => {
    // VFS paths often start with /, e.g. /index.html, /assets/style.css
    const result = sanitizeFilePath('/index.html', outputDir);
    expect(result).toBe(path.resolve(outputDir, 'index.html'));

    const nested = sanitizeFilePath('/assets/style.css', outputDir);
    expect(nested).toBe(path.resolve(outputDir, 'assets/style.css'));
  });

  it('should reject path traversal in VFS paths', () => {
    expect(() => sanitizeFilePath('/../../../tmp/evil', outputDir)).toThrow('Path traversal detected');
    expect(() => sanitizeFilePath('/../../etc/passwd', outputDir)).toThrow('Path traversal detected');
    expect(() => sanitizeFilePath('../secret', outputDir)).toThrow('Path traversal detected');
  });

  it('should reject traversal hidden in deeper paths', () => {
    expect(() => sanitizeFilePath('/assets/../../etc/shadow', outputDir)).toThrow('Path traversal detected');
    expect(() => sanitizeFilePath('/js/../../../tmp/evil.js', outputDir)).toThrow('Path traversal detected');
  });

  it('should remove null bytes and still reject traversal', () => {
    // Null bytes are removed, but traversal still detected
    expect(() => sanitizeFilePath('/..\x00/../etc/passwd', outputDir)).toThrow('Path traversal detected');
  });

  it('should not allow prefix attacks on the output directory', () => {
    // e.g., if outputDir is /app/public/deployments/abc
    // path /app/public/deployments/abc-backup/evil should not be accessible
    // This is handled by the startsWith(baseDir + path.sep) check
    const siblingDir = '/app/public/deployments/abc';
    expect(() => sanitizeFilePath('/../abc-backup/evil', siblingDir)).toThrow('Path traversal detected');
  });
});

// ─── Defense-in-depth: both isPathSafe AND sanitizeFilePath ───

describe('Defense-in-depth: combined isPathSafe + sanitizeFilePath', () => {
  const outputDir = '/app/public/deployments/test-deploy';

  // Simulates the static builder's file writing loop logic
  function simulateStaticBuilderWrite(filePath: string): { safe: boolean; reason?: string } {
    // Layer 1: isPathSafe pre-check
    if (!isPathSafe(filePath)) {
      return { safe: false, reason: 'isPathSafe rejected: contains traversal pattern' };
    }

    // Layer 2: sanitizeFilePath resolution
    try {
      const resolved = sanitizeFilePath(filePath, outputDir);
      // Verify it's within the output directory
      if (!resolved.startsWith(path.resolve(outputDir) + path.sep) && resolved !== path.resolve(outputDir)) {
        return { safe: false, reason: 'Resolved path escapes output directory' };
      }
      return { safe: true };
    } catch (e) {
      return { safe: false, reason: (e as Error).message };
    }
  }

  it('should allow normal VFS file paths', () => {
    expect(simulateStaticBuilderWrite('index.html').safe).toBe(true);
    expect(simulateStaticBuilderWrite('/index.html').safe).toBe(true);
    expect(simulateStaticBuilderWrite('/assets/style.css').safe).toBe(true);
    expect(simulateStaticBuilderWrite('/js/app.bundle.js').safe).toBe(true);
  });

  it('should catch traversal at the isPathSafe layer', () => {
    const result = simulateStaticBuilderWrite('/../../../tmp/evil');
    expect(result.safe).toBe(false);
    expect(result.reason).toContain('isPathSafe rejected');
  });

  it('should catch traversal at the sanitizeFilePath layer if isPathSafe is bypassed', () => {
    // Hypothetical: if isPathSafe has a bug, sanitizeFilePath still catches it
    // Direct test of sanitizeFilePath alone
    expect(() => sanitizeFilePath('/../../../tmp/evil', outputDir)).toThrow('Path traversal detected');
  });

  it('should reject all known path traversal attack vectors', () => {
    const attackVectors = [
      '/../../../tmp/evil',           // Classic traversal
      '/../../etc/passwd',            // Reading system files
      '../secret',                    // Relative traversal
      '/assets/../../etc/shadow',     // Hidden traversal
      '/..\x00/../etc/passwd',        // Null byte + traversal
      '/./../../tmp/evil',            // Mixed . and ..
      '//../../../tmp/evil',          // Double slash traversal
    ];

    for (const vector of attackVectors) {
      const result = simulateStaticBuilderWrite(vector);
      expect(result.safe).toBe(false);
    }
  });
});
