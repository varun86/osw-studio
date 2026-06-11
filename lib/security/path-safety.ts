/**
 * Path Safety Utilities
 *
 * Prevents path traversal attacks (directory traversal / ../ attacks)
 * across all file operations in the application.
 *
 * Every user-controlled path component that is joined with a base directory
 * MUST be validated through these functions before any filesystem operation.
 */

/**
 * Validate that a relative path does not escape its parent directory.
 *
 * Checks for:
 * - Path traversal via `..` segments
 * - Null byte injection
 * - Absolute path injection (paths starting with /)
 *
 * @param relativePath - The relative path to validate (user-controlled)
 * @param baseDir - The base directory the path should be confined to
 * @returns The resolved, safe absolute path
 * @throws Error if the path attempts to escape the base directory
 */
export function validateSafePath(relativePath: string, baseDir: string): string {
  // Block null bytes (can truncate paths in C-based filesystem calls)
  if (relativePath.includes('\0')) {
    throw new Error(`Path contains null byte: ${relativePath}`);
  }

  // Block absolute paths (should be relative to baseDir)
  if (path.isAbsolute(relativePath)) {
    throw new Error(`Absolute paths are not allowed: ${relativePath}`);
  }

  // Resolve both paths to their canonical forms
  const resolvedBase = path.resolve(baseDir);
  const resolvedTarget = path.resolve(baseDir, relativePath);

  // Check that the resolved target is within the resolved base directory
  // Must start with baseDir + path.sep to prevent prefix attacks
  // e.g., baseDir="/app/data" should not match "/app/data-backup"
  if (!resolvedTarget.startsWith(resolvedBase + path.sep) && resolvedTarget !== resolvedBase) {
    throw new Error(
      `Path traversal detected: "${relativePath}" resolves to "${resolvedTarget}" which is outside "${resolvedBase}"`
    );
  }

  return resolvedTarget;
}

/**
 * Sanitize a file path by:
 * 1. Removing null bytes
 * 2. Removing leading slashes (convert absolute to relative)
 * 3. Resolving and verifying it stays within the base directory
 *
 * Returns the safe resolved path, or throws if path traversal is detected.
 */
export function sanitizeFilePath(filePath: string, baseDir: string): string {
  // Remove null bytes
  let sanitized = filePath.replace(/\0/g, '');

  // Remove leading slash to make it relative
  if (sanitized.startsWith('/')) {
    sanitized = sanitized.slice(1);
  }

  return validateSafePath(sanitized, baseDir);
}

/**
 * Check if a path contains traversal patterns without resolving.
 * Useful for quick pre-checks before expensive filesystem operations.
 *
 * Returns true if the path is SAFE (no traversal detected).
 */
export function isPathSafe(relativePath: string): boolean {
  // Check for null bytes
  if (relativePath.includes('\0')) return false;

  // Check for path traversal patterns
  const segments = relativePath.split(/[/\\]/);
  for (const segment of segments) {
    if (segment === '..') return false;
  }

  return true;
}

import path from 'path';
