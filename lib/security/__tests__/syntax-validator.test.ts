/**
 * Tests for Safe JavaScript Syntax Validator (esbuild-based)
 *
 * Validates that the esbuild.transform()-based validator correctly
 * accepts valid code and rejects invalid/malicious code.
 */

import { describe, it, expect } from 'vitest';
import { validateJavaScriptSyntax } from '../syntax-validator';

describe('validateJavaScriptSyntax', () => {
  it('should accept valid JavaScript code', () => {
    const result = validateJavaScriptSyntax('return 1 + 2;');
    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it('should accept valid arrow function code', () => {
    const result = validateJavaScriptSyntax('const add = (a, b) => a + b; return add(1, 2);');
    expect(result.valid).toBe(true);
  });

  it('should accept code with async/await in async arrow function', () => {
    const result = validateJavaScriptSyntax('const fn = async () => { const res = await fetch("/api"); return res.json(); }; return fn();');
    expect(result.valid).toBe(true);
  });

  it('should reject invalid JavaScript syntax', () => {
    const result = validateJavaScriptSyntax('function {{{{');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('syntax error');
  });

  it('should reject code with unclosed brackets', () => {
    const result = validateJavaScriptSyntax('const obj = { a: 1');
    expect(result.valid).toBe(false);
  });

  it('should reject empty code', () => {
    const result = validateJavaScriptSyntax('');
    expect(result.valid).toBe(false);
  });

  it('should reject non-string code', () => {
    const result = validateJavaScriptSyntax(null as unknown as string);
    expect(result.valid).toBe(false);
  });

  it('should reject null bytes in code', () => {
    const result = validateJavaScriptSyntax('const x = 1;\0const y = 2;');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('null bytes');
  });

  it('should reject extremely long code', () => {
    const longCode = 'const x = 1;' + 'x'.repeat(600_000);
    const result = validateJavaScriptSyntax(longCode);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('too long');
  });

  it('should validate with parameter names', () => {
    const result = validateJavaScriptSyntax('return db.query("SELECT 1");', ['args', 'db', 'fetch', 'console']);
    expect(result.valid).toBe(true);
  });

  it('should reject invalid syntax even with parameter names', () => {
    const result = validateJavaScriptSyntax('return {{{{', ['args', 'db']);
    expect(result.valid).toBe(false);
  });

  it('should accept code with try/catch', () => {
    const result = validateJavaScriptSyntax('try { return JSON.parse(args); } catch (e) { return null; }');
    expect(result.valid).toBe(true);
  });

  it('should accept code with template literals', () => {
    const result = validateJavaScriptSyntax('return `Hello ${args.name}`;');
    expect(result.valid).toBe(true);
  });

  // ─── New tests for esbuild-based validation ───

  it('should accept code with class declarations', () => {
    const result = validateJavaScriptSyntax('class Foo { constructor() { this.x = 1; } } return new Foo();');
    expect(result.valid).toBe(true);
  });

  it('should accept code with destructuring', () => {
    const result = validateJavaScriptSyntax('const { a, b } = args; return a + b;');
    expect(result.valid).toBe(true);
  });

  it('should accept code with spread operator', () => {
    const result = validateJavaScriptSyntax('const arr = [1, 2, 3]; return [...arr, 4];');
    expect(result.valid).toBe(true);
  });

  it('should reject import declarations (not valid in function body)', () => {
    // Import declarations are module-level and not valid inside function bodies
    const result = validateJavaScriptSyntax('import React from "react"; return React;');
    expect(result.valid).toBe(false);
  });

  it('should reject export declarations (not valid in function body)', () => {
    const result = validateJavaScriptSyntax('export const x = 1;');
    expect(result.valid).toBe(false);
  });

  it('should accept code with for-of loops', () => {
    const result = validateJavaScriptSyntax('for (const item of args) { console.log(item); } return true;');
    expect(result.valid).toBe(true);
  });

  it('should accept code with optional chaining', () => {
    const result = validateJavaScriptSyntax('return args?.data?.value ?? null;');
    expect(result.valid).toBe(true);
  });
});
