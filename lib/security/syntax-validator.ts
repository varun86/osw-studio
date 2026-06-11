/**
 * Safe JavaScript Syntax Validation
 *
 * Replaces direct `new Function(code)` usage for syntax validation.
 * `new Function()` is dangerous because:
 * 1. It creates executable functions in the Node.js context (not the QuickJS sandbox)
 * 2. If accidentally called, the function has full host environment access
 * 3. It can cause DoS with extremely long code strings
 *
 * This module uses esbuild's `transform()` function to parse and validate
 * JavaScript syntax WITHOUT creating executable functions. esbuild performs
 * a full parse but only outputs the transformed code — no execution occurs.
 *
 * SECURITY GUARANTEES:
 * - esbuild.transform() parses code into an AST and generates output text
 * - No code is ever executed during validation
 * - Code length is capped at 512KB to prevent memory exhaustion
 * - Null bytes are rejected to prevent string truncation attacks
 * - The transformed output is discarded — only success/failure is reported
 */

import esbuild from 'esbuild';

/**
 * Maximum code length for validation (prevents DoS via extremely long code)
 */
const MAX_CODE_LENGTH = 512 * 1024; // 512 KB

/**
 * Cached esbuild transform result for synchronous callers.
 * The first call initializes esbuild, subsequent calls use the cache.
 */
let esbuildReady = false;

/**
 * Ensure esbuild is available and ready for use.
 * esbuild's native module is synchronous and doesn't require initialization.
 */
function ensureEsbuildReady(): void {
  if (esbuildReady) return;
  // Native esbuild is synchronous and always available when imported
  esbuildReady = true;
}

/**
 * Validate JavaScript syntax without executing it.
 *
 * Uses esbuild.transform() to parse the code into an AST and check for
 * syntax errors. The code is NEVER executed — esbuild only performs parsing
 * and code generation.
 *
 * @param code - The JavaScript code to validate
 * @param paramNames - Optional parameter names (for server function context).
 *   When provided, the code is wrapped in an async function with these
 *   parameter names to validate syntax in the correct scope context.
 * @returns An object with `valid: boolean` and optional `error: string`
 */
export function validateJavaScriptSyntax(
  code: string,
  paramNames?: string[]
): { valid: boolean; error?: string } {
  // Validate input
  if (!code || typeof code !== 'string') {
    return { valid: false, error: 'Missing or invalid code field' };
  }

  // Enforce code length limit to prevent DoS
  if (code.length > MAX_CODE_LENGTH) {
    return {
      valid: false,
      error: `Code too long (max ${MAX_CODE_LENGTH} bytes, got ${code.length})`,
    };
  }

  // Block null bytes (can truncate strings in C-based V8 internals)
  if (code.includes('\0')) {
    return { valid: false, error: 'Code contains null bytes' };
  }

  ensureEsbuildReady();

  try {
    // Wrap code in a function if parameter names are provided.
    // This validates that the code is syntactically correct when used
    // as a function body with the specified parameters.
    let codeToValidate = code;
    if (paramNames && paramNames.length > 0) {
      // Wrap in an async function to match server function execution context.
      // This allows `await` and `return` statements in the code body.
      codeToValidate = `async function __validate(${paramNames.join(', ')}) {\n${code}\n}`;
    } else {
      // Wrap in a function to allow `return` statements in the code body.
      codeToValidate = `function __validate() {\n${code}\n}`;
    }

    // esbuild.transform() parses the code and generates output.
    // It throws on syntax errors. The output is discarded — we only
    // care whether parsing succeeded.
    esbuild.transformSync(codeToValidate, {
      loader: 'js',
      target: 'es2020',
      // Minify to reduce memory usage (we discard the output anyway)
      minify: true,
    });

    return { valid: true };
  } catch (e: unknown) {
    // esbuild throws errors with a structured format
    const message = e instanceof Error ? e.message : String(e);
    // Extract the useful part of the esbuild error message
    // esbuild errors look like: "[plugin] error: ...  or  ✘ [ERROR] ...
    const cleanMessage = message
      .replace(/^\s*✘\s*\[ERROR\]\s*/i, '')
      .replace(/^error:\s*/i, '')
      .trim();
    return { valid: false, error: `JavaScript syntax error: ${cleanMessage}` };
  }
}
