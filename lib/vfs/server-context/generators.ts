/**
 * Server Context Content Generators
 *
 * Generate content for transient files in /.server/ directory.
 * Structure:
 * - /.server/secrets/{NAME}.json - individual secret files (SCREAMING_SNAKE_CASE)
 * - /.server/db/schema.sql - database schema
 * - /.server/edge-functions/{name}.json - individual edge functions
 * - /.server/server-functions/{name}.json - individual server functions
 */

import { EdgeFunction, ServerFunction, Secret, ScheduledFunction } from '../types';
import cronParser from 'cron-parser';
// esbuild is server-only (uses native binaries), so we lazy-import to avoid
// bundling it into the client where it would fail at runtime.
let validateJavaScriptSyntax: typeof import('@/lib/security/syntax-validator').validateJavaScriptSyntax | undefined;

async function getSyntaxValidator() {
  if (!validateJavaScriptSyntax) {
    const mod = await import('@/lib/security/syntax-validator');
    validateJavaScriptSyntax = mod.validateJavaScriptSyntax;
  }
  return validateJavaScriptSyntax;
}

// ============================================
// Type Definitions
// ============================================

export interface EdgeFunctionFileData {
  name: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'ANY';
  description?: string;
  enabled: boolean;
  timeoutMs: number;
  code: string;
}

export interface ServerFunctionFileData {
  name: string;
  description?: string;
  enabled: boolean;
  code: string;
}

export interface SecretFileData {
  name: string;
  description?: string;
  hasValue?: boolean;
}

export interface ScheduledFunctionFileData {
  name: string;
  description?: string;
  functionName: string;      // Resolved name of the linked edge function
  cronExpression: string;
  timezone: string;
  enabled: boolean;
  config: Record<string, unknown>;
  lastRunAt?: string;
  nextRunAt?: string;
  lastStatus?: string;
}

export interface ServerContextMetadata {
  projectId: string;
  runtimeDeploymentId?: string;  // Set when a deployment is connected for runtime (sqlite3, logs)
  hasDatabase: boolean;          // True when runtimeDeploymentId is set
  edgeFunctionCount: number;
  serverFunctionCount: number;
  secretCount: number;
  scheduledFunctionCount: number;
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

// ============================================
// File Generators
// ============================================

/**
 * Generate edge function file in JSON format
 */
export function generateEdgeFunctionFile(fn: EdgeFunction): string {
  const data: EdgeFunctionFileData = {
    name: fn.name,
    method: fn.method,
    description: fn.description,
    enabled: fn.enabled,
    timeoutMs: fn.timeoutMs || 5000,
    code: fn.code,
  };
  return JSON.stringify(data, null, 2);
}

/**
 * Generate server function file in JSON format
 */
export function generateServerFunctionFile(fn: ServerFunction): string {
  const data: ServerFunctionFileData = {
    name: fn.name,
    description: fn.description,
    enabled: fn.enabled,
    code: fn.code,
  };
  return JSON.stringify(data, null, 2);
}

/**
 * Generate individual secret file in JSON format
 */
export function generateSecretFile(secret: Secret): string {
  const data: SecretFileData = {
    name: secret.name,
    description: secret.description || undefined,
    hasValue: secret.hasValue,
  };
  return JSON.stringify(data, null, 2);
}

/**
 * Generate scheduled function file in JSON format
 */
export function generateScheduledFunctionFile(
  fn: ScheduledFunction,
  edgeFunctionName: string
): string {
  const data: ScheduledFunctionFileData = {
    name: fn.name,
    description: fn.description,
    functionName: edgeFunctionName,
    cronExpression: fn.cronExpression,
    timezone: fn.timezone,
    enabled: fn.enabled,
    config: fn.config,
    lastRunAt: fn.lastRunAt?.toISOString(),
    nextRunAt: fn.nextRunAt?.toISOString(),
    lastStatus: fn.lastStatus,
  };
  return JSON.stringify(data, null, 2);
}

/**
 * Generate metadata for system prompt
 */
export function generateServerContextMetadata(
  projectId: string,
  edgeFunctions: EdgeFunction[],
  serverFunctions: ServerFunction[],
  secrets: Secret[],
  scheduledFunctions?: ScheduledFunction[],
  runtimeDeploymentId?: string
): ServerContextMetadata {
  return {
    projectId,
    runtimeDeploymentId,
    hasDatabase: !!runtimeDeploymentId,
    edgeFunctionCount: edgeFunctions.filter(f => f.enabled).length,
    serverFunctionCount: serverFunctions.filter(f => f.enabled).length,
    secretCount: secrets.length,
    scheduledFunctionCount: scheduledFunctions ? scheduledFunctions.filter(f => f.enabled).length : 0,
  };
}

// ============================================
// Validators
// ============================================

/**
 * Reserved names that cannot be used for server functions
 */
const RESERVED_SERVER_FUNCTION_NAMES = [
  'db', 'fetch', 'console', 'args', 'request', 'Response', 'server', 'secrets', 'atob', 'btoa'
];

/**
 * Validate edge function data before saving
 */
export async function validateEdgeFunctionData(data: unknown): Promise<ValidationResult> {
  const errors: string[] = [];

  if (!data || typeof data !== 'object') {
    return { valid: false, errors: ['Invalid JSON: expected an object'] };
  }

  const fn = data as Record<string, unknown>;

  // Name validation (URL-safe)
  if (!fn.name || typeof fn.name !== 'string') {
    errors.push('Missing or invalid "name" field');
  } else if (!/^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$/.test(fn.name)) {
    errors.push('Name must be lowercase letters, numbers, and hyphens only (e.g., "get-users")');
  }

  // Method validation
  const validMethods = ['GET', 'POST', 'PUT', 'DELETE', 'ANY'];
  if (!fn.method || typeof fn.method !== 'string') {
    errors.push('Missing or invalid "method" field');
  } else if (!validMethods.includes(fn.method)) {
    errors.push(`Method must be one of: ${validMethods.join(', ')}`);
  }

  // Code validation — uses safe syntax validator (not new Function())
  // to prevent code execution in the Node.js context during validation
  if (!fn.code || typeof fn.code !== 'string') {
    errors.push('Missing or invalid "code" field');
  } else {
    const validator = await getSyntaxValidator();
    if (validator) {
      const result = validator(fn.code);
      if (!result.valid && result.error) {
        errors.push(result.error);
      }
    }
  }

  // Enabled validation (optional, defaults to true)
  if (fn.enabled !== undefined && typeof fn.enabled !== 'boolean') {
    errors.push('"enabled" must be a boolean');
  }

  // Timeout validation (optional)
  if (fn.timeoutMs !== undefined) {
    if (typeof fn.timeoutMs !== 'number') {
      errors.push('"timeoutMs" must be a number');
    } else if (fn.timeoutMs < 1000 || fn.timeoutMs > 30000) {
      errors.push('Timeout must be between 1000 and 30000 ms');
    }
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Validate server function data before saving
 */
export async function validateServerFunctionData(data: unknown): Promise<ValidationResult> {
  const errors: string[] = [];

  if (!data || typeof data !== 'object') {
    return { valid: false, errors: ['Invalid JSON: expected an object'] };
  }

  const fn = data as Record<string, unknown>;

  // Name validation (JavaScript identifier)
  if (!fn.name || typeof fn.name !== 'string') {
    errors.push('Missing or invalid "name" field');
  } else if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(fn.name)) {
    errors.push('Name must be a valid JavaScript identifier (e.g., "validateAuth", "formatPrice")');
  } else if (RESERVED_SERVER_FUNCTION_NAMES.includes(fn.name)) {
    errors.push(`Cannot use reserved name: ${fn.name}`);
  }

  // Code validation — uses safe syntax validator with parameter names
  // matching the server function execution context
  if (!fn.code || typeof fn.code !== 'string') {
    errors.push('Missing or invalid "code" field');
  } else {
    const validator = await getSyntaxValidator();
    if (validator) {
      const result = validator(fn.code, ['args', 'db', 'fetch', 'console']);
      if (!result.valid && result.error) {
        errors.push(result.error);
      }
    }
  }

  // Enabled validation (optional, defaults to true)
  if (fn.enabled !== undefined && typeof fn.enabled !== 'boolean') {
    errors.push('"enabled" must be a boolean');
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Validate individual secret file data
 */
export function validateSecretData(data: unknown): ValidationResult {
  const errors: string[] = [];

  if (!data || typeof data !== 'object') {
    return { valid: false, errors: ['Invalid JSON: expected an object'] };
  }

  const secret = data as Record<string, unknown>;

  // Name validation (SCREAMING_SNAKE_CASE)
  if (!secret.name || typeof secret.name !== 'string') {
    errors.push('Missing or invalid "name" field');
  } else if (!/^[A-Z][A-Z0-9_]*$/.test(secret.name)) {
    errors.push('Name must be SCREAMING_SNAKE_CASE (e.g., MY_API_KEY, SMTP_PASSWORD)');
  } else if (secret.name.length > 64) {
    errors.push('Name must be 64 characters or less');
  }

  // Description validation (optional)
  if (secret.description !== undefined && typeof secret.description !== 'string') {
    errors.push('"description" must be a string');
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Validate scheduled function data before saving via server context
 */
export function validateScheduledFunctionData(data: unknown): ValidationResult {
  const errors: string[] = [];

  if (!data || typeof data !== 'object') {
    return { valid: false, errors: ['Invalid JSON: expected an object'] };
  }

  const fn = data as Record<string, unknown>;

  // Name validation (URL-safe)
  if (!fn.name || typeof fn.name !== 'string') {
    errors.push('Missing or invalid "name" field');
  } else if (!/^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$/.test(fn.name)) {
    errors.push('Name must be lowercase letters, numbers, and hyphens only');
  }

  // functionName validation
  if (!fn.functionName || typeof fn.functionName !== 'string') {
    errors.push('Missing or invalid "functionName" field');
  }

  // cronExpression validation
  if (!fn.cronExpression || typeof fn.cronExpression !== 'string') {
    errors.push('Missing or invalid "cronExpression" field');
  } else {
    try {
      cronParser.parseExpression(fn.cronExpression);
    } catch {
      errors.push('Invalid cron expression');
    }
  }

  // timezone validation (optional, defaults to UTC)
  if (fn.timezone !== undefined) {
    if (typeof fn.timezone !== 'string') {
      errors.push('"timezone" must be a string');
    } else {
      try {
        Intl.DateTimeFormat(undefined, { timeZone: fn.timezone });
      } catch {
        errors.push(`Invalid timezone: ${fn.timezone}`);
      }
    }
  }

  // enabled validation (optional)
  if (fn.enabled !== undefined && typeof fn.enabled !== 'boolean') {
    errors.push('"enabled" must be a boolean');
  }

  // config validation (optional, must be object)
  if (fn.config !== undefined) {
    if (typeof fn.config !== 'object' || fn.config === null || Array.isArray(fn.config)) {
      errors.push('"config" must be a plain object');
    }
  }

  return { valid: errors.length === 0, errors };
}
