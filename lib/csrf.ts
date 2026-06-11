/**
 * CSRF Protection Utility
 *
 * Validates Origin and Referer headers on state-changing requests
 * (POST, PUT, PATCH, DELETE) to prevent Cross-Site Request Forgery attacks.
 *
 * Strategy: Origin/Referer validation
 * - All modern browsers send the Origin header on cross-origin requests
 * - If Origin is present, it must match the application's allowed origins
 * - If Origin is absent (rare), falls back to Referer header
 * - If both are absent, the request is rejected (unless exempted)
 *
 * This is simpler and more reliable than double-submit cookies because:
 * - No client-side token management needed
 * - No risk of token leakage via XSS
 * - Works seamlessly with SameSite=Lax cookies
 * - Covers all write routes automatically via middleware
 */

import type { NextRequest } from 'next/server';

/**
 * Routes that are exempt from CSRF protection.
 * These are either public endpoints or accept requests from external origins.
 */
const CSRF_EXEMPT_PATHS: string[] = [
  // Auth routes - login/register are public, handoff accepts external redirects
  '/api/auth/login',
  '/api/auth/register',
  '/api/auth/handoff',
  '/api/auth/setup-status',
  '/api/auth/check',
  '/api/auth/me',
  '/api/auth/desktop-init',
  '/api/auth/hf/capabilities',

  // Codex token/status - machine-to-machine or simple reads
  '/api/auth/codex/token',
  '/api/auth/codex/status',
  // Note: codex/connect and codex/disconnect are authenticated write
  // endpoints and MUST have CSRF protection (not exempted)

  // Analytics tracking - already has its own Origin validation
  '/api/analytics/track',
  '/api/analytics/interaction',

  // Edge function execution - called from external deployed sites
  // These already have their own auth mechanism (deployment tokens)
  '/api/deployments/',

  // Resolve domain - called by Caddy on-demand TLS (no browser origin)
  '/api/resolve-domain',
];

/**
 * Check if a path is exempt from CSRF protection
 */
function isCsrfExempt(pathname: string): boolean {
  return CSRF_EXEMPT_PATHS.some(
    (exempt) => pathname === exempt || pathname.startsWith(exempt)
  );
}

/**
 * Get the allowed origins for this application instance.
 * Returns the app URL(s) that are valid origins for same-origin requests.
 */
function getAllowedOrigins(): string[] {
  const origins: string[] = [];

  // Primary app URL
  const appUrl = process.env.NEXT_PUBLIC_APP_URL;
  if (appUrl) {
    origins.push(appUrl);
  }

  // Gateway URL (for managed auth setups)
  const gatewayUrl = process.env.NEXT_PUBLIC_GATEWAY_URL;
  if (gatewayUrl) {
    origins.push(gatewayUrl);
  }

  // Development origins
  if (process.env.NODE_ENV === 'development') {
    origins.push('http://localhost:3000');
    origins.push('http://127.0.0.1:3000');
    origins.push('http://localhost:7860');
    origins.push('http://127.0.0.1:7860');
  }

  // Fallback: if no APP_URL set, infer from other env vars
  if (origins.length === 0) {
    origins.push('http://localhost:3000');
  }

  return origins;
}

/**
 * Extract the origin from a URL string (protocol + host)
 */
function extractOrigin(url: string): string | null {
  try {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.host}`;
  } catch {
    return null;
  }
}

/**
 * Check if a given origin matches any of the allowed origins.
 * Supports exact matching and wildcard subdomain matching.
 */
function isOriginAllowed(origin: string, allowedOrigins: string[]): boolean {
  return allowedOrigins.some((allowed) => {
    // Exact match
    if (origin === allowed) return true;

    // Wildcard subdomain match (e.g., https://*.oswstudio.com)
    if (allowed.includes('*.')) {
      const suffix = allowed.replace(/^https?:\/\/\*\./, '.');
      const originHost = new URL(origin).hostname;
      // originHost must end with the suffix (e.g., ".oswstudio.com")
      return originHost.endsWith(suffix);
    }

    return false;
  });
}

/**
 * Validate CSRF protection for a request.
 *
 * Checks Origin and Referer headers on state-changing HTTP methods.
 * Returns true if the request passes CSRF validation, false otherwise.
 *
 * @param request - The incoming Next.js request
 * @returns { valid: boolean, reason?: string } - Validation result
 */
export function validateCsrf(request: NextRequest): { valid: boolean; reason?: string } {
  const { pathname } = request.nextUrl;
  const method = request.method.toUpperCase();

  // Only validate state-changing methods
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    return { valid: true };
  }

  // Skip exempt paths
  if (isCsrfExempt(pathname)) {
    return { valid: true };
  }

  // Desktop mode: no CSRF needed (local-only access)
  if (process.env.OSW_DESKTOP === 'true') {
    return { valid: true };
  }

  // Instance API key requests: machine-to-machine, no browser origin
  const instanceApiKey = request.headers.get('x-instance-api-key');
  if (instanceApiKey) {
    return { valid: true };
  }

  const allowedOrigins = getAllowedOrigins();

  // Check Origin header (preferred - always sent by browsers on cross-origin requests)
  const origin = request.headers.get('origin');

  if (origin) {
    // Origin is present — validate it
    if (isOriginAllowed(origin, allowedOrigins)) {
      return { valid: true };
    }

    // Check if origin matches the request's own host (same-origin request)
    const requestOrigin = extractOrigin(request.url);
    if (requestOrigin && origin === requestOrigin) {
      return { valid: true };
    }

    return {
      valid: false,
      reason: `Origin ${origin} not allowed`,
    };
  }

  // No Origin header — check Referer as fallback
  const referer = request.headers.get('referer');

  if (referer) {
    const refererOrigin = extractOrigin(referer);
    if (refererOrigin && isOriginAllowed(refererOrigin, allowedOrigins)) {
      return { valid: true };
    }

    // Check if referer matches the request's own host
    const requestOrigin = extractOrigin(request.url);
    if (requestOrigin && refererOrigin === requestOrigin) {
      return { valid: true };
    }

    return {
      valid: false,
      reason: `Referer origin ${refererOrigin} not allowed`,
    };
  }

  // Neither Origin nor Referer present
  // Browsers always send Origin on POST/PUT/DELETE, so this is suspicious
  // Exception: some API clients (curl, Postman) don't send these headers
  // In production, we reject. In development, we allow (for API testing).
  if (process.env.NODE_ENV === 'development') {
    return { valid: true };
  }

  return {
    valid: false,
    reason: 'Missing Origin and Referer headers',
  };
}
