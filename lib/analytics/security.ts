/**
 * Analytics Security Utilities
 *
 * Token generation and validation for secure analytics tracking.
 * Prevents unauthorized data injection and replay attacks.
 */

import crypto from 'crypto';

const TOKEN_EXPIRY_MS = 48 * 60 * 60 * 1000; // 48 hours (reduced from 30 days for security)

/**
 * Generate a signed analytics tracking token
 * Token format (base64-encoded): deploymentId:timestamp:nonce:signature
 *
 * @param deploymentId - Deployment identifier
 * @returns Base64-encoded signed token
 */
export function generateAnalyticsToken(deploymentId: string): string {
  const secret = getAnalyticsSecret();
  const timestamp = Date.now().toString();
  const nonce = crypto.randomBytes(8).toString('hex');
  const payload = `${deploymentId}:${timestamp}:${nonce}`;

  const signature = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');

  const token = `${payload}:${signature}`;
  return Buffer.from(token).toString('base64');
}

/**
 * Verify an analytics tracking token and optionally issue a fresh one
 * (rolling token refresh).
 *
 * Rolling refresh: each valid request returns a new token with a fresh
 * timestamp, so active sessions never expire. Stolen tokens expire after
 * 48 hours of inactivity because they are not refreshed.
 *
 * @param token - Base64-encoded token from client
 * @param expectedDeploymentId - Expected deployment ID
 * @returns Object with valid flag and, if valid, a refreshed token
 */
export function verifyAnalyticsToken(
  token: string,
  expectedDeploymentId: string
): { valid: boolean; refreshedToken?: string } {
  try {
    const secret = getAnalyticsSecret();

    // Decode token
    const decoded = Buffer.from(token, 'base64').toString('utf-8');
    const parts = decoded.split(':');

    if (parts.length !== 4) {
      return { valid: false }; // Invalid format
    }

    const [deploymentId, timestamp, nonce, signature] = parts;

    // Verify deployment ID matches
    if (deploymentId !== expectedDeploymentId) {
      return { valid: false };
    }

    // Verify timestamp is recent (prevent replay attacks)
    const tokenAge = Date.now() - parseInt(timestamp, 10);
    if (tokenAge > TOKEN_EXPIRY_MS || tokenAge < 0) {
      return { valid: false }; // Token expired or from future
    }

    // Verify signature
    const payload = `${deploymentId}:${timestamp}:${nonce}`;
    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(payload)
      .digest('hex');

    // Constant-time comparison to prevent timing attacks
    const signatureValid = crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );

    if (!signatureValid) {
      return { valid: false };
    }

    // Token is valid — issue a refreshed token (rolling refresh)
    const refreshedToken = generateAnalyticsToken(deploymentId);

    return { valid: true, refreshedToken };
  } catch {
    // Invalid token format or other error
    return { valid: false };
  }
}

/**
 * Get analytics secret from environment
 * Generates a random secret if not configured (dev only)
 */
function getAnalyticsSecret(): string {
  const secret = process.env.ANALYTICS_SECRET;

  if (!secret) {
    // SECURITY: No hardcoded dev secret. Auto-generate a random per-instance secret
    // and persist it in the system database so it survives restarts.
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const { getSystemDatabase } = require('@/lib/auth/system-database') as typeof import('@/lib/auth/system-database');
      const db = getSystemDatabase();

      // Check if we have a persisted secret
      const existing = db.prepare("SELECT value FROM system_config WHERE key = 'analytics_secret'").get() as { value: string } | undefined;
      if (existing?.value) {
        return existing.value;
      }

      // Generate and persist a new random secret
      const newSecret = crypto.randomBytes(32).toString('hex');
      db.prepare("INSERT OR REPLACE INTO system_config (key, value) VALUES ('analytics_secret', ?)").run(newSecret);
      console.warn('[Analytics Security] ANALYTICS_SECRET not set, auto-generated and persisted a random secret');
      return newSecret;
    } catch {
      // System database not available (browser mode) — generate ephemeral secret
      console.warn('[Analytics Security] ANALYTICS_SECRET not set and DB unavailable, using ephemeral secret (not for production)');
      return crypto.randomBytes(32).toString('hex');
    }
  }

  return secret;
}

/**
 * Validate request origin against allowed domains
 *
 * @param request - Incoming request
 * @param allowedOrigins - Array of allowed origin URLs
 * @returns true if origin is allowed, false otherwise
 */
export function validateOrigin(
  request: Request,
  allowedOrigins: string[]
): boolean {
  const origin = request.headers.get('origin') || '';
  const referer = request.headers.get('referer') || '';

  return allowedOrigins.some((allowed) => {
    if (allowed.includes('*')) {
      // Wildcard subdomain matching (e.g., https://*.oswstudio.com)
      const suffix = allowed.replace(/^https?:\/\/\*/, '');
      // SECURITY: Use proper hostname parsing instead of endsWith()
      // endsWith() would match "evil-oswstudio.com" for ".oswstudio.com"
      const matchesOrigin = isValidSubdomainMatch(origin, suffix) && /^https?:\/\//.test(origin);
      const matchesReferer = isValidSubdomainMatch(referer, suffix);
      return matchesOrigin || matchesReferer;
    }
    return origin.startsWith(allowed) || referer.startsWith(allowed);
  });
}

/**
 * Validate that a URL's hostname is a proper subdomain match for the given suffix.
 *
 * SECURITY: Prevents bypass via lookalike domains.
 * e.g., "evil-oswstudio.com" must NOT match ".oswstudio.com"
 * but "app.oswstudio.com" must match ".oswstudio.com"
 *
 * @param urlStr - The URL to validate
 * @param suffix - The expected suffix (e.g., ".oswstudio.com")
 * @returns true if the URL hostname properly ends with the suffix
 */
function isValidSubdomainMatch(urlStr: string, suffix: string): boolean {
  try {
    const parsed = new URL(urlStr);
    const hostname = parsed.hostname;

    // The hostname must end with the suffix AND either:
    // 1. The suffix starts with a dot (e.g., ".oswstudio.com") — hostname is a subdomain
    // 2. The hostname equals the suffix exactly (root domain match)
    if (suffix.startsWith('.')) {
      return hostname.endsWith(suffix) || hostname === suffix.slice(1);
    }
    return hostname === suffix || hostname.endsWith('.' + suffix);
  } catch {
    // Not a valid URL
    return false;
  }
}

/**
 * Get allowed origins for a deployment
 *
 * @param deploymentId - Deployment identifier
 * @param customDomain - Optional custom domain
 * @returns Array of allowed origin URLs
 */
export function getAllowedOrigins(
  deploymentId: string,
  customDomain?: string | null
): string[] {
  const appUrl = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000';

  const origins: string[] = [
    `${appUrl}/deployments/${deploymentId}`, // Published deployment path
    appUrl // Base app URL (for development/testing)
  ];

  // Add localhost variations for development
  if (appUrl.includes('localhost')) {
    origins.push('http://localhost:3000');
    origins.push('http://127.0.0.1:3000');
  }

  // Add custom domain if configured
  if (customDomain) {
    origins.push(`https://${customDomain}`);
    // SECURITY: Only allow HTTP for custom domains in development.
    // In production, custom domains must use HTTPS to prevent MITM attacks.
    if (process.env.NODE_ENV !== 'production') {
      origins.push(`http://${customDomain}`);
    }
  }

  // Allow subdomain-routed deployments (e.g., my-site.oswstudio.com)
  const appHost = appUrl.replace(/^https?:\/\//, '').split(':')[0];
  if (appHost && !appHost.includes('localhost')) {
    origins.push(`https://*.${appHost}`);
    origins.push(`http://*.${appHost}`);
  }

  return origins;
}

/**
 * Generate token hash for storage (to verify tokens without storing plaintext)
 *
 * @param token - Token to hash
 * @returns SHA-256 hash of token
 */
export function hashToken(token: string): string {
  return crypto
    .createHash('sha256')
    .update(token)
    .digest('hex');
}

/**
 * Check if user agent appears to be a bot
 *
 * @param userAgent - User agent string
 * @returns true if likely a bot, false otherwise
 */
export function isLikelyBot(userAgent: string): boolean {
  if (!userAgent) return true; // No user agent = suspicious

  const lowerUA = userAgent.toLowerCase();

  // Common bot indicators
  const botPatterns = [
    'bot',
    'crawl',
    'spider',
    'scrape',
    'curl',
    'wget',
    'python',
    'java',
    'http',
    'go-http-client',
    'axios',
    'fetch',
    'node-fetch',
    'requests', // Python
    'urllib',
    'headless',
    'phantom',
    'selenium',
    'puppeteer',
    'playwright'
  ];

  return botPatterns.some((pattern) => lowerUA.includes(pattern));
}

/**
 * Detect suspicious request patterns
 *
 * @param data - Analytics data to validate
 * @returns true if suspicious, false otherwise
 */
export function isSuspiciousRequest(data: {
  pagePath?: string;
  referrer?: string;
  userAgent?: string;
}): boolean {
  // Check for obviously fake/malicious data
  if (data.pagePath && data.pagePath.length > 500) {
    return true; // Unreasonably long path
  }

  if (data.referrer && data.referrer.length > 500) {
    return true; // Unreasonably long referrer
  }

  if (data.userAgent && data.userAgent.length > 500) {
    return true; // Unreasonably long user agent
  }

  // Check for SQL injection attempts
  const sqlPatterns = /(union|select|insert|update|delete|drop|create|alter)/i;
  if (
    (data.pagePath && sqlPatterns.test(data.pagePath)) ||
    (data.referrer && sqlPatterns.test(data.referrer))
  ) {
    return true;
  }

  return false;
}
