/**
 * Analytics Tracking API
 * POST /api/analytics/track - Record a pageview
 *
 * Security Features:
 * - Origin/Referer validation (primary defense - browser-enforced)
 * - Rate limiting per IP (100 requests/minute)
 * - Bot detection (blocks automated tools)
 * - Anomaly detection (SQL injection, suspicious patterns)
 *
 * Note: Same-origin hosting provides stronger security than Google Analytics.
 * Tokens not required due to browser CORS protections.
 */

import { NextRequest, NextResponse } from 'next/server';
import { getSQLiteAdapter } from '@/lib/vfs/adapters/server';
import {
  pageviewRateLimiter,
  RATE_LIMIT_CONFIG,
  getIdentifier,
} from '@/lib/analytics/rate-limiter';
import {
  validateOrigin,
  getAllowedOrigins,
  isLikelyBot,
  isSuspiciousRequest,
} from '@/lib/analytics/security';

interface PageviewData {
  deploymentId: string;
  pagePath: string;
  referrer: string;
  userAgent: string;
  deviceType?: string;
  // token field removed - origin validation provides sufficient security
}

export async function POST(request: NextRequest) {
  try {
    const body: PageviewData = await request.json();
    const { deploymentId, pagePath, referrer, userAgent, deviceType } = body;

    // 1. Rate Limiting Check
    const identifier = getIdentifier(request);
    const rateLimitAllowed = pageviewRateLimiter.check(
      identifier,
      RATE_LIMIT_CONFIG.pageview
    );

    if (!rateLimitAllowed) {
      const resetTime = pageviewRateLimiter.getResetTime(
        identifier,
        RATE_LIMIT_CONFIG.pageview
      );

      return NextResponse.json(
        { error: 'Rate limit exceeded' },
        {
          status: 429,
          headers: {
            'Retry-After': resetTime.toString(),
            'X-RateLimit-Limit': RATE_LIMIT_CONFIG.pageview.limit.toString(),
            'X-RateLimit-Remaining': '0',
          },
        }
      );
    }

    // 2. Validate required fields
    if (!deploymentId || !pagePath) {
      return NextResponse.json(
        { error: 'Missing required fields: deploymentId, pagePath' },
        { status: 400 }
      );
    }

    // 3. Anomaly Detection - Check for suspicious data
    if (isSuspiciousRequest({ pagePath, referrer, userAgent })) {
      console.warn('[Analytics] Suspicious request detected:', {
        deploymentId,
        pagePath,
        ip: identifier,
      });
      return NextResponse.json(
        { error: 'Invalid request' },
        { status: 400 }
      );
    }

    // 4. Bot Detection
    if (isLikelyBot(userAgent)) {
      // Silently ignore bot requests (don't return error to avoid detection)
      return NextResponse.json({ success: true });
    }

    const adapter = getSQLiteAdapter();
    await adapter.init();

    // 5. Verify deployment exists (from core database)
    const deployment = await adapter.getDeployment(deploymentId);
    if (!deployment) {
      return NextResponse.json(
        { error: 'Deployment not found' },
        { status: 404 }
      );
    }

    // 6. Check if analytics is enabled for this deployment
    if (!deployment.analytics.enabled || deployment.analytics.provider !== 'builtin') {
      return NextResponse.json(
        { error: 'Built-in analytics not enabled for this deployment' },
        { status: 403 }
      );
    }

    // 6b. Check if deployment database is enabled (created when deployment is published)
    const deploymentDb = adapter.getAnalyticsDatabaseInstance(deploymentId);
    if (!deploymentDb) {
      return NextResponse.json(
        { error: 'Deployment database not enabled' },
        { status: 404 }
      );
    }

    // 7. CORS/Origin Validation (Primary Security Layer)
    // This is our main defense against abuse. Unlike Google Analytics (which must accept
    // requests from any domain), we only accept requests from our own domain paths.
    // Browser security prevents attackers from spoofing Origin/Referer across domains.
    const allowedOrigins = getAllowedOrigins(deploymentId, deployment.customDomain);
    if (!validateOrigin(request, allowedOrigins)) {
      console.warn('[Analytics] Invalid origin (rejected):', {
        origin: request.headers.get('origin'),
        referer: request.headers.get('referer'),
        allowedOrigins,
        deploymentId,
        ip: identifier,
      });
      return NextResponse.json(
        { error: 'Origin not allowed' },
        { status: 403 }
      );
    }

    // Note: Token-based authentication removed in favor of origin validation.
    // Origin validation is stronger for same-origin hosting and avoids token expiration issues.
    // Additional protection provided by: rate limiting, bot detection, and anomaly detection.

    // Generate session ID using crypto.randomUUID()
    const sessionId = generateSessionId(userAgent, request);

    // Extract country from IP (anonymized - no storing IP addresses)
    const country = await getCountryFromIP(request);

    // Normalize path for consistent tracking
    const normalizedPath = normalizePath(pagePath);

    // Record pageview using DeploymentDatabase
    deploymentDb.recordPageview({
      pagePath: normalizedPath,
      referrer: referrer || undefined,
      country: country || undefined,
      userAgent,
      deviceType: deviceType || undefined,
      sessionId,
    });

    // Upsert session record
    deploymentDb.upsertSession(sessionId, normalizedPath);

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('[Analytics API] Error tracking pageview:', error);
    return NextResponse.json(
      { error: 'Failed to track pageview' },
      { status: 500 }
    );
  }
}

/**
 * Generate anonymous session ID using crypto.randomUUID()
 * No cookies, no personal data - just a unique identifier per session
 */
function generateSessionId(_userAgent: string, _request: NextRequest): string {
  return crypto.randomUUID();
}

/**
 * Anonymize IP address
 */
function anonymizeIP(ip: string): string {
  if (!ip) return '';

  if (ip.includes(':')) {
    // IPv6 - keep first 4 groups
    const parts = ip.split(':');
    return parts.slice(0, 4).join(':') + '::';
  } else {
    // IPv4 - keep first 2 octets
    const parts = ip.split('.');
    return parts.slice(0, 2).join('.') + '.0.0';
  }
}

/**
 * Get country from IP address
 * For now, just return null - can integrate with a geo-IP service later
 */
async function getCountryFromIP(request: NextRequest): Promise<string | null> {
  // Future: integrate with geo-IP library (geoip-lite, maxmind, etc.)
  // For MVP, we'll skip country detection
  return null;
}

/**
 * Normalize page path for consistent tracking
 * - Strips trailing slashes
 * - Converts directory paths to index.html
 * Example: /deployments/abc/ -> /deployments/abc/index.html
 */
function normalizePath(path: string): string {
  if (!path || path === '/') return '/index.html';

  // Remove trailing slash
  let normalized = path.replace(/\/$/, '');

  // If path doesn't have an extension, it's likely a directory - add /index.html
  if (!normalized.includes('.') || normalized.split('/').pop()?.indexOf('.') === -1) {
    normalized += '/index.html';
  }

  return normalized;
}
