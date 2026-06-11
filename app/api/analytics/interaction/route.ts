/**
 * Analytics Interaction Tracking API
 * POST /api/analytics/interaction - Record interactions (clicks, scrolls, custom events)
 *
 * Security Features:
 * - Origin/Referer validation (primary defense - browser-enforced)
 * - Rate limiting per IP (500 requests/minute for interactions)
 * - Bot detection (blocks automated tools)
 * - Anomaly detection (SQL injection, suspicious patterns)
 *
 * Note: Same-origin hosting provides stronger security than Google Analytics.
 * Tokens not required due to browser CORS protections.
 */

import { NextRequest, NextResponse } from 'next/server';
import { getSQLiteAdapter } from '@/lib/vfs/adapters/server';
import {
  interactionRateLimiter,
  RATE_LIMIT_CONFIG,
  getIdentifier,
} from '@/lib/analytics/rate-limiter';
import {
  validateOrigin,
  getAllowedOrigins,
  isLikelyBot,
  isSuspiciousRequest,
} from '@/lib/analytics/security';

interface InteractionData {
  deploymentId: string;
  pagePath: string;
  interactionType: 'click' | 'scroll' | 'exit' | 'custom';
  elementSelector?: string;
  coordinates?: {
    x: number;
    y: number;
    scrollY?: number;
    viewportWidth?: number;
    viewportHeight?: number;
    documentHeight?: number;
  };
  scrollDepth?: number;
  timeOnPage?: number;
  customData?: Record<string, unknown>;
  userAgent?: string;
  // token field removed - origin validation provides sufficient security
}

interface BatchInteractionData {
  batch: boolean;
  interactions: InteractionData[];
}

export async function POST(request: NextRequest) {
  try {
    const body: InteractionData | BatchInteractionData = await request.json();

    // Check if this is a batch request
    if ('batch' in body && body.batch === true) {
      return handleBatchInteractions(request, body);
    }

    // Handle single interaction (backward compatibility)
    const {
      deploymentId,
      pagePath,
      interactionType,
      elementSelector,
      coordinates,
      scrollDepth,
      timeOnPage,
      userAgent,
    } = body as InteractionData;

    // 1. Rate Limiting Check (higher limit for interactions)
    const identifier = getIdentifier(request);
    const rateLimitAllowed = interactionRateLimiter.check(
      identifier,
      RATE_LIMIT_CONFIG.interaction
    );

    if (!rateLimitAllowed) {
      const resetTime = interactionRateLimiter.getResetTime(
        identifier,
        RATE_LIMIT_CONFIG.interaction
      );

      return NextResponse.json(
        { error: 'Rate limit exceeded' },
        {
          status: 429,
          headers: {
            'Retry-After': resetTime.toString(),
            'X-RateLimit-Limit': RATE_LIMIT_CONFIG.interaction.limit.toString(),
            'X-RateLimit-Remaining': '0',
          },
        }
      );
    }

    // 2. Validate required fields
    if (!deploymentId || !pagePath || !interactionType) {
      return NextResponse.json(
        { error: 'Missing required fields: deploymentId, pagePath, interactionType' },
        { status: 400 }
      );
    }

    // 3. Anomaly Detection
    if (isSuspiciousRequest({ pagePath, userAgent })) {
      console.warn('[Analytics Interaction] Suspicious request detected:', {
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
    if (userAgent && isLikelyBot(userAgent)) {
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

    // 6. Check if analytics is enabled
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

    // 7. Check if specific feature is enabled
    const features = deployment.analytics.features || {};
    if (interactionType === 'click' && !features.heatmaps) {
      return NextResponse.json(
        { error: 'Heatmaps feature not enabled' },
        { status: 403 }
      );
    }

    if (interactionType === 'scroll' && !features.engagementTracking && !features.heatmaps) {
      return NextResponse.json(
        { error: 'Engagement tracking not enabled' },
        { status: 403 }
      );
    }

    if (interactionType === 'exit' && !features.engagementTracking) {
      return NextResponse.json(
        { error: 'Engagement tracking not enabled' },
        { status: 403 }
      );
    }

    // 8. CORS/Origin Validation (Primary Security Layer)
    const allowedOrigins = getAllowedOrigins(deploymentId, deployment.customDomain);
    if (!validateOrigin(request, allowedOrigins)) {
      console.warn('[Analytics Interaction] Invalid origin (rejected):', {
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

    // Generate session ID
    const sessionId = generateSessionId(userAgent || request.headers.get('user-agent') || '', request);

    // Normalize path for consistent tracking
    const normalizedPath = normalizePath(pagePath);

    // Record interaction using DeploymentDatabase
    deploymentDb.recordInteraction({
      sessionId,
      pagePath: normalizedPath,
      interactionType,
      elementSelector,
      coordinates: coordinates ? {
        x: coordinates.x,
        y: coordinates.y,
        scrollY: coordinates.scrollY,
        viewportWidth: coordinates.viewportWidth,
        viewportHeight: coordinates.viewportHeight,
        documentHeight: coordinates.documentHeight,
      } : undefined,
      scrollDepth,
      timeOnPage,
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('[Analytics Interaction API] Error:', error);
    return NextResponse.json(
      { error: 'Failed to track interaction' },
      { status: 500 }
    );
  }
}

/**
 * Generate anonymous session ID using crypto.randomUUID()
 */
function generateSessionId(_userAgent: string, _request: NextRequest): string {
  return crypto.randomUUID();
}

function anonymizeIP(ip: string): string {
  if (!ip) return '';

  if (ip.includes(':')) {
    const parts = ip.split(':');
    return parts.slice(0, 4).join(':') + '::';
  } else {
    const parts = ip.split('.');
    return parts.slice(0, 2).join('.') + '.0.0';
  }
}

/**
 * Normalize page path for consistent tracking
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

/**
 * Handle batch interaction tracking
 * Processes multiple interactions in a single request for improved performance
 */
async function handleBatchInteractions(
  request: NextRequest,
  body: BatchInteractionData
): Promise<NextResponse> {
  const { interactions } = body;

  if (!interactions || interactions.length === 0) {
    return NextResponse.json(
      { error: 'No interactions provided in batch' },
      { status: 400 }
    );
  }

  // Validate batch size (max 100 events per batch)
  if (interactions.length > 100) {
    return NextResponse.json(
      { error: 'Batch size exceeds maximum of 100 interactions' },
      { status: 400 }
    );
  }

  // 1. Rate Limiting Check - count as single request with batch multiplier
  const identifier = getIdentifier(request);
  const rateLimitAllowed = interactionRateLimiter.check(
    identifier,
    RATE_LIMIT_CONFIG.interaction
  );

  if (!rateLimitAllowed) {
    const resetTime = interactionRateLimiter.getResetTime(
      identifier,
      RATE_LIMIT_CONFIG.interaction
    );

    return NextResponse.json(
      { error: 'Rate limit exceeded' },
      {
        status: 429,
        headers: {
          'Retry-After': resetTime.toString(),
          'X-RateLimit-Limit': RATE_LIMIT_CONFIG.interaction.limit.toString(),
          'X-RateLimit-Remaining': '0',
        },
      }
    );
  }

  // 2. Extract common fields from first interaction for validation
  const firstInteraction = interactions[0];
  const { deploymentId, userAgent } = firstInteraction;

  if (!deploymentId) {
    return NextResponse.json(
      { error: 'Missing required field: deploymentId' },
      { status: 400 }
    );
  }

  // 3. Bot Detection
  if (userAgent && isLikelyBot(userAgent)) {
    return NextResponse.json({ success: true });
  }

  const adapter = getSQLiteAdapter();
  await adapter.init();

  try {
    // 4. Verify deployment exists (from core database)
    const deployment = await adapter.getDeployment(deploymentId);
    if (!deployment) {
      return NextResponse.json(
        { error: 'Deployment not found' },
        { status: 404 }
      );
    }

    // 5. Check if analytics is enabled
    if (!deployment.analytics.enabled || deployment.analytics.provider !== 'builtin') {
      return NextResponse.json(
        { error: 'Built-in analytics not enabled for this deployment' },
        { status: 403 }
      );
    }

    // 5b. Check if deployment database is enabled (created when deployment is published)
    const deploymentDb = adapter.getAnalyticsDatabaseInstance(deploymentId);
    if (!deploymentDb) {
      return NextResponse.json(
        { error: 'Deployment database not enabled' },
        { status: 404 }
      );
    }

    // 6. CORS/Origin Validation
    const allowedOrigins = getAllowedOrigins(deploymentId, deployment.customDomain);
    if (!validateOrigin(request, allowedOrigins)) {
      console.warn('[Analytics Batch] Invalid origin (rejected):', {
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

    // 7. Process all interactions
    const defaultUserAgent = request.headers.get('user-agent') || '';

    let successCount = 0;
    let skipCount = 0;

    for (const interaction of interactions) {
      const {
        pagePath,
        interactionType,
        elementSelector,
        coordinates,
        scrollDepth,
        timeOnPage,
        userAgent: interactionUserAgent,
      } = interaction;

      // Validate each interaction
      if (!pagePath || !interactionType) {
        skipCount++;
        continue;
      }

      // Check feature flags for this interaction type
      const features = deployment.analytics.features || {};
      if (interactionType === 'click' && !features.heatmaps) {
        skipCount++;
        continue;
      }

      if (interactionType === 'scroll' && !features.engagementTracking && !features.heatmaps) {
        skipCount++;
        continue;
      }

      if (interactionType === 'exit' && !features.engagementTracking) {
        skipCount++;
        continue;
      }

      // Anomaly detection per interaction
      if (isSuspiciousRequest({ pagePath, userAgent: interactionUserAgent })) {
        skipCount++;
        continue;
      }

      // Generate session ID
      const sessionId = generateSessionId(
        interactionUserAgent || defaultUserAgent,
        request
      );

      // Normalize path
      const normalizedPath = normalizePath(pagePath);

      // Record interaction
      try {
        deploymentDb.recordInteraction({
          sessionId,
          pagePath: normalizedPath,
          interactionType,
          elementSelector,
          coordinates: coordinates ? {
            x: coordinates.x,
            y: coordinates.y,
            scrollY: coordinates.scrollY,
            viewportWidth: coordinates.viewportWidth,
            viewportHeight: coordinates.viewportHeight,
            documentHeight: coordinates.documentHeight,
          } : undefined,
          scrollDepth,
          timeOnPage,
        });
        successCount++;
      } catch (error) {
        console.error('[Analytics Batch] Error inserting interaction:', error);
        skipCount++;
      }
    }

    return NextResponse.json({
      success: true,
      processed: successCount,
      skipped: skipCount,
      total: interactions.length,
    });
  } catch (error) {
    console.error('[Analytics Batch] Error processing batch:', error);
    return NextResponse.json(
      { error: 'Failed to process batch interactions' },
      { status: 500 }
    );
  }
}
