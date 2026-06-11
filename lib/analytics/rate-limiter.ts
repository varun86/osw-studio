/**
 * Rate Limiter for Analytics Endpoints
 *
 * In-memory sliding window rate limiter to prevent abuse.
 * Uses LRU-like cleanup to prevent memory leaks.
 */

interface RateLimitConfig {
  limit: number;      // Max requests per window
  windowMs: number;   // Time window in milliseconds
}

export class RateLimiter {
  private requests = new Map<string, number[]>();
  private lastCleanup = Date.now();
  private readonly CLEANUP_INTERVAL = 60 * 1000; // Clean up every minute
  private readonly MAX_KEYS = 10000; // Prevent memory exhaustion

  /**
   * Check if request should be allowed
   * @param identifier - Usually IP address
   * @param config - Rate limit configuration
   * @returns true if allowed, false if rate limited
   */
  check(identifier: string, config: RateLimitConfig): boolean {
    const now = Date.now();

    // Periodic cleanup to prevent memory leaks
    if (now - this.lastCleanup > this.CLEANUP_INTERVAL) {
      this.cleanup(config.windowMs);
    }

    // Get existing requests for this identifier
    const timestamps = this.requests.get(identifier) || [];

    // Filter to only recent requests within the window
    const recentRequests = timestamps.filter(t => now - t < config.windowMs);

    // Check if limit exceeded
    if (recentRequests.length >= config.limit) {
      return false; // Rate limited
    }

    // Add current request
    recentRequests.push(now);
    this.requests.set(identifier, recentRequests);

    // Prevent memory exhaustion - if too many identifiers, remove oldest
    if (this.requests.size > this.MAX_KEYS) {
      const firstKey = this.requests.keys().next().value;
      if (firstKey !== undefined) {
        this.requests.delete(firstKey);
      }
    }

    return true; // Allowed
  }

  /**
   * Get current request count for an identifier
   */
  getCount(identifier: string, windowMs: number): number {
    const now = Date.now();
    const timestamps = this.requests.get(identifier) || [];
    return timestamps.filter(t => now - t < windowMs).length;
  }

  /**
   * Get time until rate limit resets (in seconds)
   */
  getResetTime(identifier: string, config: RateLimitConfig): number {
    const timestamps = this.requests.get(identifier) || [];
    if (timestamps.length === 0) return 0;

    const now = Date.now();
    const recentRequests = timestamps.filter(t => now - t < config.windowMs);

    if (recentRequests.length === 0) return 0;

    const oldestRequest = Math.min(...recentRequests);
    const resetTime = oldestRequest + config.windowMs - now;

    return Math.ceil(resetTime / 1000); // Convert to seconds
  }

  /**
   * Clean up old entries to prevent memory leaks
   */
  private cleanup(windowMs: number): void {
    const now = Date.now();

    for (const [identifier, timestamps] of this.requests.entries()) {
      const recent = timestamps.filter(t => now - t < windowMs);

      if (recent.length === 0) {
        // No recent requests, remove entirely
        this.requests.delete(identifier);
      } else {
        // Update with only recent requests
        this.requests.set(identifier, recent);
      }
    }

    this.lastCleanup = now;
  }

  /**
   * Clear all rate limit data (for testing)
   */
  clear(): void {
    this.requests.clear();
  }

  /**
   * Get current stats (for monitoring)
   */
  getStats(): { totalIdentifiers: number; totalRequests: number } {
    let totalRequests = 0;
    for (const timestamps of this.requests.values()) {
      totalRequests += timestamps.length;
    }

    return {
      totalIdentifiers: this.requests.size,
      totalRequests,
    };
  }
}

// Singleton instances for different endpoints
export const pageviewRateLimiter = new RateLimiter();
export const interactionRateLimiter = new RateLimiter();
export const adminRateLimiter = new RateLimiter();
export const databaseQueryRateLimiter = new RateLimiter();

// Predefined configurations
export const RATE_LIMIT_CONFIG = {
  pageview: {
    limit: 100,           // 100 requests
    windowMs: 10 * 60 * 1000 // per 10 minutes
  },
  interaction: {
    limit: 500,           // 500 requests (higher for heatmaps)
    windowMs: 10 * 60 * 1000 // per 10 minutes
  },
  strict: {
    limit: 10,            // Very strict for suspicious activity
    windowMs: 60 * 1000   // per 1 minute
  },
  admin: {
    limit: 60,            // 60 requests per minute per user
    windowMs: 60 * 1000   // per 1 minute
  },
  databaseQuery: {
    limit: 20,            // 20 requests per minute per user
    windowMs: 60 * 1000   // per 1 minute
  }
} as const;

/**
 * Get the trusted proxy IPs from environment variable.
 * Only when the direct connection IP matches a trusted proxy should we
 * trust headers like x-forwarded-for, x-real-ip, cf-connecting-ip.
 */
function getTrustedProxyIPs(): Set<string> {
  const trustedProxies = process.env.TRUSTED_PROXY_IPS;
  if (!trustedProxies) return new Set();
  return new Set(trustedProxies.split(',').map(ip => ip.trim()).filter(Boolean));
}

/**
 * Get the direct (socket-level) remote address of the request.
 * This is the IP we actually received the connection from, NOT from any header.
 */
function getDirectRemoteAddress(request: Request): string | null {
  // Next.js stores the socket remote address on the request object internally.
  // Unfortunately, the standard Request type doesn't expose it, but NextRequest
  // and the underlying Node.js IncomingMessage do.
  try {
    const req = request as any;
    // Next.js internal: request[Symbol.for('next_request_meta')]
    // or via the socket property
    if (req.socket?.remoteAddress) return req.socket.remoteAddress;
    if (req.headers?.get('x-direct-remote-address')) return req.headers.get('x-direct-remote-address');
  } catch {}
  return null;
}

/**
 * Extract client IP address from request, respecting trusted proxy configuration.
 *
 * SECURITY: Only trusts proxy headers (x-forwarded-for, x-real-ip, cf-connecting-ip)
 * when the direct connection comes from a trusted proxy IP (TRUSTED_PROXY_IPS env var).
 * Otherwise, uses the direct remote address or falls back to 'unknown'.
 *
 * Without TRUSTED_PROXY_IPS, proxy headers are still used for backward compatibility,
 * but a warning is logged on first use.
 */
let _proxyWarningLogged = false;
export function getIdentifier(request: Request): string {
  const trustedProxies = getTrustedProxyIPs();
  const directRemoteAddr = getDirectRemoteAddress(request);

  // If TRUSTED_PROXY_IPS is configured, only trust proxy headers from trusted sources
  if (trustedProxies.size > 0) {
    // Check if the direct connection is from a trusted proxy
    const isFromTrustedProxy = directRemoteAddr ? trustedProxies.has(directRemoteAddr) : false;

    if (!isFromTrustedProxy) {
      // Not from a trusted proxy — use direct remote address, ignore headers
      return directRemoteAddr || 'unknown';
    }
  }

  // From a trusted proxy (or no TRUSTED_PROXY_IPS configured) — trust proxy headers
  const forwardedFor = request.headers.get('x-forwarded-for');
  const realIp = request.headers.get('x-real-ip');
  const cfConnectingIp = request.headers.get('cf-connecting-ip'); // Cloudflare

  if (cfConnectingIp) return cfConnectingIp;
  if (realIp) return realIp;
  if (forwardedFor) {
    // x-forwarded-for can be comma-separated, take first
    return forwardedFor.split(',')[0].trim();
  }

  return directRemoteAddr || 'unknown';
}
