/**
 * Telemetry Configuration
 *
 * SECURITY: The telemetry token must be provided via the NEXT_PUBLIC_ANALYTICS_TOKEN
 * environment variable. There is NO hardcoded fallback token.
 *
 * If the token is not set, telemetry will still function but without
 * authentication headers — the receiving endpoint should reject
 * unauthenticated requests in production.
 */

export const TELEMETRY_ENDPOINT =
  process.env.NEXT_PUBLIC_ANALYTICS_ENDPOINT || 'https://stats.oswstudio.com/collect';

/**
 * Telemetry authentication token.
 *
 * SECURITY: Must be set via NEXT_PUBLIC_ANALYTICS_TOKEN environment variable.
 * No hardcoded default — hardcoding secrets in source code is a critical
 * vulnerability that allows anyone with repo access to forge telemetry data.
 *
 * To set up: add NEXT_PUBLIC_ANALYTICS_TOKEN=<your-token> to your .env file
 */
export const TELEMETRY_TOKEN: string = process.env.NEXT_PUBLIC_ANALYTICS_TOKEN || '';

export const TELEMETRY_ENABLED =
  process.env.NEXT_PUBLIC_TELEMETRY_ENABLED !== 'false';

export const TELEMETRY_DEBUG =
  process.env.NEXT_PUBLIC_TELEMETRY_DEBUG === 'true';

export const FLUSH_INTERVAL_MS = 30_000;
export const MAX_BATCH_SIZE = 50;
export const MAX_RETRIES = 3;
export const RETRY_BASE_MS = 1_000;
export const HEARTBEAT_INTERVAL_MS = 300_000;

export function detectDeploymentType(): 'hf_space' | 'desktop' | 'managed' | 'server' | 'browser' {
  if (typeof window !== 'undefined') {
    const hostname = window.location.hostname;
    if (hostname.includes('hf.space') || hostname.includes('huggingface.co')) {
      return 'hf_space';
    }
  }
  if (process.env.NEXT_PUBLIC_DESKTOP === 'true') {
    return 'desktop';
  }
  if (process.env.NEXT_PUBLIC_SERVER_MODE === 'true') {
    if (process.env.NEXT_PUBLIC_GATEWAY_URL) {
      return 'managed';
    }
    return 'server';
  }
  return 'browser';
}

export function getManagedContext(): Record<string, string> | null {
  if (detectDeploymentType() !== 'managed') return null;
  const ctx: Record<string, string> = {};
  if (process.env.NEXT_PUBLIC_INSTANCE_ID) ctx.instance_id = process.env.NEXT_PUBLIC_INSTANCE_ID;
  if (process.env.NEXT_PUBLIC_GATEWAY_URL) ctx.gateway_url = process.env.NEXT_PUBLIC_GATEWAY_URL;
  return ctx;
}

import pkg from '@/package.json';

export function getAppVersion(): string {
  return pkg.version;
}

export function detectOsPlatform(): string {
  if (typeof navigator === 'undefined') return 'unknown';
  const ua = navigator.userAgent.toLowerCase();
  if (ua.includes('win')) return 'windows';
  if (ua.includes('mac')) return 'macos';
  if (ua.includes('linux')) return 'linux';
  return 'unknown';
}
