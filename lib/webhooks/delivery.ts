/**
 * Webhook Delivery System
 *
 * Outbound webhook delivery with HMAC-SHA256 signature verification.
 *
 * SECURITY (Step 42): Webhook Signature Verification Documentation
 * ================================================================
 * Consumers of OSW Studio webhooks MUST verify the signature to ensure
 * payload authenticity and integrity. The verification algorithm is:
 *
 * 1. Algorithm: HMAC-SHA256
 * 2. Header: x-webhook-signature
 * 3. Secret: The same WEBHOOK_SECRET environment variable configured on this server
 * 4. Verification steps:
 *    a. Read the raw request body as a string (do NOT parse JSON first)
 *    b. Compute: HMAC-SHA256(raw_body, WEBHOOK_SECRET) as hex digest
 *    c. Compare the result with the value of the x-webhook-signature header
 *    d. Use constant-time comparison to prevent timing attacks
 *
 * Example (Node.js):
 *   const crypto = require('crypto');
 *   const expected = crypto.createHmac('sha256', WEBHOOK_SECRET)
 *     .update(rawBody).digest('hex');
 *   if (crypto.timingSafeEqual(
 *     Buffer.from(expected, 'hex'),
 *     Buffer.from(signature, 'hex')
 *   )) { /* verified *\/ }
 *
 * Example (Python):
 *   import hmac, hashlib
 *   expected = hmac.new(WEBHOOK_SECRET.encode(), raw_body, hashlib.sha256).hexdigest()
 *   if hmac.compare_digest(expected, signature):  # verified
 *
 * Payload format (JSON):
 *   { "event_type": string, "payload": object, "timestamp": string }
 *
 * Headers:
 *   Content-Type: application/json
 *   x-instance-id: The OSW Studio instance identifier
 *   x-webhook-signature: HMAC-SHA256 hex digest of the raw body
 */

import { createHmac } from 'crypto';
import { getPendingEvents, markDelivered, markFailed, pruneDelivered, isWebhookEnabled } from './outbox';
import { logger } from '@/lib/utils';
import type { WebhookEvent } from './types';

const WEBHOOK_URL = process.env.WEBHOOK_URL;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
const INSTANCE_ID = process.env.INSTANCE_ID || 'unknown';

const BACKOFF_SCHEDULE = [5, 30, 120, 600, 600, 600, 600, 600, 600, 600]; // seconds

function signPayload(body: string): string | null {
  if (!WEBHOOK_SECRET) return null;
  return createHmac('sha256', WEBHOOK_SECRET).update(body).digest('hex');
}

function shouldDeliver(event: WebhookEvent): boolean {
  if (event.attempts === 0) return true;
  if (!event.last_attempted_at) return true;
  const backoffSeconds = BACKOFF_SCHEDULE[Math.min(event.attempts - 1, BACKOFF_SCHEDULE.length - 1)];
  const nextAttempt = new Date(event.last_attempted_at).getTime() + backoffSeconds * 1000;
  return Date.now() >= nextAttempt;
}

async function deliverEvent(event: WebhookEvent): Promise<boolean> {
  const body = JSON.stringify({
    event_type: event.event_type,
    payload: JSON.parse(event.payload),
    timestamp: event.created_at,
  });

  const signature = signPayload(body);
  if (!signature) {
    markFailed(event.id);
    return false;
  }

  try {
    const response = await fetch(`${WEBHOOK_URL}/api/webhooks/osws`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-instance-id': INSTANCE_ID,
        'x-webhook-signature': signature,
      },
      body,
      signal: AbortSignal.timeout(10000),
    });

    if (response.ok) {
      markDelivered(event.id);
      return true;
    } else {
      markFailed(event.id);
      return false;
    }
  } catch {
    markFailed(event.id);
    return false;
  }
}

export async function deliverPendingEvents(): Promise<{ delivered: number; failed: number }> {
  if (!isWebhookEnabled()) return { delivered: 0, failed: 0 };

  const events = getPendingEvents();
  let delivered = 0;
  let failed = 0;

  for (const event of events) {
    if (!shouldDeliver(event)) continue;
    const success = await deliverEvent(event);
    if (success) delivered++;
    else failed++;
  }

  // Prune old delivered events
  pruneDelivered();

  return { delivered, failed };
}

let deliveryInterval: ReturnType<typeof setInterval> | null = null;

export function startDeliveryLoop(): void {
  if (deliveryInterval || !isWebhookEnabled()) return;
  deliveryInterval = setInterval(() => {
    deliverPendingEvents().catch(err => logger.error('[Webhook] Delivery failed:', err));
  }, 5000);
}

export function stopDeliveryLoop(): void {
  if (deliveryInterval) {
    clearInterval(deliveryInterval);
    deliveryInterval = null;
  }
}
