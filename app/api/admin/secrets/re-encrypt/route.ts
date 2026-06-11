/**
 * Admin API: Re-encrypt all deployment secrets with the latest encryption key.
 *
 * POST /api/admin/secrets/re-encrypt
 *
 * This endpoint is used during key rotation to re-encrypt all secrets
 * that were encrypted with older keys to the current active key.
 * Requires admin authentication (DB-verified).
 *
 * Body (optional):
 * - deploymentId: If provided, only re-encrypt secrets for that deployment.
 *                 If omitted, re-encrypt secrets across ALL deployments.
 */

import { NextRequest, NextResponse } from 'next/server';
import { requireAdmin } from '@/lib/auth/session';
import { reEncryptSecret, clearKeyCache, getEncryptionKey } from '@/lib/edge-functions/secrets-crypto';
import { getSystemDatabase } from '@/lib/auth/system-database';
import { internalErrorResponse } from '@/lib/security/error-response';
import { adminRateLimiter, RATE_LIMIT_CONFIG, getIdentifier } from '@/lib/analytics/rate-limiter';

export async function POST(request: NextRequest) {
  // SECURITY (Step 51): Rate limit admin API routes
  const identifier = getIdentifier(request);
  if (!adminRateLimiter.check(identifier, RATE_LIMIT_CONFIG.admin)) {
    const retryAfter = adminRateLimiter.getResetTime(identifier, RATE_LIMIT_CONFIG.admin);
    return NextResponse.json(
      { error: 'Too many requests' },
      { status: 429, headers: { 'Retry-After': String(retryAfter) } }
    );
  }

  // Verify admin status from database (not just JWT claim)
  await requireAdmin();

  // Check that encryption is configured
  try {
    getEncryptionKey();
  } catch {
    return NextResponse.json(
      { error: 'Secrets encryption not configured. Set SECRETS_ENCRYPTION_KEY environment variable.' },
      { status: 500 }
    );
  }

  let body: { deploymentId?: string } = {};
  try {
    body = await request.json();
  } catch {
    // Empty body is fine — means re-encrypt all deployments
  }

  const systemDb = getSystemDatabase();
  const results = {
    deploymentsProcessed: 0,
    secretsReEncrypted: 0,
    errors: [] as string[],
  };

  try {
    // Get all deployment IDs from the system database
    const deployments = systemDb.prepare(`
      SELECT d.id, d.project_id
      FROM deployments d
      WHERE d.id LIKE 'dep-%'
    `).all() as Array<{ id: string; project_id: string }>;

    for (const deployment of deployments) {
      // If a specific deploymentId was requested, skip others
      if (body.deploymentId && deployment.id !== body.deploymentId) {
        continue;
      }

      try {
        // Open the deployment's runtime database
        const { getRuntimeDatabaseConnection } = await import('@/lib/vfs/adapters/sqlite-connection');
        const runtimeDb = getRuntimeDatabaseConnection(deployment.id);

        // Get all secrets with their encrypted values
        const secrets = runtimeDb.prepare(
          'SELECT id, name, encrypted_value, iv, auth_tag, key_version FROM secrets'
        ).all() as Array<{
          id: string;
          name: string;
          encrypted_value: string;
          iv: string;
          auth_tag: string;
          key_version: string | null;
        }>;

        for (const secret of secrets) {
          try {
            // Re-encrypt with the latest key
            const reEncrypted = reEncryptSecret(
              secret.encrypted_value,
              secret.iv,
              secret.auth_tag,
              secret.key_version || undefined
            );

            // Update the secret in the database
            runtimeDb.prepare(`
              UPDATE secrets
              SET encrypted_value = ?, iv = ?, auth_tag = ?, key_version = ?, updated_at = ?
              WHERE id = ?
            `).run(
              reEncrypted.encryptedValue,
              reEncrypted.iv,
              reEncrypted.authTag,
              reEncrypted.keyVersion || null,
              new Date().toISOString(),
              secret.id
            );

            results.secretsReEncrypted++;
          } catch (err) {
            results.errors.push(
              `Failed to re-encrypt secret in deployment ${deployment.id}: ${err instanceof Error ? err.message : String(err)}`
            );
          }
        }

        results.deploymentsProcessed++;
      } catch (err) {
        results.errors.push(
          `Failed to process deployment ${deployment.id}: ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }

    // Clear the key cache after rotation
    clearKeyCache();

    return NextResponse.json({
      success: true,
      message: `Re-encrypted ${results.secretsReEncrypted} secrets across ${results.deploymentsProcessed} deployments`,
      ...results,
    });
  } catch (err) {
    return NextResponse.json(
      ...internalErrorResponse(err)
    );
  }
}
