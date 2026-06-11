/**
 * Server-Side Encrypted API Key Store
 *
 * Stores user API keys (OpenRouter, OpenAI, Anthropic, etc.) encrypted
 * in the system SQLite database using AES-256-GCM (same as edge function
 * secrets). Only key hints (last 4 characters) are ever returned to the
 * client for display purposes.
 *
 * Falls back gracefully when SECRETS_ENCRYPTION_KEY is not configured
 * (e.g., in desktop mode).
 */

import { randomUUID } from 'crypto';
import { encryptSecret, decryptSecret, isEncryptionConfigured } from '../edge-functions/secrets-crypto';
import { getSystemDatabase } from './system-database';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface StoredApiKeyHint {
  provider: string;
  keyHint: string;
  createdAt: string;
  updatedAt: string;
}

export interface StoreApiKeyResult {
  provider: string;
  keyHint: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Generate a display hint from an API key — the last 4 characters.
 * For keys shorter than 4 chars, returns the whole key masked as "****".
 */
function makeKeyHint(apiKey: string): string {
  if (!apiKey || apiKey.length < 4) return '****';
  return apiKey.slice(-4);
}

/**
 * Check whether server-side key storage is available.
 * Returns false if SECRETS_ENCRYPTION_KEY is not configured.
 */
export function isServerKeyStorageAvailable(): boolean {
  return isEncryptionConfigured();
}

// ---------------------------------------------------------------------------
// Core operations
// ---------------------------------------------------------------------------

/**
 * Store (or update) an API key for a user + provider.
 * Encrypts the key with AES-256-GCM and stores it in user_api_keys.
 * Returns a hint (last 4 chars) for display.
 */
export function storeApiKey(userId: string, provider: string, apiKey: string): StoreApiKeyResult {
  if (!isEncryptionConfigured()) {
    throw new Error('SECRETS_ENCRYPTION_KEY not configured; cannot store API keys server-side');
  }

  const db = getSystemDatabase();
  const { encryptedValue, iv, authTag } = encryptSecret(apiKey);
  const keyHint = makeKeyHint(apiKey);
  const id = randomUUID();

  db.prepare(`
    INSERT OR REPLACE INTO user_api_keys (id, user_id, provider, encrypted_key, iv, auth_tag, key_hint, created_at, updated_at)
    VALUES (
      ?,
      ?,
      ?,
      ?,
      ?,
      ?,
      ?,
      COALESCE((SELECT created_at FROM user_api_keys WHERE user_id = ? AND provider = ?), datetime('now')),
      datetime('now')
    )
  `).run(id, userId, provider, encryptedValue, iv, authTag, keyHint, userId, provider);

  return { provider, keyHint };
}

/**
 * Retrieve and decrypt an API key for a user + provider.
 * Returns the plaintext API key, or null if not found.
 */
export function getApiKey(userId: string, provider: string): string | null {
  if (!isEncryptionConfigured()) {
    return null;
  }

  const db = getSystemDatabase();
  const row = db.prepare(
    'SELECT encrypted_key, iv, auth_tag FROM user_api_keys WHERE user_id = ? AND provider = ?'
  ).get(userId, provider) as { encrypted_key: string; iv: string; auth_tag: string } | undefined;

  if (!row) return null;

  try {
    return decryptSecret(row.encrypted_key, row.iv, row.auth_tag);
  } catch {
    // Decryption failure (e.g., key rotation) — treat as not found
    console.error(`[api-key-store] Failed to decrypt API key for user=${userId} provider=${provider}`);
    return null;
  }
}

/**
 * List all stored API keys for a user. Returns only hints (no decrypted values).
 */
export function listApiKeys(userId: string): StoredApiKeyHint[] {
  const db = getSystemDatabase();
  const rows = db.prepare(
    'SELECT provider, key_hint, created_at, updated_at FROM user_api_keys WHERE user_id = ? ORDER BY provider'
  ).all(userId) as { provider: string; key_hint: string; created_at: string; updated_at: string }[];

  return rows.map(r => ({
    provider: r.provider,
    keyHint: r.key_hint,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  }));
}

/**
 * Delete a specific API key for a user + provider.
 */
export function deleteApiKey(userId: string, provider: string): boolean {
  const db = getSystemDatabase();
  const result = db.prepare(
    'DELETE FROM user_api_keys WHERE user_id = ? AND provider = ?'
  ).run(userId, provider);
  return result.changes > 0;
}

/**
 * Delete all API keys for a user (e.g., on account deactivation).
 */
export function deleteAllUserApiKeys(userId: string): number {
  const db = getSystemDatabase();
  const result = db.prepare(
    'DELETE FROM user_api_keys WHERE user_id = ?'
  ).run(userId);
  return result.changes;
}

/**
 * Bulk-migrate API keys from localStorage to server-side storage.
 * Accepts a map of provider → apiKey and stores each one.
 * Returns a list of results with hints for successful migrations.
 */
export function migrateLocalStorageKeys(
  userId: string,
  providerKeys: Record<string, string>
): StoreApiKeyResult[] {
  const results: StoreApiKeyResult[] = [];

  for (const [provider, apiKey] of Object.entries(providerKeys)) {
    if (!apiKey || typeof apiKey !== 'string') continue;
    try {
      const result = storeApiKey(userId, provider, apiKey);
      results.push(result);
    } catch (err) {
      console.error(`[api-key-store] Failed to migrate key for provider=${provider}:`, err);
    }
  }

  return results;
}
