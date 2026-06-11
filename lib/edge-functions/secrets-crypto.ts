/**
 * Secrets Encryption Utilities
 *
 * Provides AES-256-GCM encryption for storing secrets securely.
 * Uses environment variable SECRETS_ENCRYPTION_KEY for the master key.
 *
 * Key Rotation Support:
 * - Multiple keys supported via SECRETS_ENCRYPTION_KEY_V1, _V2, etc.
 * - SECRETS_ENCRYPTION_KEY is always the latest (active) key used for encryption
 * - Decryption tries all available keys to support rotation
 * - Encrypted records include a keyVersion field for efficient key selection
 */

import crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32; // 256 bits

export interface EncryptedSecret {
  encryptedValue: string;
  iv: string;
  authTag: string;
  /** Key version used for encryption (e.g., "1", "2") */
  keyVersion?: string;
}

// Cache for parsed encryption keys
let keyCache: Map<string, Buffer> | null = null;

/**
 * Get all available encryption keys from environment variables.
 * Returns a Map of version -> key buffer.
 *
 * Key lookup order:
 * 1. SECRETS_ENCRYPTION_KEY_V{n} for n = 1, 2, 3, ...
 * 2. SECRETS_ENCRYPTION_KEY (treated as the latest version)
 *
 * The latest version number is determined by finding the highest _V{n} suffix,
 * or defaulting to the number of explicitly versioned keys + 1.
 */
function getAllEncryptionKeys(): Map<string, Buffer> {
  if (keyCache) return keyCache;

  const keys = new Map<string, Buffer>();
  let latestVersion = 0;

  // First, look for explicitly versioned keys: SECRETS_ENCRYPTION_KEY_V1, _V2, etc.
  for (let v = 1; v <= 10; v++) {
    const keyBase64 = process.env[`SECRETS_ENCRYPTION_KEY_V${v}`];
    if (keyBase64) {
      const key = Buffer.from(keyBase64, 'base64');
      if (key.length === KEY_LENGTH) {
        keys.set(String(v), key);
        latestVersion = v;
      }
    }
  }

  // SECRETS_ENCRYPTION_KEY is always the active (latest) key
  const activeKeyBase64 = process.env.SECRETS_ENCRYPTION_KEY;
  if (activeKeyBase64) {
    const activeKey = Buffer.from(activeKeyBase64, 'base64');
    if (activeKey.length === KEY_LENGTH) {
      // If no versioned keys found, this is version "1"
      // Otherwise, it's the next version after the last versioned key
      const activeVersion = latestVersion > 0 ? String(latestVersion + 1) : '1';
      keys.set(activeVersion, activeKey);
    }
  }

  keyCache = keys;
  return keys;
}

/**
 * Get the active (latest) encryption key and its version.
 * This is the key used for NEW encryptions.
 * @throws Error if no encryption key is configured
 */
function getActiveKey(): { key: Buffer; version: string } {
  const keys = getAllEncryptionKeys();
  if (keys.size === 0) {
    throw new Error('SECRETS_ENCRYPTION_KEY environment variable not set');
  }

  // Find the highest version number
  let maxVersion = '1';
  for (const version of keys.keys()) {
    if (parseInt(version) > parseInt(maxVersion)) {
      maxVersion = version;
    }
  }

  return { key: keys.get(maxVersion)!, version: maxVersion };
}

/**
 * Get the encryption key from environment variable (backward compatible)
 * @throws Error if SECRETS_ENCRYPTION_KEY is not set or invalid
 */
export function getEncryptionKey(): Buffer {
  return getActiveKey().key;
}

/**
 * Check if encryption key is configured
 */
export function isEncryptionConfigured(): boolean {
  try {
    getEncryptionKey();
    return true;
  } catch {
    return false;
  }
}

/**
 * Encrypt a secret value using the active (latest) key
 * @param plaintext The secret value to encrypt
 * @returns Encrypted data with IV, auth tag, and key version
 */
export function encryptSecret(plaintext: string): EncryptedSecret {
  const { key, version } = getActiveKey();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  let encrypted = cipher.update(plaintext, 'utf8', 'base64');
  encrypted += cipher.final('base64');

  return {
    encryptedValue: encrypted,
    iv: iv.toString('base64'),
    authTag: cipher.getAuthTag().toString('base64'),
    keyVersion: version,
  };
}

/**
 * Decrypt an encrypted secret, trying all available keys for key rotation support.
 * @param encryptedValue The encrypted value (base64)
 * @param iv The initialization vector (base64)
 * @param authTag The authentication tag (base64)
 * @param keyVersion Optional key version hint for efficient decryption
 * @returns The decrypted plaintext
 * @throws Error if decryption fails with all available keys
 */
export function decryptSecret(
  encryptedValue: string,
  iv: string,
  authTag: string,
  keyVersion?: string
): string {
  const keys = getAllEncryptionKeys();
  if (keys.size === 0) {
    throw new Error('SECRETS_ENCRYPTION_KEY environment variable not set');
  }

  // If a key version is specified, try that key first
  if (keyVersion && keys.has(keyVersion)) {
    try {
      return decryptWithKey(keys.get(keyVersion)!, encryptedValue, iv, authTag);
    } catch {
      // Key version hint didn't work, fall through to try all keys
    }
  }

  // Try all available keys (from newest to oldest)
  const sortedVersions = [...keys.keys()].sort((a, b) => parseInt(b) - parseInt(a));
  for (const version of sortedVersions) {
    try {
      return decryptWithKey(keys.get(version)!, encryptedValue, iv, authTag);
    } catch {
      // This key didn't work, try the next one
    }
  }

  throw new Error('Failed to decrypt secret with any available key');
}

/**
 * Decrypt with a specific key (internal helper)
 */
function decryptWithKey(
  key: Buffer,
  encryptedValue: string,
  iv: string,
  authTag: string
): string {
  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    key,
    Buffer.from(iv, 'base64')
  );
  decipher.setAuthTag(Buffer.from(authTag, 'base64'));

  let decrypted = decipher.update(encryptedValue, 'base64', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

/**
 * Re-encrypt a secret with the latest key.
 * Used during key rotation to update secrets to the new key.
 *
 * @param encryptedValue The current encrypted value
 * @param iv The current IV
 * @param authTag The current auth tag
 * @param keyVersion The current key version
 * @returns Re-encrypted secret with the latest key
 */
export function reEncryptSecret(
  encryptedValue: string,
  iv: string,
  authTag: string,
  keyVersion?: string
): EncryptedSecret {
  const plaintext = decryptSecret(encryptedValue, iv, authTag, keyVersion);
  return encryptSecret(plaintext);
}

/**
 * Generate a new encryption key (for initial setup or rotation)
 * @returns Base64-encoded 256-bit key
 */
export function generateEncryptionKey(): string {
  return crypto.randomBytes(KEY_LENGTH).toString('base64');
}

/**
 * Clear the key cache (useful after env var changes)
 */
export function clearKeyCache(): void {
  keyCache = null;
}
