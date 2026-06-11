/**
 * /api/user/keys — Server-Side Encrypted API Key Management
 *
 * GET  — List all stored API keys for the current user (hints only)
 * POST — Store (or update) an API key (encrypted server-side)
 * DELETE — Remove an API key for a specific provider
 *
 * Also supports POST with { action: 'migrate', providerKeys: {...} }
 * for bulk migration from localStorage.
 */

import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth/session';
import {
  storeApiKey,
  getApiKey,
  listApiKeys,
  deleteApiKey,
  migrateLocalStorageKeys,
  isServerKeyStorageAvailable,
} from '@/lib/auth/api-key-store';
import { logger } from '@/lib/utils';

// ---------------------------------------------------------------------------
// GET — List all stored API keys (hints only)
// ---------------------------------------------------------------------------

export async function GET() {
  try {
    const session = await requireAuth();
    const keys = listApiKeys(session.userId);
    return NextResponse.json({ keys });
  } catch {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
}

// ---------------------------------------------------------------------------
// POST — Store an API key or migrate from localStorage
// ---------------------------------------------------------------------------

export async function POST(request: NextRequest) {
  try {
    const session = await requireAuth();
    const body = await request.json();

    // Check if server-side key storage is available
    if (!isServerKeyStorageAvailable()) {
      return NextResponse.json(
        { error: 'Server-side key storage is not available. SECRETS_ENCRYPTION_KEY must be configured.' },
        { status: 503 }
      );
    }

    // Bulk migration from localStorage
    if (body.action === 'migrate' && body.providerKeys && typeof body.providerKeys === 'object') {
      const results = migrateLocalStorageKeys(session.userId, body.providerKeys as Record<string, string>);
      return NextResponse.json({ migrated: results });
    }

    // Single key store
    const { provider, apiKey } = body;

    if (!provider || !apiKey) {
      return NextResponse.json(
        { error: 'Provider and apiKey are required' },
        { status: 400 }
      );
    }

    if (typeof provider !== 'string' || typeof apiKey !== 'string') {
      return NextResponse.json(
        { error: 'Provider and apiKey must be strings' },
        { status: 400 }
      );
    }

    // Validate provider name — only alphanumeric, hyphens, underscores
    if (!/^[a-zA-Z0-9_-]+$/.test(provider)) {
      return NextResponse.json(
        { error: 'Invalid provider name' },
        { status: 400 }
      );
    }

    try {
      const result = storeApiKey(session.userId, provider, apiKey);
      logger.info(`[api/user/keys] Stored API key for provider=${provider}, user=${session.userId}`);
      return NextResponse.json(result);
    } catch (err) {
      logger.error('[api/user/keys] Failed to store API key:', err);
      return NextResponse.json(
        { error: 'Failed to store API key' },
        { status: 500 }
      );
    }
  } catch {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
}

// ---------------------------------------------------------------------------
// DELETE — Remove an API key for a provider
// ---------------------------------------------------------------------------

export async function DELETE(request: NextRequest) {
  try {
    const session = await requireAuth();
    const body = await request.json();
    const { provider } = body;

    if (!provider) {
      return NextResponse.json(
        { error: 'Provider is required' },
        { status: 400 }
      );
    }

    const deleted = deleteApiKey(session.userId, provider);

    if (deleted) {
      logger.info(`[api/user/keys] Deleted API key for provider=${provider}, user=${session.userId}`);
      return NextResponse.json({ success: true });
    } else {
      return NextResponse.json(
        { error: 'API key not found for this provider' },
        { status: 404 }
      );
    }
  } catch {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
}
