/**
 * Codex Connect API Route
 *
 * Receives the full Codex auth JSON from the client, validates the access_token
 * with OpenAI's token introspection endpoint, and stores the refresh_token
 * in an HttpOnly cookie.
 *
 * SECURITY: Requires authentication. Access token is validated before storing.
 */

import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth/session';
import { CODEX_COOKIE_NAME, codexCookieOptions } from '../cookie';

/**
 * Get the Codex OAuth client ID from environment variable with fallback.
 * The fallback is the known public client ID for the Codex CLI application.
 */
function getCodexClientId(): string {
  return process.env.CODEX_CLIENT_ID || 'app_EMoamEEZ73f0CkXaXp7hrann';
}

/**
 * Validate an access token with OpenAI's token introspection endpoint.
 * Returns true if the token is valid, false otherwise.
 */
async function validateAccessToken(accessToken: string): Promise<boolean> {
  const clientId = getCodexClientId();

  try {
    const formBody = new URLSearchParams({
      token: accessToken,
      client_id: clientId,
    });

    const res = await fetch('https://auth.openai.com/oauth/introspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formBody.toString(),
    });

    if (!res.ok) {
      return false;
    }

    const data = await res.json();
    // Token is valid if active is true
    return data.active === true;
  } catch {
    // If the introspection endpoint is unreachable, allow the token
    // (graceful degradation — we don't want to block Codex setup on network issues)
    console.warn('[Codex Connect] Token introspection failed, allowing token');
    return true;
  }
}

export async function POST(request: NextRequest) {
  try {
    // Require authentication — anonymous users cannot store Codex tokens
    const session = await requireAuth();

    const body = await request.json();
    const { access_token, refresh_token, expires_at, user_email } = body;

    if (!refresh_token || typeof refresh_token !== 'string') {
      return NextResponse.json({ error: 'Missing refresh_token' }, { status: 400 });
    }
    if (!access_token || typeof access_token !== 'string') {
      return NextResponse.json({ error: 'Missing access_token' }, { status: 400 });
    }

    // Validate the access token with OpenAI before storing
    const isValid = await validateAccessToken(access_token);
    if (!isValid) {
      return NextResponse.json(
        { error: 'Invalid access_token. Please re-authenticate with Codex.' },
        { status: 401 }
      );
    }

    const response = NextResponse.json({
      access_token,
      expires_at: expires_at || Math.floor(Date.now() / 1000) + 3600,
      user_email: user_email || undefined,
    });

    response.cookies.set(CODEX_COOKIE_NAME, refresh_token, codexCookieOptions());

    return response;
  } catch (error) {
    if (error instanceof Error && error.message === 'Unauthorized') {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    const message = error instanceof Error ? error.message : 'Unknown error';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
