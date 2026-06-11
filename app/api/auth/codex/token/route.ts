import { NextRequest, NextResponse } from 'next/server';
import { CODEX_COOKIE_NAME, codexCookieOptions } from '../cookie';

/**
 * Get the Codex OAuth client ID from environment variable with fallback.
 */
function getCodexClientId(): string {
  return process.env.CODEX_CLIENT_ID || 'app_EMoamEEZ73f0CkXaXp7hrann';
}

/**
 * Refreshes the Codex access token using the refresh_token stored in the
 * HttpOnly cookie. The client never sees or sends the refresh_token.
 */
export async function POST(request: NextRequest) {
  try {
    const refreshToken = request.cookies.get(CODEX_COOKIE_NAME)?.value;

    if (!refreshToken) {
      return NextResponse.json(
        { error: 'No refresh token cookie. Please re-authenticate.' },
        { status: 401 },
      );
    }

    const formBody = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: getCodexClientId(),
      refresh_token: refreshToken,
    });

    const res = await fetch('https://auth.openai.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formBody.toString(),
    });

    const data = await res.json();

    if (!res.ok) {
      // If the refresh token is revoked/expired, clear the cookie
      if (res.status === 401 || res.status === 403) {
        const errResponse = NextResponse.json(
          { error: data.error_description || 'Refresh token revoked' },
          { status: 401 },
        );
        errResponse.cookies.set(CODEX_COOKIE_NAME, '', codexCookieOptions(0));
        return errResponse;
      }
      return NextResponse.json(data, { status: res.status });
    }

    const response = NextResponse.json({
      access_token: data.access_token,
      expires_at: Math.floor(Date.now() / 1000) + (data.expires_in || 3600),
    });

    // If OpenAI rotated the refresh token, update the cookie
    if (data.refresh_token && data.refresh_token !== refreshToken) {
      response.cookies.set(CODEX_COOKIE_NAME, data.refresh_token, codexCookieOptions());
    }

    return response;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
