/**
 * Codex Disconnect API Route
 *
 * Deletes the HttpOnly refresh token cookie.
 * SECURITY: Requires authentication.
 */

import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth/session';
import { CODEX_COOKIE_NAME, codexCookieOptions } from '../cookie';

export async function POST(request: NextRequest) {
  try {
    // Require authentication — anonymous users cannot disconnect Codex
    await requireAuth();

    const response = NextResponse.json({ success: true });
    response.cookies.set(CODEX_COOKIE_NAME, '', codexCookieOptions(0));
    return response;
  } catch (error) {
    if (error instanceof Error && error.message === 'Unauthorized') {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    return NextResponse.json({ error: 'Failed to disconnect' }, { status: 500 });
  }
}
