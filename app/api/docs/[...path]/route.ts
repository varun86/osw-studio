/**
 * API Route for Documentation Files
 * GET /api/docs/[...path] - Serve documentation files from /docs/
 *
 * This prevents docs from being publicly accessible in /public/
 * while still allowing the admin interface to read them.
 *
 * SECURITY (Step 52): Requires authentication — docs were moved out of /public/
 * specifically to restrict access, so the API route must enforce auth.
 */

import { NextRequest, NextResponse } from 'next/server';
import { readFile } from 'fs/promises';
import { join, resolve, sep } from 'path';
import { verifySession, verifyInstanceApiKey, SESSION_COOKIE_NAME } from '@/lib/auth/session';
import { internalErrorResponse } from '@/lib/security/error-response';

const DOCS_ROOT = resolve(process.cwd(), 'docs');

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  // SECURITY (Step 52): Require authentication to access docs
  // These files were moved from /public/ to restrict access —
  // without auth, the move is defeated.
  const token = request.cookies.get(SESSION_COOKIE_NAME)?.value;
  if (token) {
    const session = await verifySession(token);
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
  } else {
    // Also accept instance API key (machine-to-machine)
    const apiSession = verifyInstanceApiKey(request);
    if (!apiSession) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
  }

  try {
    const { path } = await params;

    // Security: prevent path traversal using path.resolve()
    // Resolve the full path and verify it stays within the docs root directory
    const filename = path.join('/');
    const resolvedPath = resolve(DOCS_ROOT, filename);

    // Ensure the resolved path is within the docs root directory
    // Using separator-aware prefix check to prevent traversal attacks like:
    // - ".." sequences that escape the docs directory
    // - Absolute paths that point outside the docs directory
    if (!resolvedPath.startsWith(DOCS_ROOT + sep) && resolvedPath !== DOCS_ROOT) {
      return NextResponse.json(
        { error: 'Invalid path' },
        { status: 400 }
      );
    }

    // Read file from /docs/ directory
    const content = await readFile(resolvedPath, 'utf-8');

    // Return as plain text with markdown content type
    return new NextResponse(content, {
      headers: {
        'Content-Type': 'text/markdown; charset=utf-8',
        'Cache-Control': 'public, max-age=3600', // Cache for 1 hour
      },
    });
  } catch (error) {
    console.error('[Docs API] Error reading file:', error);

    // Check if file doesn't exist
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return NextResponse.json(
        { error: 'Document not found' },
        { status: 404 }
      );
    }

    return NextResponse.json(...internalErrorResponse(error));
  }
}
