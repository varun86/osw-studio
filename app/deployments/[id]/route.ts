/**
 * Public Deployments Route - Root
 *
 * Serves index.html from public/deployments/[id]/
 * Disabled when STATIC_PROXY=true (Caddy serves static files directly).
 */

import { NextRequest, NextResponse } from 'next/server';
import { promises as fs } from 'fs';
import path from 'path';

/**
 * Validate deployment ID for use in filesystem paths.
 * Only alphanumeric, hyphens, and underscores allowed.
 */
function isValidDeploymentId(id: string): boolean {
  return /^[a-zA-Z0-9_-]+$/.test(id);
}

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  if (process.env.STATIC_PROXY === 'true') {
    return new NextResponse('Not found', { status: 404 });
  }

  const { id } = await params;

  // Validate deployment ID to prevent path traversal
  if (!isValidDeploymentId(id)) {
    return new NextResponse('Invalid deployment ID', { status: 400 });
  }

  try {
    const indexPath = path.join(process.cwd(), 'public', 'deployments', id, 'index.html');

    try {
      await fs.access(indexPath);
    } catch {
      return new NextResponse('Deployment not found', { status: 404 });
    }

    const content = await fs.readFile(indexPath, 'utf-8');

    return new NextResponse(content, {
      status: 200,
      headers: {
        'Content-Type': 'text/html',
        'Cache-Control': 'public, max-age=3600',
      },
    });
  } catch (error) {
    console.error('[Deployments Route] Error:', error);
    return new NextResponse('Internal server error', { status: 500 });
  }
}
