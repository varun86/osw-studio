/**
 * Workspace-Scoped Individual Deployment Operations
 *
 * GET - Get deployment by ID
 * PUT - Update deployment
 * DELETE - Delete deployment
 */

import { logger } from '@/lib/utils';
import { NextRequest, NextResponse } from 'next/server';
import { getWorkspaceContext } from '@/lib/api/workspace-context';
import { cleanStaticDeployment } from '@/lib/compiler/static-builder';
import { removeDeploymentRoute } from '@/lib/auth/system-database';
import { regenerateInstanceCaddy } from '@/lib/caddy/regenerate';

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ workspaceId: string; id: string }> }
) {
  try {
    const { adapter } = await getWorkspaceContext(params, 'viewer');
    const { id } = await params;

    const deployment = await adapter.getDeployment?.(id);

    if (!deployment) {
      return NextResponse.json(
        { error: 'Deployment not found' },
        { status: 404 }
      );
    }

    return NextResponse.json(deployment);
  } catch (error) {
    if (error instanceof Error && error.message === 'Unauthorized') {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    if (error instanceof Error && (error.message === 'Workspace access denied' || error.message === 'Insufficient workspace permissions')) {
      return NextResponse.json({ error: error.message }, { status: 403 });
    }
    logger.error('[Deployments API] Error getting deployment:', error);
    return NextResponse.json(
      { error: 'Failed to get deployment' },
      { status: 500 }
    );
  }
}

export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ workspaceId: string; id: string }> }
) {
  try {
    const { adapter } = await getWorkspaceContext(params);
    const { id } = await params;
    const body = await request.json();

    const existingDeployment = await adapter.getDeployment?.(id);
    if (!existingDeployment) {
      return NextResponse.json(
        { error: 'Deployment not found' },
        { status: 404 }
      );
    }

    // SECURITY: Use explicit allowlist instead of spreading the entire body
    // to prevent mass assignment attacks (e.g., setting projectId, databaseEnabled, publishedAt)
    const ALLOWED_UPDATE_FIELDS = ['name', 'slug', 'enabled', 'underConstruction', 'customDomain'] as const;

    const updates: Record<string, unknown> = {};
    for (const field of ALLOWED_UPDATE_FIELDS) {
      if (field in body) {
        updates[field] = body[field];
      }
    }

    const updatedDeployment = {
      ...existingDeployment,
      ...updates,
      id, // Ensure ID doesn't change
      updatedAt: new Date(),
    };

    if (adapter.updateDeployment) {
      await adapter.updateDeployment(updatedDeployment);
    }

    return NextResponse.json(updatedDeployment);
  } catch (error) {
    if (error instanceof Error && error.message === 'Unauthorized') {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    if (error instanceof Error && (error.message === 'Workspace access denied' || error.message === 'Insufficient workspace permissions')) {
      return NextResponse.json({ error: error.message }, { status: 403 });
    }
    logger.error('[Deployments API] Error updating deployment:', error);
    return NextResponse.json(
      { error: 'Failed to update deployment' },
      { status: 500 }
    );
  }
}

export async function DELETE(
  _request: NextRequest,
  { params }: { params: Promise<{ workspaceId: string; id: string }> }
) {
  try {
    const { adapter } = await getWorkspaceContext(params);
    const { id } = await params;

    const deployment = await adapter.getDeployment?.(id);
    if (!deployment) {
      return NextResponse.json(
        { error: 'Deployment not found' },
        { status: 404 }
      );
    }

    if (adapter.deleteDeployment) {
      await adapter.deleteDeployment(id);
    }

    // Clean up static files and deployment routing (frees quota)
    await cleanStaticDeployment(id);
    removeDeploymentRoute(id);

    if (deployment.customDomain) {
      regenerateInstanceCaddy().catch(() => {});
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    if (error instanceof Error && error.message === 'Unauthorized') {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    if (error instanceof Error && (error.message === 'Workspace access denied' || error.message === 'Insufficient workspace permissions')) {
      return NextResponse.json({ error: error.message }, { status: 403 });
    }
    logger.error('[Deployments API] Error deleting deployment:', error);
    return NextResponse.json(
      { error: 'Failed to delete deployment' },
      { status: 500 }
    );
  }
}
