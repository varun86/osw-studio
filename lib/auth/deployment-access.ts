/**
 * Deployment Access Control
 *
 * Shared utility for verifying that an authenticated user has access to
 * a deployment's analytics data. Prevents IDOR (Insecure Direct Object
 * Reference) attacks where any authenticated user could read any
 * deployment's analytics by guessing the deploymentId.
 *
 * The pattern is:
 *   1. Require authentication (401 if not logged in)
 *   2. Look up which workspace owns the deployment
 *   3. Check the user's access to that workspace
 *   4. Return 404 (not 403) to avoid leaking deployment existence
 */

import { NextResponse } from 'next/server';
import { getSession, type SessionData } from './session';
import { getDeploymentWorkspace, getWorkspaceAccess, getUserById } from './system-database';

export interface DeploymentAccessResult {
  session: SessionData;
  workspaceId: string | undefined;
}

/**
 * Require authentication + workspace access for a deployment.
 *
 * Returns `{ session, workspaceId }` on success, or a NextResponse
 * (401 / 404) on failure. Callers should use it like:
 *
 * ```ts
 * const accessResult = requireDeploymentAccess(deploymentId);
 * if (accessResult instanceof NextResponse) return accessResult;
 * const { session } = accessResult;
 * ```
 */
export async function requireDeploymentAccess(
  deploymentId: string
): Promise<DeploymentAccessResult | NextResponse> {
  // 1. Require authentication
  const session = await getSession();
  if (!session) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  // 2. Admin, desktop, and instance-api users bypass workspace checks
  if (session.userId === 'admin' || session.userId === 'desktop' || session.userId === 'instance-api') {
    const workspaceId = getDeploymentWorkspace(deploymentId);
    return { session, workspaceId };
  }

  // 3. Check is_admin from database (not just JWT claim) for authorization decisions
  const user = getUserById(session.userId);
  if (user?.is_admin) {
    const workspaceId = getDeploymentWorkspace(deploymentId);
    return { session, workspaceId };
  }

  // 4. Look up which workspace owns the deployment
  const workspaceId = getDeploymentWorkspace(deploymentId);
  if (workspaceId) {
    const access = getWorkspaceAccess(session.userId, workspaceId);
    if (!access) {
      // Return 404, not 403, to avoid leaking deployment existence
      return NextResponse.json({ error: 'Not found' }, { status: 404 });
    }
  } else {
    // No workspace routing found for this deployment — deny access
    // Deployment may not exist or may not be in the routing table
    return NextResponse.json({ error: 'Not found' }, { status: 404 });
  }

  return { session, workspaceId };
}
