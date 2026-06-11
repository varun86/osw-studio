/**
 * Tests for Deployment Access Control (IDOR Prevention)
 *
 * Verifies that all analytics sub-routes properly check workspace access
 * before returning deployment analytics data.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NextResponse } from 'next/server';
import {
  requireDeploymentAccess,
  type DeploymentAccessResult,
} from '@/lib/auth/deployment-access';

// Mock dependencies
vi.mock('@/lib/auth/session', () => ({
  getSession: vi.fn(),
}));

vi.mock('@/lib/auth/system-database', () => ({
  getDeploymentWorkspace: vi.fn(),
  getWorkspaceAccess: vi.fn(),
  getUserById: vi.fn(),
}));

import { getSession } from '@/lib/auth/session';
import { getDeploymentWorkspace, getWorkspaceAccess, getUserById } from '@/lib/auth/system-database';

const mockGetSession = vi.mocked(getSession);
const mockGetDeploymentWorkspace = vi.mocked(getDeploymentWorkspace);
const mockGetWorkspaceAccess = vi.mocked(getWorkspaceAccess);
const mockGetUserById = vi.mocked(getUserById);

describe('requireDeploymentAccess', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should return 401 when no session exists', async () => {
    mockGetSession.mockResolvedValue(null);

    const result = await requireDeploymentAccess('deploy-123');

    expect(result).toBeInstanceOf(NextResponse);
    if (result instanceof NextResponse) {
      expect(result.status).toBe(401);
    }
  });

  it('should allow admin user without workspace check', async () => {
    mockGetSession.mockResolvedValue({
      userId: 'admin',
      email: 'admin@localhost',
      isAdmin: true,
      exp: 9999999999,
      jti: 'test-jti',
      iat: 1000000,
    });
    mockGetDeploymentWorkspace.mockReturnValue('ws-123');

    const result = await requireDeploymentAccess('deploy-123');

    expect(result).not.toBeInstanceOf(NextResponse);
    expect((result as DeploymentAccessResult).session.userId).toBe('admin');
    expect((result as DeploymentAccessResult).workspaceId).toBe('ws-123');
    // Should NOT check workspace access for admin
    expect(mockGetWorkspaceAccess).not.toHaveBeenCalled();
  });

  it('should allow desktop user without workspace check', async () => {
    mockGetSession.mockResolvedValue({
      userId: 'desktop',
      email: 'desktop@localhost',
      isAdmin: true,
      exp: 9999999999,
      jti: '__desktop__',
      iat: 1000000,
    });
    mockGetDeploymentWorkspace.mockReturnValue('ws-123');

    const result = await requireDeploymentAccess('deploy-123');

    expect(result).not.toBeInstanceOf(NextResponse);
    expect((result as DeploymentAccessResult).session.userId).toBe('desktop');
    expect(mockGetWorkspaceAccess).not.toHaveBeenCalled();
  });

  it('should allow instance-api user without workspace check', async () => {
    mockGetSession.mockResolvedValue({
      userId: 'instance-api',
      email: 'api@localhost',
      isAdmin: true,
      exp: 9999999999,
      jti: 'test-jti',
      iat: 1000000,
    });
    mockGetDeploymentWorkspace.mockReturnValue('ws-123');

    const result = await requireDeploymentAccess('deploy-123');

    expect(result).not.toBeInstanceOf(NextResponse);
    expect(mockGetWorkspaceAccess).not.toHaveBeenCalled();
  });

  it('should allow user with workspace access', async () => {
    mockGetSession.mockResolvedValue({
      userId: 'user-456',
      email: 'user@example.com',
      isAdmin: false,
      exp: 9999999999,
      jti: 'test-jti',
      iat: 1000000,
    });
    mockGetUserById.mockReturnValue({
      id: 'user-456',
      email: 'user@example.com',
      password_hash: 'hash',
      display_name: 'Test User',
      is_admin: 0,
      active: 1,
      default_workspace_id: null,
      created_at: '2024-01-01',
      updated_at: '2024-01-01',
    });
    mockGetDeploymentWorkspace.mockReturnValue('ws-123');
    mockGetWorkspaceAccess.mockReturnValue({
      user_id: 'user-456',
      workspace_id: 'ws-123',
      role: 'editor',
      created_at: '2024-01-01',
    });

    const result = await requireDeploymentAccess('deploy-123');

    expect(result).not.toBeInstanceOf(NextResponse);
    expect((result as DeploymentAccessResult).session.userId).toBe('user-456');
    expect((result as DeploymentAccessResult).workspaceId).toBe('ws-123');
  });

  it('should allow user with viewer role', async () => {
    mockGetSession.mockResolvedValue({
      userId: 'viewer-789',
      email: 'viewer@example.com',
      isAdmin: false,
      exp: 9999999999,
      jti: 'test-jti',
      iat: 1000000,
    });
    mockGetUserById.mockReturnValue({
      id: 'viewer-789',
      email: 'viewer@example.com',
      password_hash: 'hash',
      display_name: 'Viewer',
      is_admin: 0,
      active: 1,
      default_workspace_id: null,
      created_at: '2024-01-01',
      updated_at: '2024-01-01',
    });
    mockGetDeploymentWorkspace.mockReturnValue('ws-123');
    mockGetWorkspaceAccess.mockReturnValue({
      user_id: 'viewer-789',
      workspace_id: 'ws-123',
      role: 'viewer',
      created_at: '2024-01-01',
    });

    const result = await requireDeploymentAccess('deploy-123');

    expect(result).not.toBeInstanceOf(NextResponse);
    expect((result as DeploymentAccessResult).workspaceId).toBe('ws-123');
  });

  it('should return 404 when user has no workspace access (IDOR prevention)', async () => {
    mockGetSession.mockResolvedValue({
      userId: 'user-456',
      email: 'user@example.com',
      isAdmin: false,
      exp: 9999999999,
      jti: 'test-jti',
      iat: 1000000,
    });
    mockGetUserById.mockReturnValue({
      id: 'user-456',
      email: 'user@example.com',
      password_hash: 'hash',
      display_name: 'Test User',
      is_admin: 0,
      active: 1,
      default_workspace_id: null,
      created_at: '2024-01-01',
      updated_at: '2024-01-01',
    });
    mockGetDeploymentWorkspace.mockReturnValue('ws-other');
    mockGetWorkspaceAccess.mockReturnValue(undefined);

    const result = await requireDeploymentAccess('deploy-123');

    expect(result).toBeInstanceOf(NextResponse);
    if (result instanceof NextResponse) {
      expect(result.status).toBe(404); // 404, not 403, to avoid leaking existence
    }
  });

  it('should return 404 when deployment has no workspace routing', async () => {
    mockGetSession.mockResolvedValue({
      userId: 'user-456',
      email: 'user@example.com',
      isAdmin: false,
      exp: 9999999999,
      jti: 'test-jti',
      iat: 1000000,
    });
    mockGetUserById.mockReturnValue({
      id: 'user-456',
      email: 'user@example.com',
      password_hash: 'hash',
      display_name: 'Test User',
      is_admin: 0,
      active: 1,
      default_workspace_id: null,
      created_at: '2024-01-01',
      updated_at: '2024-01-01',
    });
    mockGetDeploymentWorkspace.mockReturnValue(undefined);

    const result = await requireDeploymentAccess('deploy-123');

    expect(result).toBeInstanceOf(NextResponse);
    if (result instanceof NextResponse) {
      expect(result.status).toBe(404);
    }
  });

  it('should allow DB-verified admin user (is_admin from DB, not just JWT)', async () => {
    mockGetSession.mockResolvedValue({
      userId: 'db-admin',
      email: 'admin@example.com',
      isAdmin: false, // JWT doesn't say admin
      exp: 9999999999,
      jti: 'test-jti',
      iat: 1000000,
    });
    mockGetUserById.mockReturnValue({
      id: 'db-admin',
      email: 'admin@example.com',
      password_hash: 'hash',
      display_name: 'DB Admin',
      is_admin: 1, // But DB says admin
      active: 1,
      default_workspace_id: null,
      created_at: '2024-01-01',
      updated_at: '2024-01-01',
    });
    mockGetDeploymentWorkspace.mockReturnValue('ws-123');

    const result = await requireDeploymentAccess('deploy-123');

    expect(result).not.toBeInstanceOf(NextResponse);
    expect((result as DeploymentAccessResult).session.userId).toBe('db-admin');
    // Should NOT check workspace access for DB-verified admin
    expect(mockGetWorkspaceAccess).not.toHaveBeenCalled();
  });

  it('should deny user who is inactive in DB', async () => {
    // The getSession() itself handles this case (returns null for inactive users)
    // But we test the edge case where the session is somehow valid but the user
    // doesn't exist in DB
    mockGetSession.mockResolvedValue({
      userId: 'ghost-user',
      email: 'ghost@example.com',
      isAdmin: false,
      exp: 9999999999,
      jti: 'test-jti',
      iat: 1000000,
    });
    mockGetUserById.mockReturnValue(undefined); // User doesn't exist in DB
    mockGetDeploymentWorkspace.mockReturnValue('ws-123');
    mockGetWorkspaceAccess.mockReturnValue(undefined);

    const result = await requireDeploymentAccess('deploy-123');

    expect(result).toBeInstanceOf(NextResponse);
    if (result instanceof NextResponse) {
      expect(result.status).toBe(404);
    }
  });
});

describe('Analytics Route IDOR Prevention', () => {
  it('should verify requireDeploymentAccess is used in all analytics sub-routes', async () => {
    // Read the source files and verify they import requireDeploymentAccess
    const fs = await import('fs');
    const path = await import('path');

    const routeFiles = [
      'app/api/analytics/[deploymentId]/route.ts',
      'app/api/analytics/[deploymentId]/engagement/route.ts',
      'app/api/analytics/[deploymentId]/export/route.ts',
      'app/api/analytics/[deploymentId]/heatmap/route.ts',
      'app/api/analytics/[deploymentId]/overview/route.ts',
      'app/api/analytics/[deploymentId]/sessions/route.ts',
      'app/api/analytics/[deploymentId]/storage/route.ts',
      'app/api/analytics/[deploymentId]/clear/route.ts',
    ];

    // Resolve the project root from __dirname (lib/auth/__tests__ -> 3 levels up)
    const projectRoot = path.resolve(__dirname, '../../..');

    for (const file of routeFiles) {
      const filePath = path.join(projectRoot, file);
      const content = fs.readFileSync(filePath, 'utf-8');

      // Each file should import requireDeploymentAccess
      expect(
        content.includes('requireDeploymentAccess'),
        `${file} should import requireDeploymentAccess`
      ).toBe(true);

      // Each file should NOT import getSession directly (anymore)
      // (Except for the shared utility itself)
      expect(
        content.includes("from '@/lib/auth/session'"),
        `${file} should not import from session directly (should use deployment-access)`
      ).toBe(false);

      // Each file should call requireDeploymentAccess
      expect(
        content.includes('await requireDeploymentAccess('),
        `${file} should call requireDeploymentAccess`
      ).toBe(true);

      // Each file should check the result
      expect(
        content.includes('instanceof NextResponse'),
        `${file} should check if result is NextResponse`
      ).toBe(true);
    }
  });
});
