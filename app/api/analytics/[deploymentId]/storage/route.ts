/**
 * Analytics Storage Management API
 * GET /api/analytics/[deploymentId]/storage - Get storage usage breakdown
 */

import { NextRequest, NextResponse } from 'next/server';
import { requireDeploymentAccess } from '@/lib/auth/deployment-access';
import { getSQLiteAdapter } from '@/lib/vfs/adapters/server';

interface StorageBreakdown {
  totalMB: number;
  breakdown: {
    pageviews: {
      count: number;
      sizeMB: number;
    };
    interactions: {
      count: number;
      sizeMB: number;
    };
    sessions: {
      count: number;
      sizeMB: number;
    };
  };
}

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ deploymentId: string }> }
) {
  try {
    const { deploymentId } = await params;

    // Require authentication + workspace access
    const accessResult = await requireDeploymentAccess(deploymentId);
    if (accessResult instanceof NextResponse) return accessResult;

    const adapter = getSQLiteAdapter();
    await adapter.init();

    // Verify deployment exists (from core database)
    const deployment = await adapter.getDeployment(deploymentId);
    if (!deployment) {
      return NextResponse.json(
        { error: 'Deployment not found' },
        { status: 404 }
      );
    }

    // Get deployment database for analytics
    const deploymentDb = adapter.getAnalyticsDatabaseInstance(deploymentId);
    if (!deploymentDb) {
      return NextResponse.json(
        { error: 'Deployment database not enabled' },
        { status: 404 }
      );
    }

    // Get storage info from DeploymentDatabase
    const storageInfo = deploymentDb.getAnalyticsStorageInfo();

    // Rough size estimates (in bytes per row)
    const PAGEVIEW_SIZE = 200; // ~200 bytes per pageview (SQLite is more compact)
    const INTERACTION_SIZE = 150; // ~150 bytes per interaction
    const SESSION_SIZE = 100; // ~100 bytes per session

    const pageviewsSizeMB = (storageInfo.pageviewCount * PAGEVIEW_SIZE) / (1024 * 1024);
    const interactionsSizeMB = (storageInfo.interactionCount * INTERACTION_SIZE) / (1024 * 1024);
    const sessionsSizeMB = (storageInfo.sessionCount * SESSION_SIZE) / (1024 * 1024);

    const totalMB = pageviewsSizeMB + interactionsSizeMB + sessionsSizeMB;

    const storage: StorageBreakdown = {
      totalMB: parseFloat(totalMB.toFixed(2)),
      breakdown: {
        pageviews: {
          count: storageInfo.pageviewCount,
          sizeMB: parseFloat(pageviewsSizeMB.toFixed(2)),
        },
        interactions: {
          count: storageInfo.interactionCount,
          sizeMB: parseFloat(interactionsSizeMB.toFixed(2)),
        },
        sessions: {
          count: storageInfo.sessionCount,
          sizeMB: parseFloat(sessionsSizeMB.toFixed(2)),
        },
      },
    };

    return NextResponse.json(storage);
  } catch (error) {
    console.error('[Analytics Storage API] Error:', error);
    return NextResponse.json(
      { error: 'Failed to get storage usage' },
      { status: 500 }
    );
  }
}
