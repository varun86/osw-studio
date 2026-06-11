/**
 * Analytics Engagement Metrics API
 * GET /api/analytics/[deploymentId]/engagement - Fetch engagement metrics
 *
 * Query parameters:
 * - days: Number of days to look back (default: 30)
 */

import { NextRequest, NextResponse } from 'next/server';
import { requireDeploymentAccess } from '@/lib/auth/deployment-access';
import { getSQLiteAdapter } from '@/lib/vfs/adapters/server';

interface EngagementMetrics {
  timeOnPage: {
    average: number;
    median: number;
    distribution: Record<string, number>; // page -> avg time
  };
  scrollDepth: {
    average: number;
    milestones: Record<number, number>; // milestone -> count
  };
  exitPages: Array<{
    page: string;
    exitCount: number;
    exitRate: number;
  }>;
  topLandingPages: Array<{
    page: string;
    visitCount: number;
    bounceRate: number;
  }>;
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

    const { searchParams } = new URL(request.url);
    const days = parseInt(searchParams.get('days') || '30', 10);

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

    // Get engagement metrics from DeploymentDatabase
    const engagementData = deploymentDb.getEngagementMetrics(days);

    // Build engagement metrics response
    // Note: SQLite doesn't have PERCENTILE_CONT, so we approximate median with average
    const metrics: EngagementMetrics = {
      timeOnPage: {
        average: engagementData.avgTimeOnPage,
        median: engagementData.avgTimeOnPage, // Approximation
        distribution: {}, // Would need additional query for per-page breakdown
      },
      scrollDepth: {
        average: engagementData.avgScrollDepth,
        milestones: engagementData.scrollDepthDistribution,
      },
      exitPages: engagementData.exitPageCounts.map((item, index, array) => {
        const totalExits = array.reduce((sum, e) => sum + e.count, 0);
        return {
          page: item.page,
          exitCount: item.count,
          exitRate: totalExits > 0 ? item.count / totalExits : 0,
        };
      }),
      topLandingPages: [], // Would need additional query for landing pages with bounce rate
    };

    return NextResponse.json(metrics);
  } catch (error) {
    console.error('[Analytics Engagement API] Error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch engagement metrics' },
      { status: 500 }
    );
  }
}
