/**
 * Analytics Overview API
 * GET /api/analytics/[deploymentId]/overview - Fetch overview analytics
 *
 * Query parameters:
 * - days: Number of days to look back (default: 30)
 */

import { NextRequest, NextResponse } from 'next/server';
import { requireDeploymentAccess } from '@/lib/auth/deployment-access';
import { getSQLiteAdapter } from '@/lib/vfs/adapters/server';

interface AnalyticsOverview {
  totalPageviews: number;
  uniqueVisitors: number;
  averageTimeOnSite: number;
  bounceRate: number;
  topPages: Array<{ page: string; views: number }>;
  topReferrers: Array<{ referrer: string; count: number }>;
  deviceBreakdown: Record<string, number>;
  countryBreakdown: Record<string, number>;
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

    // Get overview stats from DeploymentDatabase
    const overviewStats = deploymentDb.getOverviewStats(days);
    const basicStats = deploymentDb.getStats(days);

    // Build response
    const overview: AnalyticsOverview = {
      totalPageviews: overviewStats.totalPageviews,
      uniqueVisitors: overviewStats.uniqueSessions,
      averageTimeOnSite: overviewStats.avgSessionDuration,
      bounceRate: overviewStats.bounceRate / 100, // Convert from percentage
      topPages: basicStats.topPages.map((p) => ({
        page: p.path,
        views: p.views,
      })),
      topReferrers: basicStats.topReferrers,
      deviceBreakdown: overviewStats.deviceBreakdown.reduce((acc, item) => {
        acc[item.device] = item.count;
        return acc;
      }, {} as Record<string, number>),
      countryBreakdown: {}, // Country tracking not implemented yet
    };

    return NextResponse.json(overview);
  } catch (error) {
    console.error('[Analytics Overview API] Error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch analytics overview' },
      { status: 500 }
    );
  }
}
