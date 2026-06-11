/**
 * Analytics Dashboard API
 * GET /api/analytics/[deploymentId] - Get analytics data for a deployment
 */

import { NextRequest, NextResponse } from 'next/server';
import { getSQLiteAdapter } from '@/lib/vfs/adapters/server';
import { requireDeploymentAccess } from '@/lib/auth/deployment-access';

export interface AnalyticsStats {
  totalPageviews: number;
  uniqueVisitors: number;
  topPages: Array<{ path: string; views: number }>;
  topReferrers: Array<{ referrer: string; views: number }>;
  countries: Array<{ country: string; views: number }>;
  pageviewsOverTime: Array<{ date: string; views: number }>;
}

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ deploymentId: string }> }
) {
  try {
    const { deploymentId } = await params;

    // Auth + workspace access check: verify session has access to the deployment
    const accessResult = await requireDeploymentAccess(deploymentId);
    if (accessResult instanceof NextResponse) return accessResult;

    // Get date range from query params (default: last 30 days)
    const searchParams = request.nextUrl.searchParams;
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

    // Get analytics stats
    const analyticsStats = deploymentDb.getStats(days);
    const topPages = deploymentDb.getTopPages(days, 10);
    const topReferrers = deploymentDb.getTopReferrers(days, 10);
    const pageviewsOverTime = deploymentDb.getPageviewsOverTime(days);

    // Note: Country tracking not implemented yet
    const countries: Array<{ country: string; views: number }> = [];

    const stats: AnalyticsStats = {
      totalPageviews: analyticsStats.totalPageviews,
      uniqueVisitors: analyticsStats.uniqueSessions,
      topPages,
      topReferrers: topReferrers.map(r => ({ referrer: r.referrer, views: r.count })),
      countries,
      pageviewsOverTime: pageviewsOverTime.map(p => ({ date: p.date, views: p.views })),
    };

    return NextResponse.json(stats);
  } catch (error) {
    console.error('[Analytics API] Error fetching analytics:', error);
    return NextResponse.json(
      { error: 'Failed to fetch analytics' },
      { status: 500 }
    );
  }
}
