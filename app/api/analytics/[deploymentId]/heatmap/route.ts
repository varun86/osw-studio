/**
 * Analytics Heatmap Data API
 * GET /api/analytics/[deploymentId]/heatmap - Fetch heatmap data for visualization
 *
 * Query parameters:
 * - page: Page path to get heatmap for (required)
 * - type: 'click' | 'scroll' (default: click)
 * - dateFrom: ISO date string (optional)
 * - dateTo: ISO date string (optional)
 */

import { NextRequest, NextResponse } from 'next/server';
import { requireDeploymentAccess } from '@/lib/auth/deployment-access';
import { getSQLiteAdapter } from '@/lib/vfs/adapters/server';

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
    const page = searchParams.get('page');
    const type = searchParams.get('type') || 'click';
    const device = searchParams.get('device'); // mobile, tablet, desktop, or null for all
    const dateFrom = searchParams.get('dateFrom');
    const dateTo = searchParams.get('dateTo');

    if (!page) {
      return NextResponse.json(
        { error: 'Missing required parameter: page' },
        { status: 400 }
      );
    }

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

    // Process and return heatmap data based on type
    if (type === 'click') {
      // Get click data from DeploymentDatabase
      const clickData = deploymentDb.getClickData(
        page,
        dateFrom || undefined,
        dateTo || undefined
      );

      // Parse coordinates and filter by device
      let points = clickData
        .map((row) => {
          try {
            const coords = typeof row.coordinates === 'string'
              ? JSON.parse(row.coordinates)
              : row.coordinates;
            return {
              x: coords.x,
              y: coords.y,
              scrollY: coords.scrollY || 0,
              viewportWidth: coords.viewportWidth,
              viewportHeight: coords.viewportHeight,
              documentHeight: coords.documentHeight,
              elementSelector: row.elementSelector,
              timestamp: row.timestamp,
            };
          } catch {
            return null;
          }
        })
        .filter((p): p is NonNullable<typeof p> => p !== null);

      // Filter by device type based on viewport width
      if (device && device !== 'all') {
        points = points.filter((point) => {
          const width = point.viewportWidth;
          if (device === 'mobile') return width < 768;
          if (device === 'tablet') return width >= 768 && width < 1024;
          if (device === 'desktop') return width >= 1024;
          return true;
        });
      }

      return NextResponse.json({
        type: 'click',
        page,
        sampleSize: points.length,
        points,
      });
    } else if (type === 'scroll') {
      // Get scroll data from DeploymentDatabase
      const scrollData = deploymentDb.getScrollData(
        page,
        dateFrom || undefined,
        dateTo || undefined
      );

      // Aggregate scroll depth data
      const depthCounts = scrollData.reduce((acc, row) => {
        const depth = row.scrollDepth;
        acc[depth] = (acc[depth] || 0) + 1;
        return acc;
      }, {} as Record<number, number>);

      return NextResponse.json({
        type: 'scroll',
        page,
        sampleSize: scrollData.length,
        depthDistribution: depthCounts,
        rawData: scrollData,
      });
    }

    return NextResponse.json({ error: 'Invalid type' }, { status: 400 });
  } catch (error) {
    console.error('[Analytics Heatmap API] Error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch heatmap data' },
      { status: 500 }
    );
  }
}
