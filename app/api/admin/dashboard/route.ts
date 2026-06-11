/**
 * Admin Dashboard API
 *
 * GET /api/admin/dashboard - Get all dashboard statistics in a single call
 *
 * Returns system info, content counts, hosting stats, and traffic metrics.
 * Protected by admin authentication.
 */

import { NextResponse } from 'next/server';
import { requireAdmin, verifyInstanceApiKey } from '@/lib/auth/session';
import { getCoreDatabase } from '@/lib/vfs/adapters/sqlite-connection';
import { getRequestStats, cleanupOldLogs } from '@/lib/logging/request-logger';
import { getSystemDatabase } from '@/lib/auth/system-database';
import { adminRateLimiter, RATE_LIMIT_CONFIG, getIdentifier } from '@/lib/analytics/rate-limiter';
import { promises as fs } from 'fs';
import path from 'path';

// Read version from package.json
async function getVersion(): Promise<string> {
  try {
    const packagePath = path.join(process.cwd(), 'package.json');
    const content = await fs.readFile(packagePath, 'utf-8');
    const pkg = JSON.parse(content);
    return pkg.version || 'unknown';
  } catch {
    return 'unknown';
  }
}

// Parse What's New from docs/WHATS_NEW.md
interface WhatsNewData {
  version: string;
  title: string;
  highlights: string[];
}

async function getWhatsNew(): Promise<WhatsNewData> {
  const defaultData: WhatsNewData = {
    version: 'unknown',
    title: 'Welcome to OSW Studio',
    highlights: [],
  };

  try {
    const whatsNewPath = path.join(process.cwd(), 'docs', 'WHATS_NEW.md');
    const content = await fs.readFile(whatsNewPath, 'utf-8');

    // Find first version heading: ## v{version} - {title}
    const versionMatch = content.match(/^## v(\d+\.\d+\.\d+)\s*-\s*(.+)$/m);
    if (!versionMatch) {
      return defaultData;
    }

    const version = versionMatch[1];
    const title = versionMatch[2].trim();

    // Get content after the version heading until the next ## or ---
    const versionIndex = content.indexOf(versionMatch[0]);
    const afterVersion = content.substring(versionIndex + versionMatch[0].length);
    const nextSectionMatch = afterVersion.match(/^(?:## |---)/m);
    const sectionContent = nextSectionMatch
      ? afterVersion.substring(0, nextSectionMatch.index)
      : afterVersion;

    // Extract bullet points (lines starting with - or *)
    const bulletRegex = /^[-*]\s+\*\*(.+?)\*\*\s*[-–]?\s*(.*)$/gm;
    const highlights: string[] = [];
    let match;

    while ((match = bulletRegex.exec(sectionContent)) !== null && highlights.length < 4) {
      // Combine bold title with description if present
      const boldTitle = match[1].trim();
      const description = match[2]?.trim();
      highlights.push(description ? `${boldTitle} - ${description}` : boldTitle);
    }

    // If no bold bullet points found, try regular bullets
    if (highlights.length === 0) {
      const simpleBulletRegex = /^[-*]\s+(.+)$/gm;
      while ((match = simpleBulletRegex.exec(sectionContent)) !== null && highlights.length < 4) {
        const text = match[1].trim();
        // Skip if it's a link-only line
        if (!text.match(/^\[.*\]\(.*\)$/)) {
          highlights.push(text.replace(/\*\*/g, ''));
        }
      }
    }

    return { version, title, highlights };
  } catch {
    return defaultData;
  }
}

// Calculate directory size recursively
async function getDirectorySize(dirPath: string): Promise<number> {
  let totalSize = 0;

  try {
    const entries = await fs.readdir(dirPath, { withFileTypes: true });

    for (const entry of entries) {
      const entryPath = path.join(dirPath, entry.name);

      if (entry.isDirectory()) {
        totalSize += await getDirectorySize(entryPath);
      } else if (entry.isFile()) {
        const stat = await fs.stat(entryPath);
        totalSize += stat.size;
      }
    }
  } catch {
    // Directory doesn't exist or not accessible
  }

  return totalSize;
}

// Count SQLite files in deployments directory (deployment databases)
async function countDeploymentDatabases(): Promise<number> {
  const deploymentsDir = path.join(process.cwd(), 'deployments');
  let count = 0;

  try {
    const entries = await fs.readdir(deploymentsDir, { withFileTypes: true });

    for (const entry of entries) {
      if (entry.isDirectory()) {
        const dbPath = path.join(deploymentsDir, entry.name, 'runtime.sqlite');
        try {
          await fs.access(dbPath);
          count++;
        } catch {
          // No database for this deployment
        }
      }
    }
  } catch {
    // Deployments directory doesn't exist
  }

  return count;
}

export async function GET(request: Request) {
  try {
    // Rate limiting — 60 requests per minute per user
    const identifier = getIdentifier(request);
    if (!adminRateLimiter.check(identifier, RATE_LIMIT_CONFIG.admin)) {
      const retryAfter = adminRateLimiter.getResetTime(identifier, RATE_LIMIT_CONFIG.admin);
      return NextResponse.json(
        { error: 'Too many requests' },
        { status: 429, headers: { 'Retry-After': String(retryAfter) } }
      );
    }

    // Verify admin authentication (database-verified, not just JWT claim)
    let session;
    try {
      const apiSession = verifyInstanceApiKey(request as any);
      session = apiSession || await requireAdmin();
    } catch {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Get database connection
    const db = getCoreDatabase();

    // Clean up old logs (7 days retention)
    cleanupOldLogs(7);

    // Gather all statistics in parallel where possible
    const [
      version,
      projectCount,
      templateCount,
      skillCount,
      fileCount,
      publishedSiteCount,
      deploymentsWithDb,
      storageSize,
      trafficStats,
      whatsNew,
    ] = await Promise.all([
      getVersion(),
      Promise.resolve((db.prepare('SELECT COUNT(*) as count FROM projects').get() as { count: number }).count),
      Promise.resolve((db.prepare('SELECT COUNT(*) as count FROM custom_templates').get() as { count: number }).count),
      Promise.resolve((db.prepare('SELECT COUNT(*) as count FROM skills').get() as { count: number }).count),
      Promise.resolve((db.prepare('SELECT COUNT(*) as count FROM files').get() as { count: number }).count),
      Promise.resolve((db.prepare('SELECT COUNT(*) as count FROM deployments WHERE published_at IS NOT NULL').get() as { count: number }).count),
      countDeploymentDatabases(),
      getDirectorySize(path.join(process.cwd(), 'public', 'deployments')),
      Promise.resolve(getRequestStats(24)),
      getWhatsNew(),
    ]);

    // Get deployment names for top deployments
    const topDeploymentsWithNames = trafficStats.topDeployments.map((deployment) => {
      const deploymentInfo = db.prepare('SELECT name FROM deployments WHERE id = ?').get(deployment.deploymentId) as { name: string } | undefined;
      return {
        ...deployment,
        deploymentName: deploymentInfo?.name || deployment.deploymentId.substring(0, 8),
      };
    });

    // Get recent projects (last 5 by updated_at)
    const recentProjects = db.prepare(`
      SELECT id, name, description, updated_at as updatedAt
      FROM projects
      ORDER BY updated_at DESC
      LIMIT 5
    `).all() as Array<{ id: string; name: string; description: string | null; updatedAt: string }>;

    // Get recent deployments (last 5 by updated_at)
    const recentDeployments = db.prepare(`
      SELECT id, name, slug, enabled, published_at as publishedAt, updated_at as updatedAt
      FROM deployments
      ORDER BY updated_at DESC
      LIMIT 5
    `).all() as Array<{ id: string; name: string; slug: string; enabled: number; publishedAt: string | null; updatedAt: string }>;

    // System info
    const memoryUsage = process.memoryUsage();

    // Multi-tenant stats from system database
    let userStats = { totalUsers: 0, activeUsers: 0, totalDeploymentRoutes: 0 };
    try {
      const sysDb = getSystemDatabase();
      const total = sysDb.prepare('SELECT COUNT(*) as count FROM users').get() as { count: number };
      const active = sysDb.prepare('SELECT COUNT(*) as count FROM users WHERE active = 1').get() as { count: number };
      const routes = sysDb.prepare('SELECT COUNT(*) as count FROM deployment_routing').get() as { count: number };
      userStats = { totalUsers: total.count, activeUsers: active.count, totalDeploymentRoutes: routes.count };
    } catch {
      // System database may not exist in browser mode or single-user setups
    }

    return NextResponse.json({
      system: {
        version,
        instanceId: process.env.INSTANCE_ID || null,
        nodeVersion: process.version,
        uptime: process.uptime(),
        memoryUsed: memoryUsage.heapUsed,
        memoryTotal: memoryUsage.heapTotal,
      },
      users: userStats,
      content: {
        projects: projectCount,
        templates: templateCount,
        skills: skillCount,
        totalFiles: fileCount,
      },
      hosting: {
        publishedDeployments: publishedSiteCount,
        deploymentsWithDb,
        storageUsed: storageSize,
      },
      traffic: {
        requestsLastHour: trafficStats.requestsLastHour,
        requestsLastDay: trafficStats.requestsLastDay,
        errorCount: trafficStats.errorCount,
        topDeployments: topDeploymentsWithNames,
        recentErrors: trafficStats.recentErrors,
      },
      whatsNew,
      recentProjects,
      recentDeployments: recentDeployments.map(deployment => ({
        ...deployment,
        enabled: Boolean(deployment.enabled),
      })),
    });

  } catch (error) {
    console.error('[Dashboard API] Error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch dashboard data' },
      { status: 500 }
    );
  }
}
