/**
 * Static Deployment Builder
 *
 * Compiles projects from SQLite using VirtualServer (Handlebars rendering)
 * and writes compiled static files to public directory
 */

import { promises as fs } from 'fs';
import path from 'path';
import { createServerAdapter, getWorkspaceAdapter } from '@/lib/vfs/adapters/server';
import { VirtualServer } from '@/lib/preview/virtual-server';
import { VirtualFile, FileTreeNode, Deployment } from '@/lib/vfs/types';
import { logger } from '@/lib/utils';
import { processHtml } from '@/lib/publishing/html-processor';
import { generateSitemap, generateRobotsTxt } from '@/lib/publishing/seo-generator';
import { extractBackendFeatures } from './backend-feature-extractor';
import { sanitizeFilePath, isPathSafe } from '@/lib/security/path-safety';

export interface BuildResult {
  success: boolean;
  deploymentId: string;
  projectId: string;
  filesWritten: number;
  outputPath: string;
  error?: string;
}

/**
 * Create a minimal VFS-like wrapper for server-side VirtualServer compilation
 * Only implements the methods that VirtualServer actually uses
 */
function createServerVfs(
  projectId: string,
  allFiles: VirtualFile[]
) {
  const generatedFiles = new Map<string, VirtualFile>();

  return {
    async getAllFilesAndDirectories(pid: string): Promise<VirtualFile[]> {
      if (pid !== projectId) throw new Error('Invalid project ID');
      return allFiles;
    },

    async listDirectory(pid: string, dirPath: string): Promise<VirtualFile[]> {
      if (pid !== projectId) throw new Error('Invalid project ID');
      if (dirPath === '/') return allFiles;
      return allFiles.filter(f => f.path.startsWith(dirPath));
    },

    async readFile(pid: string, filePath: string): Promise<VirtualFile> {
      if (pid !== projectId) throw new Error('Invalid project ID');
      const file = allFiles.find(f => f.path === filePath);
      if (!file) throw new Error(`File not found: ${filePath}`);
      return file;
    },

    async fileExists(pid: string, filePath: string): Promise<boolean> {
      if (pid !== projectId) throw new Error('Invalid project ID');
      return allFiles.some(f => f.path === filePath);
    },

    // Generated file methods used by VirtualServer during bundled runtime compilation
    clearGeneratedFiles(): void {
      generatedFiles.clear();
    },

    setGeneratedFile(path: string, content: string, mimeType: string): void {
      const now = new Date();
      generatedFiles.set(path, {
        id: `generated-${path}`,
        projectId,
        path,
        name: path.split('/').pop() || path,
        type: path.endsWith('.css') ? 'css' : 'js',
        content,
        mimeType,
        size: content.length,
        createdAt: now,
        updatedAt: now,
        metadata: { isGenerated: true },
      });
    },

    getGeneratedFiles(): VirtualFile[] {
      return Array.from(generatedFiles.values());
    },

    isGeneratedPath(path: string): boolean {
      return generatedFiles.has(path);
    },
  };
}

/**
 * Build a static deployment from a deployment entity
 * Uses VirtualServer to compile Handlebars templates (same as export)
 */
/**
 * Validate that a deployment ID is safe for use in filesystem paths.
 * Deployment IDs should be alphanumeric with hyphens only.
 * Rejects path traversal patterns and special characters.
 */
function validateDeploymentId(deploymentId: string): void {
  if (!deploymentId || typeof deploymentId !== 'string') {
    throw new Error('Invalid deployment ID: must be a non-empty string');
  }
  // Only allow alphanumeric, hyphens, and underscores — no path separators or traversal
  if (!/^[a-zA-Z0-9_-]+$/.test(deploymentId)) {
    throw new Error(
      `Invalid deployment ID: "${deploymentId}" contains disallowed characters. ` +
      'Only alphanumeric characters, hyphens, and underscores are permitted.'
    );
  }
}

export async function buildStaticDeployment(deploymentId: string, workspaceId?: string): Promise<BuildResult> {
  try {
    // Validate deployment ID before using it in any filesystem paths
    validateDeploymentId(deploymentId);

    const adapter = workspaceId ? getWorkspaceAdapter(workspaceId) : await createServerAdapter();
    await adapter.init();

    // Get deployment
    const deployment = await adapter.getDeployment?.(deploymentId);
    if (!deployment) {
      logger.error(`[Static Builder] Deployment ${deploymentId} not found in database`);
      return {
        success: false,
        deploymentId,
        projectId: '',
        filesWritten: 0,
        outputPath: '',
        error: 'Deployment not found',
      };
    }

    // Get project
    const project = await adapter.getProject(deployment.projectId);
    if (!project) {
      logger.error(`[Static Builder] Project ${deployment.projectId} not found in database`);
      return {
        success: false,
        deploymentId,
        projectId: deployment.projectId,
        filesWritten: 0,
        outputPath: '',
        error: 'Project not found',
      };
    }

    // Check if under construction - if so, replace entire deployment with construction page
    if (deployment.underConstruction) {
      // Output directory: public/deployments/[deploymentId]
      const outputDir = path.join(process.cwd(), 'public', 'deployments', deploymentId);

      // Clean existing output directory
      try {
        await fs.rm(outputDir, { recursive: true, force: true });
      } catch (error) {
        // Directory doesn't exist, that's fine
      }

      // Create output directory
      await fs.mkdir(outputDir, { recursive: true });

      // Generate and write under construction page as index.html
      const constructionHtml = generateUnderConstructionHtml(deployment.name);
      await fs.writeFile(path.join(outputDir, 'index.html'), constructionHtml, 'utf-8');

      logger.info(`[Static Builder] Built under construction page for deployment ${deploymentId}`);

      return {
        success: true,
        deploymentId,
        projectId: deployment.projectId,
        filesWritten: 1,
        outputPath: `/deployments/${deploymentId}`,
      };
    }

    // Get all files from SQLite
    const allFiles = await adapter.listFiles(deployment.projectId);

    // Create a minimal VFS-like wrapper for server-side compilation
    const serverVfs = createServerVfs(deployment.projectId, allFiles);

    // Check if project has edge functions (for conditional interceptor injection)
    const edgeFunctions = adapter.listEdgeFunctions
      ? await adapter.listEdgeFunctions(deployment.projectId)
      : [];
    const hasEdgeFunctions = edgeFunctions.some(f => f.enabled);

    // Compile project using VirtualServer (renders Handlebars templates)
    const server = new VirtualServer(serverVfs as any, deployment.projectId, { runtime: project.settings?.runtime });
    const compiledProject = await server.compileProject();

    // Create reverse map: blobUrl -> filePath for replacements
    const blobUrlToPath = new Map<string, string>();
    for (const [filePath, blobUrl] of compiledProject.blobUrls) {
      blobUrlToPath.set(blobUrl, filePath);
    }

    // Determine base URL for published deployment
    const appUrl = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000';
    const instanceDomain = appUrl.replace(/^https?:\/\//, '');
    const baseUrl = deployment.customDomain
      ? `https://${deployment.customDomain}`
      : deployment.slug
      ? `https://${deployment.slug}.${instanceDomain}`
      : `${appUrl}/deployments/${deploymentId}`;

    // Post-process files to replace asset references with absolute paths
    // and apply deployment settings (scripts, CDN, SEO, etc.)
    const htmlFiles: string[] = [];
    for (const file of compiledProject.files) {
      if (typeof file.content === 'string') {
        // Replace both blob URLs and file path references with absolute paths
        const servedAtRoot = !!(deployment.customDomain || deployment.slug);
        file.content = replaceAssetPathsWithDeploymentPrefix(
          file.content,
          blobUrlToPath,
          allFiles,
          deploymentId,
          servedAtRoot
        );

        // Remove VFS interceptor script from HTML files
        if (file.path.endsWith('.html')) {
          file.content = removePreviewScripts(file.content);
          htmlFiles.push(file.path);

          // Apply deployment settings to HTML files
          file.content = processHtml(file.content, {
            publishSettings: {
              enabled: deployment.enabled,
              underConstruction: deployment.underConstruction,
              customDomain: deployment.customDomain,
              headScripts: deployment.headScripts,
              bodyScripts: deployment.bodyScripts,
              cdnLinks: deployment.cdnLinks,
              analytics: deployment.analytics,
              seo: deployment.seo,
              compliance: deployment.compliance,
              settingsVersion: deployment.settingsVersion,
              lastPublishedVersion: deployment.lastPublishedVersion,
            },
            projectId: deployment.projectId,
            baseUrl,
            deploymentId,
            hasEdgeFunctions,
          });
        }
      }
    }

    // Output directory: public/deployments/[deploymentId]
    const outputDir = path.join(process.cwd(), 'public', 'deployments', deploymentId);

    // Clean existing output directory
    try {
      await fs.rm(outputDir, { recursive: true, force: true });
    } catch (error) {
      // Directory doesn't exist (first build), that's fine
    }

    // Create output directory
    await fs.mkdir(outputDir, { recursive: true });

    let filesWritten = 0;

    // Write compiled files
    for (const file of compiledProject.files) {
      // Skip template files and development files (same as export)
      if (shouldExcludeFromExport(file.path)) {
        continue;
      }

      // Defense-in-depth: reject paths containing traversal patterns early,
      // before any path resolution. This catches obvious attacks like
      // /../../../tmp/evil before we even attempt to resolve the path.
      if (!isPathSafe(file.path)) {
        logger.warn(`[Static Builder] Skipping file with unsafe path: "${file.path}"`);
        continue;
      }

      // Determine file path — sanitize against path traversal attacks
      // An attacker could set file.path to "../../etc/malicious" to write
      // outside the deployment directory. sanitizeFilePath() prevents this
      // even if isPathSafe() is bypassed (e.g., via symlinks or encoding tricks).
      const filePath = sanitizeFilePath(file.path, outputDir);

      // Create directory if needed
      const fileDir = path.dirname(filePath);
      await fs.mkdir(fileDir, { recursive: true });

      // Write file content
      if (typeof file.content === 'string') {
        await fs.writeFile(filePath, file.content, 'utf-8');
      } else {
        // Binary content (ArrayBuffer)
        await fs.writeFile(filePath, Buffer.from(file.content));
      }

      filesWritten++;
    }

    // Generate and write sitemap.xml if htmlFiles exist
    if (htmlFiles.length > 0) {
      const sitemapContent = generateSitemap({
        baseUrl,
        htmlFiles,
        publishSettings: {
          enabled: deployment.enabled,
          underConstruction: deployment.underConstruction,
          customDomain: deployment.customDomain,
          headScripts: deployment.headScripts,
          bodyScripts: deployment.bodyScripts,
          cdnLinks: deployment.cdnLinks,
          analytics: deployment.analytics,
          seo: deployment.seo,
          compliance: deployment.compliance,
          settingsVersion: deployment.settingsVersion,
          lastPublishedVersion: deployment.lastPublishedVersion,
        },
      });
      await fs.writeFile(path.join(outputDir, 'sitemap.xml'), sitemapContent, 'utf-8');
      filesWritten++;
    }

    // Generate and write robots.txt
    const robotsContent = generateRobotsTxt({
      baseUrl,
      publishSettings: {
        enabled: deployment.enabled,
        underConstruction: deployment.underConstruction,
        customDomain: deployment.customDomain,
        headScripts: deployment.headScripts,
        bodyScripts: deployment.bodyScripts,
        cdnLinks: deployment.cdnLinks,
        analytics: deployment.analytics,
        seo: deployment.seo,
        compliance: deployment.compliance,
        settingsVersion: deployment.settingsVersion,
        lastPublishedVersion: deployment.lastPublishedVersion,
      },
    });
    await fs.writeFile(path.join(outputDir, 'robots.txt'), robotsContent, 'utf-8');
    filesWritten++;

    // Extract backend features from project → deployment runtime database
    const extractionResult = await extractBackendFeatures(deployment.projectId, deploymentId, workspaceId);
    if (extractionResult.errors.length > 0) {
      logger.warn('[Static Builder] Backend feature extraction warnings:', extractionResult.errors);
    }
    if (extractionResult.edgeFunctions > 0 || extractionResult.serverFunctions > 0 ||
        extractionResult.secrets > 0 || extractionResult.scheduledFunctions > 0) {
      logger.info(`[Static Builder] Backend features provisioned: ${extractionResult.edgeFunctions} edge functions, ${extractionResult.serverFunctions} server functions, ${extractionResult.secrets} secrets, ${extractionResult.scheduledFunctions} scheduled functions`);
    }

    // Update lastPublishedVersion after successful build
    if (adapter.updateDeployment) {
      await adapter.updateDeployment({
        ...deployment,
        lastPublishedVersion: deployment.settingsVersion,
        publishedAt: new Date(),
      });
    }

    // Clean up VirtualServer resources
    server.cleanupBlobUrls();

    logger.info(`[Static Builder] Build complete: ${filesWritten} files written to /deployments/${deploymentId}`);

    return {
      success: true,
      deploymentId,
      projectId: deployment.projectId,
      filesWritten,
      outputPath: `/deployments/${deploymentId}`,
    };
  } catch (error) {
    logger.error('[Static Builder] Build failed:', error);
    return {
      success: false,
      deploymentId: deploymentId || '',
      projectId: '',
      filesWritten: 0,
      outputPath: '',
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

/**
 * Clean up static files for a deployment
 */
export async function cleanStaticDeployment(deploymentId: string): Promise<boolean> {
  try {
    // Validate deployment ID before using it in filesystem paths
    validateDeploymentId(deploymentId);

    const outputDir = path.join(process.cwd(), 'public', 'deployments', deploymentId);
    await fs.rm(outputDir, { recursive: true, force: true });
    return true;
  } catch (error) {
    logger.error('[Static Builder] Error cleaning deployment:', error);
    return false;
  }
}

/**
 * Check if a file should be excluded from published deployment output
 */
function shouldExcludeFromExport(filePath: string): boolean {
  // Exclude template files
  if (filePath.endsWith('.hbs') || filePath.endsWith('.handlebars')) {
    return true;
  }

  // Exclude templates directory
  if (filePath.startsWith('/templates/')) {
    return true;
  }

  // Exclude data.json file (since it's compiled into HTML)
  if (filePath === '/data.json') {
    return true;
  }

  // Exclude TypeScript/JSX/SFC source files (compiled into bundle.js)
  if (filePath.endsWith('.ts') || filePath.endsWith('.tsx') || filePath.endsWith('.jsx') ||
      filePath.endsWith('.svelte') || filePath.endsWith('.vue')) {
    return true;
  }

  // Exclude CSS source files under src/ (compiled into bundle.css by esbuild)
  if (filePath.startsWith('/src/') && filePath.endsWith('.css')) {
    return true;
  }

  // Exclude dot-prefixed files and directories (e.g. .PROMPT.md, .DESIGN.md, .skills/)
  const firstSegment = filePath.split('/').filter(Boolean)[0];
  if (firstSegment && firstSegment.startsWith('.')) {
    return true;
  }

  return false;
}

/**
 * Replace both blob URLs and file path references with deployment-prefixed absolute paths
 */
function replaceAssetPathsWithDeploymentPrefix(
  content: string,
  blobUrlToPath: Map<string, string>,
  allFiles: VirtualFile[],
  deploymentId: string,
  servedAtRoot?: boolean
): string {
  let result = content;

  // If served at domain root (custom domain or subdomain slug), use root-relative paths.
  // Otherwise use deployment-prefixed paths for direct /deployments/{id}/ access.
  const pathPrefix = servedAtRoot ? '' : `/deployments/${deploymentId}`;

  // First, replace all blob URLs with appropriate paths
  for (const [blobUrl, filePath] of blobUrlToPath) {
    const absolutePath = `${pathPrefix}${filePath}`;
    result = result.replace(new RegExp(escapeRegex(blobUrl), 'g'), absolutePath);
  }

  // Helper to check if path is already prefixed with deployment path
  const isAlreadyPrefixed = (path: string) =>
    pathPrefix && path.startsWith(pathPrefix);

  // Rewrite all internal absolute paths for HTML files
  // Pattern matches: href="/anything.html" or href="/anything.htm"
  result = result.replace(
    /href=(["'])(\/[^"']*\.html?)\1/g,
    (match, quote, filePath) => {
      if (isAlreadyPrefixed(filePath)) {
        return match;
      }
      return `href=${quote}${pathPrefix}${filePath}${quote}`;
    }
  );

  // Rewrite asset directory paths (styles, scripts, assets, images, fonts, js, css)
  const assetDirPattern = /(?:href|src)=(["'])(\/(?:styles|scripts|assets|images|fonts|js|css)\/[^"']+)\1/g;
  result = result.replace(assetDirPattern, (match, quote, filePath) => {
    if (isAlreadyPrefixed(filePath)) {
      return match;
    }
    return match.replace(filePath, `${pathPrefix}${filePath}`);
  });

  // Rewrite root-level asset references (e.g., /bundle.js, /bundle.css, /favicon.ico)
  const rootAssetPattern = /(?:href|src)=(["'])(\/[^"'\/]+\.(?:js|css|json|xml|ico|png|jpg|jpeg|gif|svg|webp|woff|woff2|ttf|eot))\1/g;
  result = result.replace(rootAssetPattern, (match, quote, filePath) => {
    if (isAlreadyPrefixed(filePath)) {
      return match;
    }
    return match.replace(filePath, `${pathPrefix}${filePath}`);
  });

  // Rewrite CSS url() references for asset directories
  result = result.replace(
    /url\(['"]?(\/(?:styles|scripts|assets|images|fonts|js|css)\/[^'")]+)['"]?\)/g,
    (match, filePath) => {
      if (isAlreadyPrefixed(filePath)) {
        return match;
      }
      return match.replace(filePath, `${pathPrefix}${filePath}`);
    }
  );

  // Handle relative HTML paths (e.g., href="about.html") - convert to absolute with prefix
  result = result.replace(
    /href=(["'])([^"':/][^"']*\.html?)\1/g,
    (match, quote, filePath) => {
      // Skip if it looks like an already-processed path or external
      if (filePath.startsWith('/') || filePath.includes('://')) {
        return match;
      }
      return `href=${quote}${pathPrefix}/${filePath}${quote}`;
    }
  );

  // Handle root path href="/" - rewrite to deployment prefix
  if (pathPrefix) {
    result = result.replace(
      /href=(["'])\/\1/g,
      (match, quote) => `href=${quote}${pathPrefix}/${quote}`
    );
  }

  return result;
}

/**
 * Remove live-preview-only scripts from HTML
 */
function removePreviewScripts(html: string): string {
  // Remove the VFS Asset Interceptor script tag
  const vfsRegex = /<script>\s*\/\/ VFS Asset Interceptor[\s\S]*?<\/script>\s*/;
  html = html.replace(vfsRegex, '');

  // Remove the Console Capture script tag (only used inside preview iframe)
  const consoleRegex = /<script>\s*\/\/ Console Capture[\s\S]*?<\/script>\s*/;
  html = html.replace(consoleRegex, '');

  return html;
}

/**
 * Escape special regex characters
 */
function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Generate under construction HTML page
 */
function generateUnderConstructionHtml(projectName?: string): string {
  const escapedName = projectName ? escapeHtml(projectName) : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Under Construction${projectName ? ` - ${escapedName}` : ''}</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Helvetica Neue', sans-serif;
      background: #0a0a0a;
      color: #ffffff;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
      animation: fadeIn 0.6s ease-in;
    }

    @keyframes fadeIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }

    .container {
      text-align: center;
      max-width: 600px;
    }

    .logo-container {
      margin-bottom: 40px;
      animation: float 3s ease-in-out infinite;
    }

    @keyframes float {
      0%, 100% { transform: translateY(0px); }
      50% { transform: translateY(-10px); }
    }

    .logo {
      width: 120px;
      height: 120px;
      margin: 0 auto;
    }

    h1 {
      font-size: 36px;
      font-weight: 600;
      margin-bottom: 16px;
      letter-spacing: -0.5px;
    }

    .project-name {
      font-size: 20px;
      font-weight: 500;
      margin-bottom: 24px;
      color: #a1a1aa;
    }

    .message {
      font-size: 16px;
      line-height: 1.6;
      color: #71717a;
      margin-bottom: 12px;
    }

    .footer {
      margin-top: 60px;
      padding-top: 24px;
      border-top: 1px solid #27272a;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      font-size: 14px;
      color: #52525b;
    }

    .footer-logo {
      width: 20px;
      height: 20px;
      opacity: 0.8;
    }

    @media (max-width: 600px) {
      .logo {
        width: 80px;
        height: 80px;
      }
      h1 { font-size: 28px; }
      .project-name { font-size: 18px; }
      .message { font-size: 15px; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo-container">
      <svg class="logo" version="1.0" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" preserveAspectRatio="xMidYMid meet">
        <rect x="0" y="0" width="256" height="256" rx="20" ry="20" fill="#000000"/>
        <g transform="translate(0,256) scale(0.0476,-0.0476)" fill="#ffffff" stroke="none">
          <path d="M725 4825 c-50 -18 -100 -71 -114 -122 -15 -54 -15 -1573 0 -1628 16 -55 44 -92 89 -115 38 -19 62 -20 855 -20 781 0 817 1 853 19 46 23 67 46 87 94 13 32 15 138 15 830 0 566 -3 804 -11 828 -16 45 -55 87 -104 110 -38 18 -82 19 -835 18 -659 0 -802 -2 -835 -14z m1351 -371 c15 -11 37 -33 48 -48 21 -27 21 -38 21 -520 0 -547 3 -523 -68 -566 -31 -19 -54 -20 -521 -20 -483 0 -489 0 -524 22 -20 12 -42 38 -53 62 -17 38 -19 74 -19 504 0 496 1 503 51 548 46 41 66 43 561 41 464 -2 477 -3 504 -23z"/>
          <path d="M3058 4830 c-44 -13 -87 -49 -108 -90 -19 -37 -20 -61 -20 -471 0 -428 0 -432 22 -471 13 -22 41 -51 64 -64 41 -24 41 -24 685 -24 645 0 645 0 689 -22 63 -33 80 -71 80 -183 0 -101 -15 -144 -63 -179 -28 -21 -41 -21 -695 -26 -666 -5 -667 -5 -702 -27 -109 -68 -106 -247 5 -310 40 -23 40 -23 858 -23 664 0 824 3 850 14 43 17 95 78 102 118 3 18 5 225 3 459 -3 426 -3 426 -31 462 -58 76 -15 71 -757 77 -620 5 -667 6 -692 23 -44 30 -58 74 -58 179 0 116 16 153 80 186 44 22 44 22 693 22 710 0 678 -3 731 60 80 96 41 240 -79 287 -35 14 -1612 17 -1657 3z"/>
          <path d="M702 2509 c-48 -24 -75 -57 -91 -114 -9 -29 -11 -253 -9 -840 3 -779 4 -801 23 -834 11 -19 37 -48 58 -65 39 -31 39 -31 380 -31 342 0 342 0 399 28 31 15 63 39 73 53 16 25 16 25 62 -16 77 -67 104 -71 470 -68 320 3 320 3 360 30 24 16 49 44 62 70 21 44 21 49 21 854 0 773 -1 811 -19 851 -35 76 -135 120 -215 93 -41 -13 -90 -51 -109 -84 -9 -16 -13 -187 -17 -688 -5 -654 -5 -667 -26 -694 -43 -58 -68 -69 -169 -72 -82 -3 -99 -1 -133 18 -22 12 -49 39 -61 60 -21 37 -21 45 -21 664 0 439 -3 641 -11 673 -32 123 -190 174 -285 91 -73 -64 -69 -20 -70 -743 0 -721 3 -687 -66 -737 -28 -20 -47 -23 -133 -26 -91 -3 -103 -2 -134 20 -19 13 -44 36 -55 51 -21 28 -21 38 -26 695 -4 481 -8 673 -17 687 -50 87 -152 118 -241 74z"/>
          <path d="M3047 2515 c-47 -16 -81 -46 -101 -90 -14 -28 -16 -95 -16 -463 0 -281 4 -440 11 -459 15 -40 48 -73 94 -94 38 -17 79 -19 685 -19 626 0 646 -1 678 -20 58 -35 72 -72 72 -185 0 -110 -14 -147 -67 -182 -25 -17 -73 -18 -698 -23 -672 -5 -672 -5 -708 -33 -20 -15 -44 -42 -53 -60 -21 -39 -21 -125 -1 -163 20 -38 65 -80 100 -93 19 -8 289 -11 833 -11 701 0 809 2 841 15 48 20 71 41 94 88 19 35 19 60 17 480 -3 444 -3 444 -30 479 -54 71 -23 68 -740 68 -612 0 -645 1 -685 20 -67 30 -83 66 -83 183 0 116 14 156 68 189 35 21 35 21 691 22 606 1 658 2 688 19 137 74 130 264 -12 328 -38 18 -85 19 -840 18 -652 0 -807 -2 -838 -14z"/>
        </g>
      </svg>
    </div>

    <h1>Under Construction</h1>
    ${projectName ? `<div class="project-name">${escapedName}</div>` : ''}
    <p class="message">This site is currently being updated and improved.</p>
    <p class="message">Please check back soon!</p>

    <div class="footer">
      <span>Powered by</span>
      <svg class="footer-logo" version="1.0" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" preserveAspectRatio="xMidYMid meet">
        <rect x="0" y="0" width="256" height="256" rx="20" ry="20" fill="#52525b"/>
        <g transform="translate(0,256) scale(0.0476,-0.0476)" fill="#ffffff" stroke="none">
          <path d="M725 4825 c-50 -18 -100 -71 -114 -122 -15 -54 -15 -1573 0 -1628 16 -55 44 -92 89 -115 38 -19 62 -20 855 -20 781 0 817 1 853 19 46 23 67 46 87 94 13 32 15 138 15 830 0 566 -3 804 -11 828 -16 45 -55 87 -104 110 -38 18 -82 19 -835 18 -659 0 -802 -2 -835 -14z m1351 -371 c15 -11 37 -33 48 -48 21 -27 21 -38 21 -520 0 -547 3 -523 -68 -566 -31 -19 -54 -20 -521 -20 -483 0 -489 0 -524 22 -20 12 -42 38 -53 62 -17 38 -19 74 -19 504 0 496 1 503 51 548 46 41 66 43 561 41 464 -2 477 -3 504 -23z"/>
          <path d="M3058 4830 c-44 -13 -87 -49 -108 -90 -19 -37 -20 -61 -20 -471 0 -428 0 -432 22 -471 13 -22 41 -51 64 -64 41 -24 41 -24 685 -24 645 0 645 0 689 -22 63 -33 80 -71 80 -183 0 -101 -15 -144 -63 -179 -28 -21 -41 -21 -695 -26 -666 -5 -667 -5 -702 -27 -109 -68 -106 -247 5 -310 40 -23 40 -23 858 -23 664 0 824 3 850 14 43 17 95 78 102 118 3 18 5 225 3 459 -3 426 -3 426 -31 462 -58 76 -15 71 -757 77 -620 5 -667 6 -692 23 -44 30 -58 74 -58 179 0 116 16 153 80 186 44 22 44 22 693 22 710 0 678 -3 731 60 80 96 41 240 -79 287 -35 14 -1612 17 -1657 3z"/>
          <path d="M702 2509 c-48 -24 -75 -57 -91 -114 -9 -29 -11 -253 -9 -840 3 -779 4 -801 23 -834 11 -19 37 -48 58 -65 39 -31 39 -31 380 -31 342 0 342 0 399 28 31 15 63 39 73 53 16 25 16 25 62 -16 77 -67 104 -71 470 -68 320 3 320 3 360 30 24 16 49 44 62 70 21 44 21 49 21 854 0 773 -1 811 -19 851 -35 76 -135 120 -215 93 -41 -13 -90 -51 -109 -84 -9 -16 -13 -187 -17 -688 -5 -654 -5 -667 -26 -694 -43 -58 -68 -69 -169 -72 -82 -3 -99 -1 -133 18 -22 12 -49 39 -61 60 -21 37 -21 45 -21 664 0 439 -3 641 -11 673 -32 123 -190 174 -285 91 -73 -64 -69 -20 -70 -743 0 -721 3 -687 -66 -737 -28 -20 -47 -23 -133 -26 -91 -3 -103 -2 -134 20 -19 13 -44 36 -55 51 -21 28 -21 38 -26 695 -4 481 -8 673 -17 687 -50 87 -152 118 -241 74z"/>
          <path d="M3047 2515 c-47 -16 -81 -46 -101 -90 -14 -28 -16 -95 -16 -463 0 -281 4 -440 11 -459 15 -40 48 -73 94 -94 38 -17 79 -19 685 -19 626 0 646 -1 678 -20 58 -35 72 -72 72 -185 0 -110 -14 -147 -67 -182 -25 -17 -73 -18 -698 -23 -672 -5 -672 -5 -708 -33 -20 -15 -44 -42 -53 -60 -21 -39 -21 -125 -1 -163 20 -38 65 -80 100 -93 19 -8 289 -11 833 -11 701 0 809 2 841 15 48 20 71 41 94 88 19 35 19 60 17 480 -3 444 -3 444 -30 479 -54 71 -23 68 -740 68 -612 0 -645 1 -685 20 -67 30 -83 66 -83 183 0 116 14 156 68 189 35 21 35 21 691 22 606 1 658 2 688 19 137 74 130 264 -12 328 -38 18 -85 19 -840 18 -652 0 -807 -2 -838 -14z"/>
        </g>
      </svg>
      <span>OSW Studio</span>
    </div>
  </div>
</body>
</html>`;
}

/**
 * Escape HTML special characters
 */
function escapeHtml(text: string): string {
  const map: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;',
  };
  return text.replace(/[&<>"']/g, (m) => map[m]);
}

/**
 * Get the primary published deployment ID
 * Returns the first enabled deployment
 */
export async function getPrimaryPublishedDeploymentId(): Promise<string | null> {
  try {
    const adapter = await createServerAdapter();
    await adapter.init();

    const deployments = await adapter.listDeployments?.() || [];
    // Find the first enabled deployment
    const enabledDeployment = deployments.find((s: Deployment) => s.enabled === true);

    return enabledDeployment?.id || null;
  } catch (error) {
    logger.error('[Static Builder] Error getting published deployment:', error);
    return null;
  }
}
