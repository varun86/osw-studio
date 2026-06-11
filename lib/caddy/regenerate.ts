/**
 * Instance-level Caddy config regeneration.
 *
 * When STATIC_PROXY=true, regenerates the Caddyfile from the deployment
 * routing table and reloads Caddy. Called after publish/unpublish.
 *
 * Generates three types of server blocks:
 * 1. Main instance domain (inst-1.oswstudio.com)
 * 2. Subdomain routes (sunny-oak-river.inst-1.oswstudio.com) — wildcard cert
 * 3. Custom domain routes (sweetcandies.com) — on-demand TLS
 *
 * Does nothing if STATIC_PROXY is not set.
 *
 * SECURITY: All domain and slug values are validated via sanitizeCaddyInput()
 * before being interpolated into the Caddyfile. This prevents Caddy config
 * injection attacks where a malicious domain could contain Caddy directives.
 */

import { getAllDomainRoutes, getAllSlugRoutes } from '@/lib/auth/system-database';

const CADDY_ADMIN_API = process.env.CADDY_ADMIN_API || 'http://localhost:2019';

/**
 * Validate and sanitize a value before interpolation into a Caddyfile.
 *
 * Only allows [a-zA-Z0-9.-] in domain names, [a-zA-Z0-9_-] in slugs/deployment IDs.
 * Rejects any value containing Caddy metacharacters: { } \n \r " '
 *
 * @param value - The value to sanitize
 * @param label - Human-readable label for error messages
 * @returns The sanitized value (unchanged if valid)
 * @throws Error if the value contains disallowed characters
 */
export function sanitizeCaddyInput(value: string, label: string = 'input'): string {
  if (!value || typeof value !== 'string') {
    throw new Error(`Caddy config: ${label} must be a non-empty string`);
  }

  // Block Caddy metacharacters and control characters
  if (/[{}\n\r"'\\]/.test(value)) {
    throw new Error(`Caddy config: ${label} contains forbidden characters ({{, }}, newlines, quotes)`);
  }

  // Block path traversal attempts
  if (value.includes('..')) {
    throw new Error(`Caddy config: ${label} contains path traversal sequence`);
  }

  return value;
}

/**
 * Validate a domain name for use in Caddy configuration.
 * Only allows [a-zA-Z0-9.-] and rejects obviously invalid patterns.
 */
export function validateCaddyDomain(domain: string): string {
  sanitizeCaddyInput(domain, 'domain');

  // Domain must only contain alphanumeric, dots, and hyphens
  if (!/^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$/.test(domain)) {
    throw new Error(`Caddy config: domain "${domain}" contains invalid characters (only [a-zA-Z0-9.-] allowed)`);
  }

  // Reject domains starting/ending with dots or hyphens
  if (domain.startsWith('.') || domain.startsWith('-') || domain.endsWith('.') || domain.endsWith('-')) {
    throw new Error(`Caddy config: domain "${domain}" has invalid format (cannot start/end with . or -)`);
  }

  return domain;
}

/**
 * Validate a slug for use in Caddy subdomain configuration.
 * Only allows [a-zA-Z0-9-] (kebab-case).
 */
export function validateCaddySlug(slug: string): string {
  sanitizeCaddyInput(slug, 'slug');

  if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(slug)) {
    throw new Error(`Caddy config: slug "${slug}" contains invalid characters (only [a-zA-Z0-9-] allowed)`);
  }

  return slug;
}

/**
 * Validate a deployment ID for use in Caddy configuration.
 * Only allows [a-zA-Z0-9_-].
 */
export function validateCaddyDeploymentId(id: string): string {
  sanitizeCaddyInput(id, 'deployment ID');

  if (!/^[a-zA-Z0-9_-]+$/.test(id)) {
    throw new Error(`Caddy config: deployment ID "${id}" contains invalid characters (only [a-zA-Z0-9_-] allowed)`);
  }

  return id;
}

export interface CaddyConfig {
  domain: string;
  publicRoot: string;
  slugRoutes: { deployment_id: string; slug: string }[];
  customDomainRoutes: { deployment_id: string; custom_domain: string }[];
}

export function generateCaddyfile(config: CaddyConfig): string {
  const { domain, publicRoot, slugRoutes, customDomainRoutes } = config;
  const lines: string[] = [];

  // SECURITY: Validate all inputs before interpolation into Caddyfile
  // This prevents Caddy config injection attacks
  const validatedDomain = validateCaddyDomain(domain);
  const validatedPublicRoot = sanitizeCaddyInput(publicRoot, 'publicRoot');

  const validatedSlugRoutes = slugRoutes.map(route => ({
    deployment_id: validateCaddyDeploymentId(route.deployment_id),
    slug: validateCaddySlug(route.slug),
  }));

  const validatedCustomDomainRoutes = customDomainRoutes.map(route => ({
    deployment_id: validateCaddyDeploymentId(route.deployment_id),
    custom_domain: validateCaddyDomain(route.custom_domain),
  }));

  // Global options
  lines.push('{');
  lines.push('  admin localhost:2019 {');
  lines.push('    origins localhost:2019');
  lines.push('  }');
  if (validatedCustomDomainRoutes.length > 0) {
    lines.push('  on_demand_tls {');
    lines.push('    ask http://localhost:3000/api/resolve-domain');
    lines.push('  }');
  }
  lines.push('}');
  lines.push('');

  // Main instance domain
  lines.push(`${validatedDomain} {`);
  lines.push('  handle /deployments/* {');
  lines.push(`    root * ${validatedPublicRoot}`);
  lines.push('    try_files {path} {path}.html {path}/index.html');
  lines.push('    file_server');
  lines.push('    header Cache-Control "public, max-age=3600"');
  lines.push('  }');
  lines.push('');
  lines.push('  reverse_proxy localhost:3000');
  lines.push('}');
  lines.push('');

  // Subdomain routes — specific blocks before the wildcard
  for (const route of validatedSlugRoutes) {
    lines.push(`${route.slug}.${validatedDomain} {`);
    lines.push(`  root * ${validatedPublicRoot}`);
    lines.push(`  rewrite * /deployments/${route.deployment_id}{uri}`);
    lines.push('  try_files {path} {path}.html {path}/index.html');
    lines.push('  file_server');
    lines.push('  header Cache-Control "public, max-age=3600"');
    lines.push('}');
    lines.push('');
  }

  // Wildcard subdomain fallback (catches slugs not yet in config, proxies to Node.js)
  if (validatedSlugRoutes.length > 0) {
    lines.push(`*.${validatedDomain} {`);
    lines.push('  tls {');
    lines.push('    dns cloudflare {env.CLOUDFLARE_API_TOKEN}');
    lines.push('  }');
    lines.push('  reverse_proxy localhost:3000');
    lines.push('}');
    lines.push('');
  }

  // Custom domain routes
  for (const route of validatedCustomDomainRoutes) {
    lines.push(`${route.custom_domain} {`);
    lines.push('  tls {');
    lines.push('    on_demand');
    lines.push('  }');
    lines.push(`  root * ${validatedPublicRoot}`);
    lines.push(`  rewrite * /deployments/${route.deployment_id}{uri}`);
    lines.push('  try_files {path} {path}.html {path}/index.html');
    lines.push('  file_server');
    lines.push('  header Cache-Control "public, max-age=3600"');
    lines.push('}');
    lines.push('');
  }

  return lines.join('\n');
}

export async function regenerateInstanceCaddy(): Promise<void> {
  if (process.env.STATIC_PROXY !== 'true') return;

  try {
    const domain = (process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000')
      .replace(/^https?:\/\//, '');
    const publicRoot = process.cwd() + '/public';

    const config = generateCaddyfile({
      domain,
      publicRoot,
      slugRoutes: getAllSlugRoutes(),
      customDomainRoutes: getAllDomainRoutes(),
    });

    // Write to disk so Caddy restarts pick up the config
    const caddyfilePath = process.env.CADDYFILE_PATH || '/etc/caddy/Caddyfile';
    const { promises: fs } = require('fs');
    await fs.writeFile(caddyfilePath, config, 'utf-8').catch(() => {});

    // Reload via admin API for immediate effect
    const res = await fetch(`${CADDY_ADMIN_API}/load`, {
      method: 'POST',
      headers: {
        'Content-Type': 'text/caddyfile',
        'Origin': `http://localhost:${new URL(CADDY_ADMIN_API).port || '2019'}`,
      },
      body: config,
    });

    if (!res.ok) {
      console.error(`[Caddy] Reload failed: ${res.status} ${await res.text()}`);
    }
  } catch (err) {
    console.error('[Caddy] Config regeneration failed:', err);
  }
}
