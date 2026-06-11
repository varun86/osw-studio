/**
 * System Database
 *
 * Manages the shared system.sqlite database for user accounts,
 * workspaces, workspace access, and deployment routing.
 * Workspaces are the unit of data isolation and quota enforcement.
 * Users get granted access to workspaces with roles (owner/editor/viewer).
 */

import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import { randomUUID } from 'crypto';
import { enqueueEvent } from '../webhooks/outbox';
import { startDeliveryLoop } from '../webhooks/delivery';
import { applyEncryptionKey } from './db-crypto';

let systemDb: Database.Database | null = null;

function getDataDir(): string {
  return process.env.DATA_DIR || path.join(process.cwd(), 'data');
}

function ensureDir(dirPath: string): void {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SystemUser {
  id: string;
  email: string;
  password_hash: string;
  display_name: string | null;
  is_admin: number;
  active: number;
  default_workspace_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface SystemWorkspace {
  id: string;
  name: string;
  owner_id: string;
  max_projects: number;
  max_deployments: number;
  max_storage_mb: number;
  created_at: string;
  updated_at: string;
}

export interface WorkspaceAccess {
  user_id: string;
  workspace_id: string;
  role: 'owner' | 'editor' | 'viewer';
  created_at: string;
}

// ---------------------------------------------------------------------------
// Role hierarchy
// ---------------------------------------------------------------------------

const ROLE_LEVELS: Record<string, number> = { viewer: 1, editor: 2, owner: 3 };

// ---------------------------------------------------------------------------
// Database init
// ---------------------------------------------------------------------------

/**
 * Get the system database connection (singleton)
 */
export function getSystemDatabase(): Database.Database {
  if (systemDb) return systemDb;

  const dataDir = getDataDir();
  ensureDir(dataDir);

  const dbPath = path.join(dataDir, 'system.sqlite');
  systemDb = new Database(dbPath);
  // SECURITY: Apply encryption key with validation to prevent SQL injection
  // Previously, the key was interpolated directly: db.pragma(`key='${encryptionKey}'`)
  // This allowed SQL injection if the env var contained single quotes.
  // applyEncryptionKey() validates the key contains only [a-fA-F0-9+/=] before use.
  applyEncryptionKey(systemDb, process.env.DB_ENCRYPTION_KEY, 'DB_ENCRYPTION_KEY');
  systemDb.pragma('journal_mode = WAL');
  systemDb.pragma('foreign_keys = ON');
  systemDb.pragma('synchronous = NORMAL');

  initSystemSchema(systemDb);

  startDeliveryLoop();

  return systemDb;
}

function initSystemSchema(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      display_name TEXT,
      is_admin INTEGER NOT NULL DEFAULT 0,
      active INTEGER NOT NULL DEFAULT 1,
      default_workspace_id TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS workspaces (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      owner_id TEXT NOT NULL,
      max_projects INTEGER NOT NULL DEFAULT 3,
      max_deployments INTEGER NOT NULL DEFAULT 1,
      max_storage_mb INTEGER NOT NULL DEFAULT 100,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (owner_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS workspace_access (
      user_id TEXT NOT NULL,
      workspace_id TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'editor',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      PRIMARY KEY (user_id, workspace_id),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS deployment_routing (
      deployment_id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL,
      slug TEXT UNIQUE,
      custom_domain TEXT UNIQUE,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS consumed_handoff_tokens (
      jti TEXT PRIMARY KEY,
      consumed_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    CREATE INDEX IF NOT EXISTS idx_workspaces_owner ON workspaces(owner_id);
    CREATE INDEX IF NOT EXISTS idx_workspace_access_user ON workspace_access(user_id);
    CREATE INDEX IF NOT EXISTS idx_workspace_access_workspace ON workspace_access(workspace_id);
    CREATE INDEX IF NOT EXISTS idx_deployment_routing_workspace ON deployment_routing(workspace_id);
    CREATE INDEX IF NOT EXISTS idx_deployment_routing_slug ON deployment_routing(slug);

    CREATE TABLE IF NOT EXISTS user_api_keys (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      provider TEXT NOT NULL,
      encrypted_key TEXT NOT NULL,
      iv TEXT NOT NULL,
      auth_tag TEXT NOT NULL,
      key_hint TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(user_id, provider),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_user_api_keys_user ON user_api_keys(user_id);

    CREATE TABLE IF NOT EXISTS webhook_outbox (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_type TEXT NOT NULL,
      payload TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      delivered INTEGER NOT NULL DEFAULT 0,
      delivered_at TEXT,
      attempts INTEGER NOT NULL DEFAULT 0,
      last_attempted_at TEXT
    );
  `);

  // Migration: add custom_domain column if missing (existing databases)
  try {
    db.prepare('SELECT custom_domain FROM deployment_routing LIMIT 0').get();
  } catch {
    db.prepare('ALTER TABLE deployment_routing ADD COLUMN custom_domain TEXT').run();
    db.prepare('CREATE UNIQUE INDEX IF NOT EXISTS idx_deployment_routing_domain ON deployment_routing(custom_domain)').run();
  }
}

// ---------------------------------------------------------------------------
// User functions
// ---------------------------------------------------------------------------

/**
 * Create a new user. Returns the user ID.
 */
export function createUser(email: string, passwordHash: string, displayName?: string): string {
  const db = getSystemDatabase();
  const id = randomUUID();
  db.prepare(`
    INSERT INTO users (id, email, password_hash, display_name)
    VALUES (?, ?, ?, ?)
  `).run(id, email.toLowerCase().trim(), passwordHash, displayName || null);

  enqueueEvent('user.created', { userId: id, email: email.toLowerCase().trim(), displayName: displayName || null });

  return id;
}

/**
 * Find a user by email
 */
export function getUserByEmail(email: string): SystemUser | undefined {
  const db = getSystemDatabase();
  return db.prepare('SELECT * FROM users WHERE email = ? AND active = 1')
    .get(email.toLowerCase().trim()) as SystemUser | undefined;
}

/**
 * Find a user by ID
 */
export function getUserById(id: string): SystemUser | undefined {
  const db = getSystemDatabase();
  return db.prepare('SELECT * FROM users WHERE id = ? AND active = 1')
    .get(id) as SystemUser | undefined;
}

/**
 * Get the number of user accounts (for bootstrap detection)
 */
export function getUserCount(): number {
  const db = getSystemDatabase();
  const row = db.prepare('SELECT COUNT(*) as count FROM users').get() as { count: number };
  return row.count;
}

/**
 * Deactivate a user (soft delete)
 */
export function deactivateUser(id: string): void {
  const db = getSystemDatabase();
  db.prepare("UPDATE users SET active = 0, updated_at = datetime('now') WHERE id = ?").run(id);
  enqueueEvent('user.deactivated', { userId: id });
}

/**
 * List all users (for admin). Excludes password_hash.
 */
export function listUsers(): Omit<SystemUser, 'password_hash'>[] {
  const db = getSystemDatabase();
  return db.prepare(`
    SELECT id, email, display_name, is_admin, active,
           default_workspace_id, created_at, updated_at
    FROM users ORDER BY created_at DESC
  `).all() as Omit<SystemUser, 'password_hash'>[];
}

/**
 * Update user properties
 */
export function updateUser(id: string, updates: { display_name?: string; active?: number }): void {
  const db = getSystemDatabase();
  const setClauses: string[] = ["updated_at = datetime('now')"];
  const values: (string | number)[] = [];

  if (updates.display_name !== undefined) { setClauses.push('display_name = ?'); values.push(updates.display_name); }
  if (updates.active !== undefined) { setClauses.push('active = ?'); values.push(updates.active); }

  values.push(id);
  db.prepare(`UPDATE users SET ${setClauses.join(', ')} WHERE id = ?`).run(...values);

  const updated = getUserById(id);
  if (updated) {
    enqueueEvent('user.updated', { userId: id, email: updated.email, displayName: updated.display_name });
  }
}

// ---------------------------------------------------------------------------
// Workspace functions
// ---------------------------------------------------------------------------

/**
 * Create a workspace, create its data directory, return workspace ID.
 */
export function createWorkspace(name: string, ownerId: string): string {
  const db = getSystemDatabase();
  const id = randomUUID();

  db.prepare(`INSERT INTO workspaces (id, name, owner_id) VALUES (?, ?, ?)`).run(id, name, ownerId);

  // Grant owner access
  db.prepare(`
    INSERT INTO workspace_access (user_id, workspace_id, role)
    VALUES (?, ?, 'owner')
  `).run(ownerId, id);

  // Create workspace data directory
  const workspaceDir = path.join(getDataDir(), 'workspaces', id);
  ensureDir(workspaceDir);

  enqueueEvent('workspace.created', { workspaceId: id, name, ownerId });

  return id;
}

/**
 * Get workspace by ID
 */
export function getWorkspaceById(id: string): SystemWorkspace | undefined {
  const db = getSystemDatabase();
  return db.prepare('SELECT * FROM workspaces WHERE id = ?')
    .get(id) as SystemWorkspace | undefined;
}

/**
 * List all workspaces (admin)
 */
export function listWorkspaces(): SystemWorkspace[] {
  const db = getSystemDatabase();
  return db.prepare('SELECT * FROM workspaces ORDER BY created_at DESC')
    .all() as SystemWorkspace[];
}

/**
 * List workspaces a user has access to (with their role)
 */
export function listUserWorkspaces(userId: string): (SystemWorkspace & { role: string })[] {
  const db = getSystemDatabase();
  return db.prepare(`
    SELECT w.*, wa.role
    FROM workspaces w
    JOIN workspace_access wa ON wa.workspace_id = w.id
    WHERE wa.user_id = ?
    ORDER BY w.created_at DESC
  `).all(userId) as (SystemWorkspace & { role: string })[];
}

/**
 * Update workspace properties
 */
export function updateWorkspace(id: string, updates: {
  name?: string;
  max_projects?: number;
  max_deployments?: number;
  max_storage_mb?: number;
}): void {
  const db = getSystemDatabase();
  const setClauses: string[] = ["updated_at = datetime('now')"];
  const values: (string | number)[] = [];

  if (updates.name !== undefined) { setClauses.push('name = ?'); values.push(updates.name); }
  if (updates.max_projects !== undefined) { setClauses.push('max_projects = ?'); values.push(updates.max_projects); }
  if (updates.max_deployments !== undefined) { setClauses.push('max_deployments = ?'); values.push(updates.max_deployments); }
  if (updates.max_storage_mb !== undefined) { setClauses.push('max_storage_mb = ?'); values.push(updates.max_storage_mb); }

  values.push(id);
  db.prepare(`UPDATE workspaces SET ${setClauses.join(', ')} WHERE id = ?`).run(...values);

  if (updates.name !== undefined) {
    enqueueEvent('workspace.updated', { workspaceId: id, name: updates.name });
  }
}

/**
 * Delete workspace (removes from DB, caller handles filesystem cleanup)
 */
export function deleteWorkspace(id: string): void {
  const db = getSystemDatabase();
  db.prepare('DELETE FROM workspaces WHERE id = ?').run(id);
  enqueueEvent('workspace.deleted', { workspaceId: id });
}

// ---------------------------------------------------------------------------
// Workspace access functions
// ---------------------------------------------------------------------------

/**
 * Grant a user access to a workspace
 */
export function grantWorkspaceAccess(userId: string, workspaceId: string, role: 'owner' | 'editor' | 'viewer'): void {
  const db = getSystemDatabase();
  db.prepare(`
    INSERT OR REPLACE INTO workspace_access (user_id, workspace_id, role)
    VALUES (?, ?, ?)
  `).run(userId, workspaceId, role);

  const grantedUser = getUserById(userId);
  if (grantedUser) {
    enqueueEvent('workspace.access_granted', { workspaceId, email: grantedUser.email, role });
  }
}

/**
 * Revoke a user's access to a workspace
 */
export function revokeWorkspaceAccess(userId: string, workspaceId: string): void {
  const db = getSystemDatabase();
  const revokedUser = getUserById(userId);
  db.prepare('DELETE FROM workspace_access WHERE user_id = ? AND workspace_id = ?')
    .run(userId, workspaceId);

  if (revokedUser) {
    enqueueEvent('workspace.access_revoked', { workspaceId, email: revokedUser.email });
  }
}

/**
 * Get a user's access to a specific workspace
 */
export function getWorkspaceAccess(userId: string, workspaceId: string): WorkspaceAccess | undefined {
  const db = getSystemDatabase();
  return db.prepare('SELECT * FROM workspace_access WHERE user_id = ? AND workspace_id = ?')
    .get(userId, workspaceId) as WorkspaceAccess | undefined;
}

/**
 * Verify user has access to workspace, throws Error if not.
 * Admin users (is_admin=1) always have access.
 * Legacy admin/desktop/instance-api users always have access.
 */
export function verifyWorkspaceAccess(
  userId: string,
  workspaceId: string,
  requiredRole: 'owner' | 'editor' | 'viewer' = 'viewer'
): void {
  // Admin users always have access
  const user = getUserById(userId);
  if (user?.is_admin) return;

  // Also allow legacy admin and desktop users
  if (userId === 'admin' || userId === 'desktop' || userId === 'instance-api') return;

  const access = getWorkspaceAccess(userId, workspaceId);
  if (!access) throw new Error('Workspace access denied');

  const userLevel = ROLE_LEVELS[access.role] || 0;
  const requiredLevel = ROLE_LEVELS[requiredRole] || 0;
  if (userLevel < requiredLevel) throw new Error('Insufficient workspace permissions');
}

/**
 * Set user's default workspace
 */
export function setDefaultWorkspace(userId: string, workspaceId: string): void {
  const db = getSystemDatabase();
  db.prepare("UPDATE users SET default_workspace_id = ?, updated_at = datetime('now') WHERE id = ?")
    .run(workspaceId, userId);
}

/**
 * Get user's default workspace ID
 */
export function getUserDefaultWorkspace(userId: string): string | undefined {
  const db = getSystemDatabase();
  const row = db.prepare('SELECT default_workspace_id FROM users WHERE id = ?')
    .get(userId) as { default_workspace_id: string | null } | undefined;
  return row?.default_workspace_id ?? undefined;
}

// ---------------------------------------------------------------------------
// Deployment routing functions
// ---------------------------------------------------------------------------

/**
 * Register a deployment for routing
 */
export function registerDeploymentRoute(deploymentId: string, workspaceId: string, slug?: string, customDomain?: string): void {
  const db = getSystemDatabase();

  // Check if another workspace already owns this deployment
  const existing = db.prepare('SELECT workspace_id FROM deployment_routing WHERE deployment_id = ?')
    .get(deploymentId) as { workspace_id: string } | undefined;
  if (existing && existing.workspace_id !== workspaceId) {
    throw new Error('Deployment is owned by another workspace');
  }

  if (customDomain) {
    const domainOwner = db.prepare(
      'SELECT deployment_id FROM deployment_routing WHERE custom_domain = ? AND deployment_id != ?'
    ).get(customDomain, deploymentId) as { deployment_id: string } | undefined;
    if (domainOwner) {
      throw new Error('Domain is already registered to another deployment');
    }
  }

  db.prepare(`
    INSERT OR REPLACE INTO deployment_routing (deployment_id, workspace_id, slug, custom_domain)
    VALUES (?, ?, ?, ?)
  `).run(deploymentId, workspaceId, slug || null, customDomain || null);
}

/**
 * Remove a deployment route
 */
export function removeDeploymentRoute(deploymentId: string): void {
  const db = getSystemDatabase();
  db.prepare('DELETE FROM deployment_routing WHERE deployment_id = ?').run(deploymentId);
}

/**
 * Get the full routing record for a deployment
 */
export function getDeploymentRoute(deploymentId: string): { deployment_id: string; workspace_id: string; slug: string | null; custom_domain: string | null } | undefined {
  const db = getSystemDatabase();
  return db.prepare('SELECT deployment_id, workspace_id, slug, custom_domain FROM deployment_routing WHERE deployment_id = ?')
    .get(deploymentId) as { deployment_id: string; workspace_id: string; slug: string | null; custom_domain: string | null } | undefined;
}

/**
 * Look up which workspace owns a deployment
 */
export function getDeploymentWorkspace(deploymentId: string): string | undefined {
  const db = getSystemDatabase();
  const row = db.prepare('SELECT workspace_id FROM deployment_routing WHERE deployment_id = ?')
    .get(deploymentId) as { workspace_id: string } | undefined;
  return row?.workspace_id;
}

/**
 * Look up a deployment by subdomain slug
 */
export function getDeploymentBySlug(slug: string): { deployment_id: string; workspace_id: string } | undefined {
  const db = getSystemDatabase();
  return db.prepare('SELECT deployment_id, workspace_id FROM deployment_routing WHERE slug = ?')
    .get(slug) as { deployment_id: string; workspace_id: string } | undefined;
}

/**
 * Look up a deployment by custom domain
 */
export function getDeploymentByDomain(domain: string): { deployment_id: string; workspace_id: string } | undefined {
  const db = getSystemDatabase();
  return db.prepare(
    'SELECT deployment_id, workspace_id FROM deployment_routing WHERE custom_domain = ?'
  ).get(domain) as { deployment_id: string; workspace_id: string } | undefined;
}

/**
 * Get all deployments with custom domains (for Caddy config generation)
 */
export function getAllDomainRoutes(): { deployment_id: string; workspace_id: string; custom_domain: string }[] {
  const db = getSystemDatabase();
  return db.prepare(
    'SELECT deployment_id, workspace_id, custom_domain FROM deployment_routing WHERE custom_domain IS NOT NULL ORDER BY custom_domain'
  ).all() as { deployment_id: string; workspace_id: string; custom_domain: string }[];
}

/**
 * Get all deployments with slugs (for Caddy subdomain config generation)
 */
export function getAllSlugRoutes(): { deployment_id: string; slug: string }[] {
  const db = getSystemDatabase();
  return db.prepare(
    'SELECT deployment_id, slug FROM deployment_routing WHERE slug IS NOT NULL ORDER BY slug'
  ).all() as { deployment_id: string; slug: string }[];
}

/**
 * Get workspace's deployment count (for quota enforcement)
 */
export function getWorkspaceDeploymentCount(workspaceId: string): number {
  const db = getSystemDatabase();
  const row = db.prepare('SELECT COUNT(*) as count FROM deployment_routing WHERE workspace_id = ?')
    .get(workspaceId) as { count: number };
  return row.count;
}

// ---------------------------------------------------------------------------
// Workspace stats (used by admin APIs)
// ---------------------------------------------------------------------------

/**
 * Get the project count for a workspace by reading its database directly.
 * Opens the workspace DB read-only, does not use the adapter cache.
 */
export function getWorkspaceProjectCount(workspaceId: string): number {
  const dbPath = path.join(getDataDir(), 'workspaces', workspaceId, 'osws.sqlite');
  if (!fs.existsSync(dbPath)) return 0;
  try {
    const db = new Database(dbPath, { readonly: true });
    const tableExists = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='projects'").get();
    if (!tableExists) { db.close(); return 0; }
    const count = (db.prepare('SELECT COUNT(*) as count FROM projects').get() as { count: number }).count;
    db.close();
    return count;
  } catch { return 0; }
}

// ---------------------------------------------------------------------------
// Close
// ---------------------------------------------------------------------------

/**
 * Mark a handoff token JTI as consumed in the database.
 * Returns true if the JTI was successfully marked (not previously consumed).
 */
export function markHandoffTokenConsumed(jti: string): boolean {
  try {
    const db = getSystemDatabase();
    const now = Date.now();
    db.prepare('INSERT OR IGNORE INTO consumed_handoff_tokens (jti, consumed_at) VALUES (?, ?)').run(jti, now);
    // Check if the insert actually happened (not ignored due to duplicate)
    const row = db.prepare('SELECT consumed_at FROM consumed_handoff_tokens WHERE jti = ?').get(jti) as { consumed_at: number } | undefined;
    return row?.consumed_at === now;
  } catch {
    return false;
  }
}

/**
 * Check if a handoff token JTI has been consumed.
 */
export function isHandoffTokenConsumed(jti: string): boolean {
  try {
    const db = getSystemDatabase();
    const row = db.prepare('SELECT jti FROM consumed_handoff_tokens WHERE jti = ?').get(jti);
    return !!row;
  } catch {
    return false;
  }
}

/**
 * Cleanup expired consumed handoff tokens (older than 5 minutes).
 */
export function cleanupExpiredHandoffTokens(): void {
  try {
    const db = getSystemDatabase();
    const cutoff = Date.now() - 5 * 60 * 1000; // 5 minutes
    db.prepare('DELETE FROM consumed_handoff_tokens WHERE consumed_at < ?').run(cutoff);
  } catch {
    // Ignore cleanup errors
  }
}

/**
 * Close system database connection
 */
export function closeSystemDatabase(): void {
  if (systemDb) {
    try { systemDb.close(); } catch {}
    systemDb = null;
  }
}
