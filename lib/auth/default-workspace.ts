/**
 * Default Workspace Management
 *
 * Ensures a default workspace exists for desktop mode and
 * legacy single-user (admin password) mode. Called on first
 * access when no workspace context exists.
 *
 * Handles migration: if data/osws.sqlite has existing projects,
 * copies it to the new workspace so data isn't lost on upgrade.
 */

import 'server-only';

import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import {
  getSystemDatabase,
  createWorkspace,
  setDefaultWorkspace,
  getUserDefaultWorkspace,
  getUserById,
  createUser,
  updateWorkspace,
} from './system-database';
import { hashPassword } from './passwords';
import { applyEncryptionKey } from './db-crypto';
import { logger } from '@/lib/utils';

function openReadonlyDb(dbPath: string): Database.Database {
  const db = new Database(dbPath, { readonly: true });
  // SECURITY: Apply encryption key with validation to prevent SQL injection
  applyEncryptionKey(db, process.env.DB_ENCRYPTION_KEY, 'DB_ENCRYPTION_KEY');
  return db;
}

const DEFAULT_WORKSPACE_NAME = 'Local Workspace';

function getDataDir(): string {
  return process.env.DATA_DIR || path.join(process.cwd(), 'data');
}

/**
 * Ensure a default workspace exists for the given user ID.
 * Creates the user (if synthetic like 'admin'/'desktop') and workspace on first call.
 * If upgrading from single-user mode, migrates existing data to the workspace.
 * Returns the default workspace ID.
 */
export async function ensureDefaultWorkspace(userId: string): Promise<string> {
  // When in managed mode (WEBHOOK_URL set), workspaces start clean — no legacy migration.
  // On standalone instances, migrate legacy data/osws.sqlite into the workspace for all users.
  const isBalancerManaged = !!process.env.WEBHOOK_URL;

  // Check if user already has a default workspace
  const existing = getUserDefaultWorkspace(userId);
  if (existing) {
    if (!isBalancerManaged) {
      migrateLegacyData(existing);
    }
    return existing;
  }

  // For synthetic users (admin, desktop), create a user record if it doesn't exist
  const user = getUserById(userId);
  if (!user) {
    const { randomBytes } = await import('crypto');
    const hash = await hashPassword(randomBytes(32).toString('hex'));
    const db = getSystemDatabase();
    db.prepare(`
      INSERT OR IGNORE INTO users (id, email, password_hash, display_name, is_admin, active)
      VALUES (?, ?, ?, ?, 1, 1)
    `).run(userId, `${userId}@localhost`, hash, userId === 'desktop' ? 'Desktop' : 'Admin');
  }

  // Create default workspace with high limits for admin/desktop
  const workspaceId = createWorkspace(DEFAULT_WORKSPACE_NAME, userId);
  updateWorkspace(workspaceId, {
    max_projects: 9999,
    max_deployments: 9999,
    max_storage_mb: 99999,
  });
  setDefaultWorkspace(userId, workspaceId);

  // Migrate legacy data on standalone instances
  if (!isBalancerManaged) {
    migrateLegacyData(workspaceId);
  }

  return workspaceId;
}

/**
 * If upgrading from single-user mode, copy the existing data/osws.sqlite
 * and project databases into the new workspace directory.
 *
 * Checks whether the legacy DB has data AND the workspace DB is empty
 * (not just whether files exist, since the adapter may have already
 * created an empty workspace DB with schema migrations).
 */
function migrateLegacyData(workspaceId: string): void {
  const dataDir = getDataDir();
  const legacyDbPath = path.join(dataDir, 'osws.sqlite');
  const workspaceDir = path.join(dataDir, 'workspaces', workspaceId);
  const workspaceDbPath = path.join(workspaceDir, 'osws.sqlite');

  if (!fs.existsSync(legacyDbPath)) return;

  // Check if legacy DB actually has projects
  let legacyProjectCount = 0;
  try {
    const db = openReadonlyDb(legacyDbPath);
    const row = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='projects'").get();
    if (row) {
      legacyProjectCount = (db.prepare('SELECT COUNT(*) as c FROM projects').get() as { c: number }).c;
    }
    db.close();
  } catch { return; }

  if (legacyProjectCount === 0) return;

  // Check if workspace DB already has data (don't overwrite)
  if (fs.existsSync(workspaceDbPath)) {
    try {
      const db = openReadonlyDb(workspaceDbPath);
      const row = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='projects'").get();
      if (row) {
        const count = (db.prepare('SELECT COUNT(*) as c FROM projects').get() as { c: number }).c;
        db.close();
        if (count > 0) return; // Workspace already has data, skip
      } else {
        db.close();
      }
    } catch { /* workspace DB doesn't exist or is corrupt — proceed with copy */ }
  }

  try {
    fs.mkdirSync(workspaceDir, { recursive: true });

    // Copy the legacy database (overwrites the empty one if it exists)
    fs.copyFileSync(legacyDbPath, workspaceDbPath);

    // Copy WAL/SHM files if they exist
    for (const ext of ['-wal', '-shm']) {
      const walPath = legacyDbPath + ext;
      if (fs.existsSync(walPath)) {
        fs.copyFileSync(walPath, workspaceDbPath + ext);
      }
    }

    // Copy project databases (data/projects/ -> data/workspaces/{id}/projects/)
    const legacyProjectsDir = path.join(dataDir, 'projects');
    if (fs.existsSync(legacyProjectsDir)) {
      const workspaceProjectsDir = path.join(workspaceDir, 'projects');
      copyDirRecursive(legacyProjectsDir, workspaceProjectsDir);
    }
  } catch (err) {
    logger.error('[DefaultWorkspace] Failed to migrate legacy data:', err);
  }
}

function copyDirRecursive(src: string, dest: string): void {
  if (!fs.existsSync(src)) return;
  fs.mkdirSync(dest, { recursive: true });

  const entries = fs.readdirSync(src, { withFileTypes: true });
  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      copyDirRecursive(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

// ---------------------------------------------------------------------------
// Repair / Heal
// ---------------------------------------------------------------------------

export interface RepairResult {
  legacyDbMigrated: boolean;
  legacyProjectsMigrated: number;
  deploymentRoutesCreated: number;
  errors: string[];
}

/**
 * Repair a workspace by detecting and fixing common issues:
 * 1. Legacy data/osws.sqlite not migrated to workspace
 * 2. Project databases in data/projects/ not copied to workspace
 * 3. Deployments in workspace DB but missing from deployment_routing
 *
 * Safe to run multiple times — skips already-fixed items.
 */
export function repairWorkspace(workspaceId: string): RepairResult {
  const dataDir = getDataDir();
  const workspaceDir = path.join(dataDir, 'workspaces', workspaceId);
  const workspaceDbPath = path.join(workspaceDir, 'osws.sqlite');
  const legacyDbPath = path.join(dataDir, 'osws.sqlite');
  const result: RepairResult = {
    legacyDbMigrated: false,
    legacyProjectsMigrated: 0,
    deploymentRoutesCreated: 0,
    errors: [],
  };

  // 1. If workspace DB is empty/missing but legacy DB has data, copy it
  if (fs.existsSync(legacyDbPath)) {
    const legacyHasData = (() => {
      try {
        const db = openReadonlyDb(legacyDbPath);
        const tableExists = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='projects'").get();
        if (!tableExists) { db.close(); return false; }
        const count = (db.prepare('SELECT COUNT(*) as count FROM projects').get() as { count: number }).count;
        db.close();
        return count > 0;
      } catch { return false; }
    })();

    if (legacyHasData) {
      const workspaceHasData = (() => {
        if (!fs.existsSync(workspaceDbPath)) return false;
        try {
          const db = openReadonlyDb(workspaceDbPath);
          const tableExists = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='projects'").get();
          if (!tableExists) { db.close(); return false; }
          const count = (db.prepare('SELECT COUNT(*) as count FROM projects').get() as { count: number }).count;
          db.close();
          return count > 0;
        } catch { return false; }
      })();

      if (!workspaceHasData) {
        try {
          fs.mkdirSync(workspaceDir, { recursive: true });
          fs.copyFileSync(legacyDbPath, workspaceDbPath);
          for (const ext of ['-wal', '-shm']) {
            const walPath = legacyDbPath + ext;
            if (fs.existsSync(walPath)) {
              fs.copyFileSync(walPath, workspaceDbPath + ext);
            }
          }
          result.legacyDbMigrated = true;
        } catch (err) {
          result.errors.push(`Failed to copy legacy DB: ${err}`);
        }
      }
    }
  }

  // 2. Copy orphaned project databases from data/projects/ to workspace
  const legacyProjectsDir = path.join(dataDir, 'projects');
  const workspaceProjectsDir = path.join(workspaceDir, 'projects');
  if (fs.existsSync(legacyProjectsDir) && fs.existsSync(workspaceDbPath)) {
    try {
      // Get project IDs from workspace DB
      const db = openReadonlyDb(workspaceDbPath);
      const tableExists = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='projects'").get();
      const projectIds: string[] = [];
      if (tableExists) {
        const rows = db.prepare('SELECT id FROM projects').all() as { id: string }[];
        projectIds.push(...rows.map(r => r.id));
      }
      db.close();

      // For each project in workspace DB, check if its database is in legacy dir but not workspace dir
      for (const projectId of projectIds) {
        const legacyProjectDir = path.join(legacyProjectsDir, projectId);
        const workspaceProjectDir = path.join(workspaceProjectsDir, projectId);
        if (fs.existsSync(legacyProjectDir) && !fs.existsSync(workspaceProjectDir)) {
          copyDirRecursive(legacyProjectDir, workspaceProjectDir);
          result.legacyProjectsMigrated++;
        }
      }
    } catch (err) {
      result.errors.push(`Failed to migrate project databases: ${err}`);
    }
  }

  // 3. Ensure all deployments in workspace DB are registered in deployment_routing
  if (fs.existsSync(workspaceDbPath)) {
    try {
      const db = openReadonlyDb(workspaceDbPath);
      const tableExists = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='deployments'").get();
      if (tableExists) {
        const deployments = db.prepare('SELECT id FROM deployments').all() as { id: string }[];
        db.close();

        const sysDb = getSystemDatabase();
        for (const deployment of deployments) {
          const existing = sysDb.prepare('SELECT deployment_id FROM deployment_routing WHERE deployment_id = ?')
            .get(deployment.id);
          if (!existing) {
            sysDb.prepare(`
              INSERT OR IGNORE INTO deployment_routing (deployment_id, workspace_id)
              VALUES (?, ?)
            `).run(deployment.id, workspaceId);
            result.deploymentRoutesCreated++;
          }
        }
      } else {
        db.close();
      }
    } catch (err) {
      result.errors.push(`Failed to repair deployment routes: ${err}`);
    }
  }

  return result;
}
