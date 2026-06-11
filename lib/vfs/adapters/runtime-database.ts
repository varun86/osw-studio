/**
 * Runtime Database Manager
 *
 * Manages the runtime portion of per-deployment SQLite databases containing:
 * - Deployment info/settings (single row)
 * - Files and file tree nodes
 * - Edge functions and execution logs
 * - Server functions
 * - Secrets (encrypted)
 * - Scheduled functions
 * - User-created tables (DDL execution)
 *
 * Each deployment gets its own runtime database at deployments/{deploymentId}/runtime.sqlite
 */

import type { Database } from 'better-sqlite3';
import { v4 as uuidv4 } from 'uuid';
import { VirtualFile, FileTreeNode, Deployment, EdgeFunction, FunctionLog, TableInfo, ServerFunction, Secret, ScheduledFunction } from '../types';
import { encryptSecret, isEncryptionConfigured } from '../../edge-functions/secrets-crypto';
import { getRuntimeDatabaseConnection, closeRuntimeDatabase } from './sqlite-connection';
import { validateRuntimeSQL, splitSQLStatements, MAX_RESULT_ROWS } from '@/lib/db/sql-validator';

/**
 * Helper to ensure a value is a Date and convert to ISO string
 */
function toISOString(value: Date | string | null | undefined): string | null {
  if (!value) return null;
  if (typeof value === 'string') return value;
  return value.toISOString();
}

/**
 * Helper to ensure a value is a Date and convert to ISO string (non-null)
 */
function toISOStringRequired(value: Date | string): string {
  if (typeof value === 'string') return value;
  return value.toISOString();
}

/**
 * Helper to parse JSON safely with a fallback
 */
function parseJSON<T>(value: string | null | undefined, fallback: T): T {
  if (!value) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

/**
 * Helper to parse Date from ISO string
 */
function parseDate(value: string | null | undefined): Date {
  if (!value) return new Date();
  return new Date(value);
}

/**
 * Per-deployment runtime database manager
 */
export class RuntimeDatabase {
  private db: Database;
  private deploymentId: string;
  private initialized = false;

  constructor(deploymentId: string) {
    this.deploymentId = deploymentId;
    this.db = getRuntimeDatabaseConnection(deploymentId);
  }

  /**
   * Initialize the database schema
   */
  init(): void {
    if (this.initialized) return;

    // Deployment info (single row)
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS site_info (
        id TEXT PRIMARY KEY DEFAULT 'main',
        project_id TEXT NOT NULL,
        name TEXT NOT NULL,
        slug TEXT,
        enabled INTEGER NOT NULL DEFAULT 0,
        under_construction INTEGER NOT NULL DEFAULT 0,
        custom_domain TEXT,
        head_scripts TEXT NOT NULL DEFAULT '[]',
        body_scripts TEXT NOT NULL DEFAULT '[]',
        cdn_links TEXT NOT NULL DEFAULT '[]',
        analytics TEXT NOT NULL DEFAULT '{}',
        seo TEXT NOT NULL DEFAULT '{}',
        compliance TEXT NOT NULL DEFAULT '{}',
        settings_version INTEGER NOT NULL DEFAULT 1,
        last_published_version INTEGER,
        preview_image TEXT,
        preview_updated_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        published_at TEXT
      )
    `);

    // Files
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS files (
        id TEXT PRIMARY KEY,
        path TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        content TEXT,
        mime_type TEXT NOT NULL,
        size INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        metadata TEXT DEFAULT '{}'
      )
    `);

    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_files_path ON files(path)`);

    // File tree nodes
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS file_tree_nodes (
        id TEXT PRIMARY KEY,
        path TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        parent_path TEXT,
        is_expanded INTEGER DEFAULT 0,
        children TEXT DEFAULT '[]',
        metadata TEXT DEFAULT '{}'
      )
    `);

    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_tree_nodes_parent_path ON file_tree_nodes(parent_path)`);

    // Edge Functions
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS edge_functions (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        description TEXT,
        code TEXT NOT NULL,
        method TEXT NOT NULL DEFAULT 'ANY',
        enabled INTEGER NOT NULL DEFAULT 1,
        timeout_ms INTEGER NOT NULL DEFAULT 5000,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )
    `);

    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_edge_functions_name ON edge_functions(name)`);

    // Function Execution Logs
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS function_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        function_id TEXT NOT NULL,
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        status_code INTEGER,
        duration_ms INTEGER,
        error TEXT,
        timestamp TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (function_id) REFERENCES edge_functions(id) ON DELETE CASCADE
      )
    `);

    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_function_logs_function_id ON function_logs(function_id)`);
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_function_logs_timestamp ON function_logs(timestamp)`);

    // Server Functions (callable from edge functions)
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS server_functions (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        description TEXT,
        code TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )
    `);

    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_server_functions_name ON server_functions(name)`);

    // Secrets (encrypted key-value storage)
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS secrets (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        encrypted_value TEXT NOT NULL,
        iv TEXT NOT NULL,
        auth_tag TEXT NOT NULL,
        key_version TEXT,
        description TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )
    `);

    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_secrets_name ON secrets(name)`);

    // Scheduled Functions (cron-triggered edge function execution)
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS scheduled_functions (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        description TEXT,
        function_id TEXT NOT NULL,
        cron_expression TEXT NOT NULL,
        timezone TEXT NOT NULL DEFAULT 'UTC',
        config TEXT NOT NULL DEFAULT '{}',
        enabled INTEGER NOT NULL DEFAULT 1,
        last_run_at TEXT,
        next_run_at TEXT,
        last_status TEXT,
        last_error TEXT,
        last_duration_ms INTEGER,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (function_id) REFERENCES edge_functions(id) ON DELETE CASCADE
      )
    `);

    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_scheduled_functions_name ON scheduled_functions(name)`);
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_scheduled_functions_next_run ON scheduled_functions(next_run_at)`);

    // Schema migrations for existing databases
    this.runMigrations();

    this.initialized = true;
  }

  /**
   * Run schema migrations for existing databases that may be missing newer columns.
   * Uses ALTER TABLE ... ADD COLUMN with IF NOT EXISTS semantics (SQLite ignores
   * duplicate column errors when wrapped in try/catch).
   */
  private runMigrations(): void {
    // Migration 1: Add key_version column to secrets table (for key rotation)
    try {
      this.db.exec(`ALTER TABLE secrets ADD COLUMN key_version TEXT`);
    } catch {
      // Column already exists — ignore
    }
  }

  /**
   * Close the database connection
   */
  close(): void {
    closeRuntimeDatabase(this.deploymentId);
  }

  // ============================================
  // Deployment Info
  // ============================================

  createDeploymentInfo(deployment: Deployment): void {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO site_info (
        id, project_id, name, slug, enabled, under_construction,
        custom_domain, head_scripts, body_scripts, cdn_links,
        analytics, seo, compliance, settings_version,
        last_published_version, preview_image, preview_updated_at,
        created_at, updated_at, published_at
      ) VALUES (
        'main', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
      )
    `);

    stmt.run(
      deployment.projectId,
      deployment.name,
      deployment.slug ?? null,
      deployment.enabled ? 1 : 0,
      deployment.underConstruction ? 1 : 0,
      deployment.customDomain ?? null,
      JSON.stringify(deployment.headScripts ?? []),
      JSON.stringify(deployment.bodyScripts ?? []),
      JSON.stringify(deployment.cdnLinks ?? []),
      JSON.stringify(deployment.analytics ?? {}),
      JSON.stringify(deployment.seo ?? {}),
      JSON.stringify(deployment.compliance ?? {}),
      deployment.settingsVersion ?? 1,
      deployment.lastPublishedVersion ?? null,
      deployment.previewImage ?? null,
      toISOString(deployment.previewUpdatedAt),
      toISOStringRequired(deployment.createdAt),
      toISOStringRequired(deployment.updatedAt),
      toISOString(deployment.publishedAt)
    );
  }

  getDeploymentInfo(): Deployment | null {
    const row = this.db.prepare('SELECT * FROM site_info WHERE id = ?').get('main') as Record<string, unknown> | undefined;

    if (!row) return null;

    return {
      id: this.deploymentId,
      projectId: row.project_id as string,
      name: row.name as string,
      slug: row.slug as string | undefined,
      enabled: Boolean(row.enabled),
      underConstruction: Boolean(row.under_construction),
      customDomain: row.custom_domain as string | undefined,
      headScripts: parseJSON(row.head_scripts as string, []),
      bodyScripts: parseJSON(row.body_scripts as string, []),
      cdnLinks: parseJSON(row.cdn_links as string, []),
      analytics: parseJSON(row.analytics as string, { enabled: false, provider: 'builtin' as const, privacyMode: true }),
      seo: parseJSON(row.seo as string, {}),
      compliance: parseJSON(row.compliance as string, { enabled: false, bannerPosition: 'bottom' as const, bannerStyle: 'bar' as const, message: '', acceptButtonText: 'Accept', declineButtonText: 'Decline', mode: 'opt-in' as const, blockAnalytics: false }),
      settingsVersion: row.settings_version as number,
      lastPublishedVersion: row.last_published_version as number | undefined,
      previewImage: row.preview_image as string | undefined,
      previewUpdatedAt: row.preview_updated_at ? parseDate(row.preview_updated_at as string) : undefined,
      createdAt: parseDate(row.created_at as string),
      updatedAt: parseDate(row.updated_at as string),
      publishedAt: row.published_at ? parseDate(row.published_at as string) : null,
    };
  }

  updateDeploymentInfo(deployment: Partial<Deployment>): void {
    const updates: string[] = [];
    const values: unknown[] = [];

    if (deployment.name !== undefined) { updates.push('name = ?'); values.push(deployment.name); }
    if (deployment.slug !== undefined) { updates.push('slug = ?'); values.push(deployment.slug); }
    if (deployment.enabled !== undefined) { updates.push('enabled = ?'); values.push(deployment.enabled ? 1 : 0); }
    if (deployment.underConstruction !== undefined) { updates.push('under_construction = ?'); values.push(deployment.underConstruction ? 1 : 0); }
    if (deployment.customDomain !== undefined) { updates.push('custom_domain = ?'); values.push(deployment.customDomain); }
    if (deployment.headScripts !== undefined) { updates.push('head_scripts = ?'); values.push(JSON.stringify(deployment.headScripts)); }
    if (deployment.bodyScripts !== undefined) { updates.push('body_scripts = ?'); values.push(JSON.stringify(deployment.bodyScripts)); }
    if (deployment.cdnLinks !== undefined) { updates.push('cdn_links = ?'); values.push(JSON.stringify(deployment.cdnLinks)); }
    if (deployment.analytics !== undefined) { updates.push('analytics = ?'); values.push(JSON.stringify(deployment.analytics)); }
    if (deployment.seo !== undefined) { updates.push('seo = ?'); values.push(JSON.stringify(deployment.seo)); }
    if (deployment.compliance !== undefined) { updates.push('compliance = ?'); values.push(JSON.stringify(deployment.compliance)); }
    if (deployment.settingsVersion !== undefined) { updates.push('settings_version = ?'); values.push(deployment.settingsVersion); }
    if (deployment.lastPublishedVersion !== undefined) { updates.push('last_published_version = ?'); values.push(deployment.lastPublishedVersion); }
    if (deployment.previewImage !== undefined) { updates.push('preview_image = ?'); values.push(deployment.previewImage); }
    if (deployment.previewUpdatedAt !== undefined) { updates.push('preview_updated_at = ?'); values.push(toISOString(deployment.previewUpdatedAt)); }
    if (deployment.updatedAt !== undefined) { updates.push('updated_at = ?'); values.push(toISOStringRequired(deployment.updatedAt)); }
    if (deployment.publishedAt !== undefined) { updates.push('published_at = ?'); values.push(toISOString(deployment.publishedAt)); }

    if (updates.length === 0) return;

    if (!deployment.updatedAt) {
      updates.push('updated_at = ?');
      values.push(new Date().toISOString());
    }

    const sql = `UPDATE site_info SET ${updates.join(', ')} WHERE id = 'main'`;
    this.db.prepare(sql).run(...values);
  }

  // ============================================
  // Files
  // ============================================

  createFile(file: VirtualFile): void {
    const stmt = this.db.prepare(`
      INSERT INTO files (
        id, path, name, type, content, mime_type, size,
        created_at, updated_at, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    let content: string;
    if (file.content instanceof ArrayBuffer) {
      content = Buffer.from(file.content).toString('base64');
    } else if (typeof file.content === 'string') {
      content = file.content;
    } else {
      content = '';
    }

    stmt.run(
      file.id,
      file.path,
      file.name,
      file.type,
      content,
      file.mimeType ?? null,
      file.size ?? 0,
      toISOStringRequired(file.createdAt),
      toISOStringRequired(file.updatedAt),
      JSON.stringify(file.metadata ?? {})
    );
  }

  getFile(path: string): VirtualFile | null {
    const row = this.db.prepare('SELECT * FROM files WHERE path = ?').get(path) as Record<string, unknown> | undefined;

    if (!row) return null;

    return this.rowToFile(row);
  }

  updateFile(file: VirtualFile): void {
    const stmt = this.db.prepare(`
      UPDATE files SET
        name = ?, type = ?, content = ?, mime_type = ?,
        size = ?, updated_at = ?, metadata = ?
      WHERE path = ?
    `);

    let content: string;
    if (file.content instanceof ArrayBuffer) {
      content = Buffer.from(file.content).toString('base64');
    } else if (typeof file.content === 'string') {
      content = file.content;
    } else {
      content = '';
    }

    stmt.run(
      file.name,
      file.type,
      content,
      file.mimeType ?? null,
      file.size ?? 0,
      toISOStringRequired(file.updatedAt),
      JSON.stringify(file.metadata ?? {}),
      file.path
    );
  }

  deleteFile(path: string): void {
    this.db.prepare('DELETE FROM files WHERE path = ?').run(path);
  }

  listFiles(): VirtualFile[] {
    const rows = this.db.prepare('SELECT * FROM files ORDER BY path').all() as Record<string, unknown>[];
    return rows.map(row => this.rowToFile(row));
  }

  deleteAllFiles(): void {
    this.db.prepare('DELETE FROM files').run();
  }

  private rowToFile(row: Record<string, unknown>): VirtualFile {
    const metadata = parseJSON(row.metadata as string, {});
    const type = row.type as VirtualFile['type'];

    let content: string | ArrayBuffer = row.content as string;
    if (type === 'image' || type === 'video' || type === 'binary') {
      try {
        let base64Data = content as string;
        if (base64Data.startsWith('data:')) {
          const commaIndex = base64Data.indexOf(',');
          if (commaIndex !== -1) {
            base64Data = base64Data.slice(commaIndex + 1);
          }
        }
        content = Buffer.from(base64Data, 'base64').buffer;
      } catch {
        // Keep as string if conversion fails
      }
    }

    return {
      id: row.id as string,
      projectId: this.deploymentId,
      path: row.path as string,
      name: row.name as string,
      type,
      content,
      mimeType: row.mime_type as string,
      size: row.size as number,
      createdAt: parseDate(row.created_at as string),
      updatedAt: parseDate(row.updated_at as string),
      metadata,
    };
  }

  // ============================================
  // File Tree Nodes
  // ============================================

  createTreeNode(node: FileTreeNode): void {
    const stmt = this.db.prepare(`
      INSERT INTO file_tree_nodes (id, path, name, type, parent_path, is_expanded, children, metadata)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      node.id,
      node.path,
      node.name,
      node.type,
      node.parentPath,
      node.isExpanded ? 1 : 0,
      JSON.stringify(node.children ?? []),
      JSON.stringify(node.metadata ?? {})
    );
  }

  getTreeNode(path: string): FileTreeNode | null {
    const row = this.db.prepare('SELECT * FROM file_tree_nodes WHERE path = ?').get(path) as Record<string, unknown> | undefined;

    if (!row) return null;

    return this.rowToTreeNode(row);
  }

  updateTreeNode(node: FileTreeNode): void {
    const stmt = this.db.prepare(`
      UPDATE file_tree_nodes SET
        name = ?, type = ?, parent_path = ?, is_expanded = ?, children = ?, metadata = ?
      WHERE path = ?
    `);

    stmt.run(
      node.name,
      node.type,
      node.parentPath,
      node.isExpanded ? 1 : 0,
      JSON.stringify(node.children ?? []),
      JSON.stringify(node.metadata ?? {}),
      node.path
    );
  }

  deleteTreeNode(path: string): void {
    this.db.prepare('DELETE FROM file_tree_nodes WHERE path = ?').run(path);
  }

  getChildNodes(parentPath: string | null): FileTreeNode[] {
    const rows = this.db.prepare(
      'SELECT * FROM file_tree_nodes WHERE parent_path IS ? ORDER BY type DESC, path'
    ).all(parentPath) as Record<string, unknown>[];

    return rows.map(row => this.rowToTreeNode(row));
  }

  getAllTreeNodes(): FileTreeNode[] {
    const rows = this.db.prepare('SELECT * FROM file_tree_nodes ORDER BY path').all() as Record<string, unknown>[];
    return rows.map(row => this.rowToTreeNode(row));
  }

  private rowToTreeNode(row: Record<string, unknown>): FileTreeNode {
    return {
      id: row.id as string,
      projectId: this.deploymentId,
      path: row.path as string,
      name: row.name as string,
      type: row.type as 'file' | 'directory',
      parentPath: row.parent_path as string | null,
      isExpanded: Boolean(row.is_expanded),
      children: parseJSON(row.children as string, []),
      metadata: parseJSON(row.metadata as string, {}),
    };
  }

  // ============================================
  // Edge Functions: CRUD
  // ============================================

  createFunction(fn: Omit<EdgeFunction, 'id' | 'projectId' | 'createdAt' | 'updatedAt'>): string {
    const id = uuidv4();
    const now = new Date().toISOString();

    const stmt = this.db.prepare(`
      INSERT INTO edge_functions (
        id, name, description, code, method, enabled, timeout_ms, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      fn.name,
      fn.description ?? null,
      fn.code,
      fn.method,
      fn.enabled ? 1 : 0,
      fn.timeoutMs,
      now,
      now
    );

    return id;
  }

  getFunction(id: string): EdgeFunction | null {
    const row = this.db.prepare('SELECT * FROM edge_functions WHERE id = ?').get(id) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.rowToFunction(row);
  }

  getFunctionByName(name: string): EdgeFunction | null {
    const row = this.db.prepare('SELECT * FROM edge_functions WHERE name = ?').get(name) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.rowToFunction(row);
  }

  updateFunction(id: string, updates: Partial<Omit<EdgeFunction, 'id' | 'createdAt' | 'updatedAt'>>): void {
    const setClauses: string[] = [];
    const values: unknown[] = [];

    if (updates.name !== undefined) { setClauses.push('name = ?'); values.push(updates.name); }
    if (updates.description !== undefined) { setClauses.push('description = ?'); values.push(updates.description); }
    if (updates.code !== undefined) { setClauses.push('code = ?'); values.push(updates.code); }
    if (updates.method !== undefined) { setClauses.push('method = ?'); values.push(updates.method); }
    if (updates.enabled !== undefined) { setClauses.push('enabled = ?'); values.push(updates.enabled ? 1 : 0); }
    if (updates.timeoutMs !== undefined) { setClauses.push('timeout_ms = ?'); values.push(updates.timeoutMs); }

    if (setClauses.length === 0) return;

    setClauses.push('updated_at = ?');
    values.push(new Date().toISOString());
    values.push(id);

    const sql = `UPDATE edge_functions SET ${setClauses.join(', ')} WHERE id = ?`;
    this.db.prepare(sql).run(...values);
  }

  deleteFunction(id: string): void {
    this.db.prepare('DELETE FROM edge_functions WHERE id = ?').run(id);
  }

  listFunctions(): EdgeFunction[] {
    const rows = this.db.prepare('SELECT * FROM edge_functions ORDER BY name').all() as Record<string, unknown>[];
    return rows.map(row => this.rowToFunction(row));
  }

  private rowToFunction(row: Record<string, unknown>): EdgeFunction {
    return {
      id: row.id as string,
      projectId: '',
      name: row.name as string,
      description: row.description as string | undefined,
      code: row.code as string,
      method: row.method as EdgeFunction['method'],
      enabled: Boolean(row.enabled),
      timeoutMs: row.timeout_ms as number,
      createdAt: parseDate(row.created_at as string),
      updatedAt: parseDate(row.updated_at as string),
    };
  }

  // ============================================
  // Edge Functions: Logging
  // ============================================

  logFunctionExecution(functionId: string, data: {
    method: string;
    path: string;
    statusCode: number;
    durationMs: number;
    error?: string;
  }): void {
    const stmt = this.db.prepare(`
      INSERT INTO function_logs (function_id, method, path, status_code, duration_ms, error)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      functionId,
      data.method,
      data.path,
      data.statusCode,
      data.durationMs,
      data.error ?? null
    );
  }

  getFunctionLogs(functionId: string, limit: number = 100): FunctionLog[] {
    const rows = this.db.prepare(`
      SELECT * FROM function_logs WHERE function_id = ?
      ORDER BY timestamp DESC LIMIT ?
    `).all(functionId, limit) as Record<string, unknown>[];

    return rows.map(row => this.rowToFunctionLog(row));
  }

  getRecentLogs(limit: number = 100): FunctionLog[] {
    const rows = this.db.prepare(`
      SELECT * FROM function_logs ORDER BY timestamp DESC LIMIT ?
    `).all(limit) as Record<string, unknown>[];

    return rows.map(row => this.rowToFunctionLog(row));
  }

  clearFunctionLogs(functionId?: string, beforeDate?: Date): void {
    if (functionId && beforeDate) {
      this.db.prepare('DELETE FROM function_logs WHERE function_id = ? AND timestamp < ?')
        .run(functionId, beforeDate.toISOString());
    } else if (functionId) {
      this.db.prepare('DELETE FROM function_logs WHERE function_id = ?').run(functionId);
    } else if (beforeDate) {
      this.db.prepare('DELETE FROM function_logs WHERE timestamp < ?').run(beforeDate.toISOString());
    } else {
      this.db.prepare('DELETE FROM function_logs').run();
    }
  }

  private rowToFunctionLog(row: Record<string, unknown>): FunctionLog {
    return {
      id: row.id as number,
      functionId: row.function_id as string,
      method: row.method as string,
      path: row.path as string,
      statusCode: row.status_code as number,
      durationMs: row.duration_ms as number,
      error: row.error as string | undefined,
      timestamp: parseDate(row.timestamp as string),
    };
  }

  // ============================================
  // Server Functions: CRUD
  // ============================================

  createServerFunction(fn: Omit<ServerFunction, 'id' | 'projectId' | 'createdAt' | 'updatedAt'>): string {
    const id = uuidv4();
    const now = new Date().toISOString();

    const stmt = this.db.prepare(`
      INSERT INTO server_functions (
        id, name, description, code, enabled, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      fn.name,
      fn.description ?? null,
      fn.code,
      fn.enabled ? 1 : 0,
      now,
      now
    );

    return id;
  }

  getServerFunction(id: string): ServerFunction | null {
    const row = this.db.prepare('SELECT * FROM server_functions WHERE id = ?').get(id) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.rowToServerFunction(row);
  }

  getServerFunctionByName(name: string): ServerFunction | null {
    const row = this.db.prepare('SELECT * FROM server_functions WHERE name = ?').get(name) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.rowToServerFunction(row);
  }

  updateServerFunction(id: string, updates: Partial<Omit<ServerFunction, 'id' | 'createdAt' | 'updatedAt'>>): void {
    const setClauses: string[] = [];
    const values: unknown[] = [];

    if (updates.name !== undefined) { setClauses.push('name = ?'); values.push(updates.name); }
    if (updates.description !== undefined) { setClauses.push('description = ?'); values.push(updates.description); }
    if (updates.code !== undefined) { setClauses.push('code = ?'); values.push(updates.code); }
    if (updates.enabled !== undefined) { setClauses.push('enabled = ?'); values.push(updates.enabled ? 1 : 0); }

    if (setClauses.length === 0) return;

    setClauses.push('updated_at = ?');
    values.push(new Date().toISOString());
    values.push(id);

    const sql = `UPDATE server_functions SET ${setClauses.join(', ')} WHERE id = ?`;
    this.db.prepare(sql).run(...values);
  }

  deleteServerFunction(id: string): void {
    this.db.prepare('DELETE FROM server_functions WHERE id = ?').run(id);
  }

  listServerFunctions(): ServerFunction[] {
    const rows = this.db.prepare('SELECT * FROM server_functions ORDER BY name').all() as Record<string, unknown>[];
    return rows.map(row => this.rowToServerFunction(row));
  }

  private rowToServerFunction(row: Record<string, unknown>): ServerFunction {
    return {
      id: row.id as string,
      projectId: '',
      name: row.name as string,
      description: row.description as string | undefined,
      code: row.code as string,
      enabled: Boolean(row.enabled),
      createdAt: parseDate(row.created_at as string),
      updatedAt: parseDate(row.updated_at as string),
    };
  }

  // ============================================
  // Secrets Management
  // ============================================

  createSecret(name: string, value: string, description?: string): string {
    if (!isEncryptionConfigured()) {
      throw new Error('Secrets encryption not configured. Set SECRETS_ENCRYPTION_KEY environment variable.');
    }

    const id = uuidv4();
    const now = new Date().toISOString();
    const encrypted = encryptSecret(value);

    this.db.prepare(`
      INSERT INTO secrets (id, name, encrypted_value, iv, auth_tag, key_version, description, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, name, encrypted.encryptedValue, encrypted.iv, encrypted.authTag, encrypted.keyVersion || null, description || null, now, now);

    return id;
  }

  getSecret(id: string): Secret | null {
    const row = this.db.prepare('SELECT * FROM secrets WHERE id = ?').get(id) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.rowToSecret(row);
  }

  getSecretByName(name: string): Secret | null {
    const row = this.db.prepare('SELECT * FROM secrets WHERE name = ?').get(name) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.rowToSecret(row);
  }

  updateSecretValue(id: string, value: string): void {
    if (!isEncryptionConfigured()) {
      throw new Error('Secrets encryption not configured. Set SECRETS_ENCRYPTION_KEY environment variable.');
    }

    const now = new Date().toISOString();
    const encrypted = encryptSecret(value);

    this.db.prepare(`
      UPDATE secrets
      SET encrypted_value = ?, iv = ?, auth_tag = ?, key_version = ?, updated_at = ?
      WHERE id = ?
    `).run(encrypted.encryptedValue, encrypted.iv, encrypted.authTag, encrypted.keyVersion || null, now, id);
  }

  updateSecretMetadata(id: string, updates: { name?: string; description?: string }): void {
    const now = new Date().toISOString();

    if (updates.name !== undefined) {
      this.db.prepare('UPDATE secrets SET name = ?, updated_at = ? WHERE id = ?')
        .run(updates.name, now, id);
    }

    if (updates.description !== undefined) {
      this.db.prepare('UPDATE secrets SET description = ?, updated_at = ? WHERE id = ?')
        .run(updates.description, now, id);
    }
  }

  deleteSecret(id: string): void {
    this.db.prepare('DELETE FROM secrets WHERE id = ?').run(id);
  }

  listSecrets(): Secret[] {
    const rows = this.db.prepare('SELECT * FROM secrets ORDER BY name').all() as Record<string, unknown>[];
    return rows.map(row => this.rowToSecret(row));
  }

  listSecretsWithValues(): Array<{
    name: string;
    encryptedValue: string;
    iv: string;
    authTag: string;
    keyVersion?: string;
  }> {
    const rows = this.db.prepare('SELECT name, encrypted_value, iv, auth_tag, key_version FROM secrets').all() as Record<string, unknown>[];
    return rows.map(row => ({
      name: row.name as string,
      encryptedValue: row.encrypted_value as string,
      iv: row.iv as string,
      authTag: row.auth_tag as string,
      keyVersion: (row.key_version as string) || undefined,
    }));
  }

  private rowToSecret(row: Record<string, unknown>): Secret {
    return {
      id: row.id as string,
      projectId: '',
      name: row.name as string,
      description: row.description as string | undefined,
      hasValue: row.encrypted_value !== null && row.encrypted_value !== '',
      createdAt: parseDate(row.created_at as string),
      updatedAt: parseDate(row.updated_at as string),
    };
  }

  createSecretPlaceholder(name: string, description?: string): string {
    const id = uuidv4();
    const now = new Date().toISOString();

    this.db.prepare(`
      INSERT INTO secrets (id, name, encrypted_value, iv, auth_tag, description, created_at, updated_at)
      VALUES (?, ?, '', '', '', ?, ?, ?)
    `).run(id, name, description || null, now, now);

    return id;
  }

  // ============================================
  // Scheduled Functions: CRUD
  // ============================================

  createScheduledFunction(fn: Omit<ScheduledFunction, 'id' | 'projectId' | 'createdAt' | 'updatedAt'>): string {
    const id = uuidv4();
    const now = new Date().toISOString();

    const stmt = this.db.prepare(`
      INSERT INTO scheduled_functions (
        id, name, description, function_id, cron_expression, timezone,
        config, enabled, last_run_at, next_run_at, last_status, last_error,
        last_duration_ms, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      fn.name,
      fn.description ?? null,
      fn.functionId,
      fn.cronExpression,
      fn.timezone || 'UTC',
      JSON.stringify(fn.config || {}),
      fn.enabled ? 1 : 0,
      toISOString(fn.lastRunAt),
      toISOString(fn.nextRunAt),
      fn.lastStatus ?? null,
      fn.lastError ?? null,
      fn.lastDurationMs ?? null,
      now,
      now
    );

    return id;
  }

  getScheduledFunction(id: string): ScheduledFunction | null {
    const row = this.db.prepare('SELECT * FROM scheduled_functions WHERE id = ?').get(id) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.rowToScheduledFunction(row);
  }

  getScheduledFunctionByName(name: string): ScheduledFunction | null {
    const row = this.db.prepare('SELECT * FROM scheduled_functions WHERE name = ?').get(name) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.rowToScheduledFunction(row);
  }

  updateScheduledFunction(id: string, updates: Partial<Omit<ScheduledFunction, 'id' | 'createdAt' | 'updatedAt'>>): void {
    const setClauses: string[] = [];
    const values: unknown[] = [];

    if (updates.name !== undefined) { setClauses.push('name = ?'); values.push(updates.name); }
    if (updates.description !== undefined) { setClauses.push('description = ?'); values.push(updates.description); }
    if (updates.functionId !== undefined) { setClauses.push('function_id = ?'); values.push(updates.functionId); }
    if (updates.cronExpression !== undefined) { setClauses.push('cron_expression = ?'); values.push(updates.cronExpression); }
    if (updates.timezone !== undefined) { setClauses.push('timezone = ?'); values.push(updates.timezone); }
    if (updates.config !== undefined) { setClauses.push('config = ?'); values.push(JSON.stringify(updates.config)); }
    if (updates.enabled !== undefined) { setClauses.push('enabled = ?'); values.push(updates.enabled ? 1 : 0); }
    if (updates.lastRunAt !== undefined) { setClauses.push('last_run_at = ?'); values.push(toISOString(updates.lastRunAt)); }
    if (updates.nextRunAt !== undefined) { setClauses.push('next_run_at = ?'); values.push(toISOString(updates.nextRunAt)); }
    if (updates.lastStatus !== undefined) { setClauses.push('last_status = ?'); values.push(updates.lastStatus); }
    if (updates.lastError !== undefined) { setClauses.push('last_error = ?'); values.push(updates.lastError); }
    if (updates.lastDurationMs !== undefined) { setClauses.push('last_duration_ms = ?'); values.push(updates.lastDurationMs); }

    if (setClauses.length === 0) return;

    setClauses.push('updated_at = ?');
    values.push(new Date().toISOString());
    values.push(id);

    const sql = `UPDATE scheduled_functions SET ${setClauses.join(', ')} WHERE id = ?`;
    this.db.prepare(sql).run(...values);
  }

  deleteScheduledFunction(id: string): void {
    this.db.prepare('DELETE FROM scheduled_functions WHERE id = ?').run(id);
  }

  listScheduledFunctions(): ScheduledFunction[] {
    const rows = this.db.prepare('SELECT * FROM scheduled_functions ORDER BY name').all() as Record<string, unknown>[];
    return rows.map(row => this.rowToScheduledFunction(row));
  }

  listDueScheduledFunctions(): ScheduledFunction[] {
    const rows = this.db.prepare(
      `SELECT * FROM scheduled_functions WHERE enabled = 1 AND next_run_at IS NOT NULL AND next_run_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`
    ).all() as Record<string, unknown>[];
    return rows.map(row => this.rowToScheduledFunction(row));
  }

  private rowToScheduledFunction(row: Record<string, unknown>): ScheduledFunction {
    return {
      id: row.id as string,
      projectId: '',
      name: row.name as string,
      description: row.description as string | undefined,
      functionId: row.function_id as string,
      cronExpression: row.cron_expression as string,
      timezone: row.timezone as string,
      config: parseJSON(row.config as string, {}),
      enabled: Boolean(row.enabled),
      lastRunAt: row.last_run_at ? parseDate(row.last_run_at as string) : undefined,
      nextRunAt: row.next_run_at ? parseDate(row.next_run_at as string) : undefined,
      lastStatus: row.last_status as ScheduledFunction['lastStatus'],
      lastError: row.last_error as string | undefined,
      lastDurationMs: row.last_duration_ms as number | undefined,
      createdAt: parseDate(row.created_at as string),
      updatedAt: parseDate(row.updated_at as string),
    };
  }

  // ============================================
  // DDL Execution
  // ============================================

  executeDDL(sql: string): void {
    // 1. Split the SQL into individual statements using the centralized splitter
    const statements = splitSQLStatements(sql);
    if (statements.length === 0) {
      throw new Error('RuntimeDB.executeDDL: Empty SQL query');
    }

    // 2. Validate each statement individually through the centralized validator
    //    This prevents injecting unvalidated SQL by hiding it after a semicolon
    const validatedStatements: string[] = [];
    for (const stmt of statements) {
      const validation = validateRuntimeSQL(stmt, { allowDDL: true, context: 'RuntimeDB.executeDDL' });
      if (!validation.valid) {
        throw new Error(validation.error);
      }
      validatedStatements.push(stmt);
    }

    // 3. Execute each validated statement individually
    for (const stmt of validatedStatements) {
      this.db.exec(stmt);
    }
  }

  // ============================================
  // Schema Management & Raw SQL
  // ============================================

  private static readonly SYSTEM_TABLES = [
    'site_info',
    'files',
    'file_tree_nodes',
    'edge_functions',
    'function_logs',
    'server_functions',
    'secrets',
    'scheduled_functions',
  ];

  executeRawSQL(sql: string, params?: unknown[]): {
    columns: string[];
    rows: unknown[][];
    rowsAffected: number;
  } {
    // Use centralized validator (replaces weak BLOCKED_PATTERNS regex)
    const validation = validateRuntimeSQL(sql, { context: 'RuntimeDB.executeRawSQL' });
    if (!validation.valid) {
      throw new Error(validation.error);
    }

    const trimmedSql = sql.trim().toLowerCase();
    const isSelect = validation.statementType === 'SELECT';

    if (isSelect) {
      const stmt = this.db.prepare(sql);
      const rows = params ? stmt.all(...params) : stmt.all();

      if (rows.length === 0) {
        return { columns: [], rows: [], rowsAffected: 0 };
      }

      // Enforce row limit to prevent memory exhaustion
      const limitedRows = (rows as unknown[]).slice(0, MAX_RESULT_ROWS);
      const columns = Object.keys(rows[0] as Record<string, unknown>);
      const rowsArray = limitedRows.map(row => columns.map(col => (row as Record<string, unknown>)[col]));

      return { columns, rows: rowsArray, rowsAffected: 0 };
    } else {
      const stmt = this.db.prepare(sql);
      const result = params ? stmt.run(...params) : stmt.run();

      return {
        columns: [],
        rows: [],
        rowsAffected: result.changes,
      };
    }
  }

  getTableSchema(): TableInfo[] {
    const tables = this.db.prepare(`
      SELECT name FROM sqlite_master
      WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
      ORDER BY name
    `).all() as Array<{ name: string }>;

    return tables.flatMap(table => {
      if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(table.name)) return [];

      const isSystemTable = RuntimeDatabase.SYSTEM_TABLES.includes(table.name);

      const columns = this.db.prepare(`PRAGMA table_info('${table.name}')`).all() as Array<{
        cid: number;
        name: string;
        type: string;
        notnull: number;
        dflt_value: string | null;
        pk: number;
      }>;

      const countResult = this.db.prepare(`SELECT COUNT(*) as count FROM "${table.name}"`).get() as { count: number };

      return {
        name: table.name,
        columns: columns.map(col => ({
          name: col.name,
          type: col.type,
          nullable: !col.notnull,
          primaryKey: col.pk > 0,
          defaultValue: col.dflt_value ?? undefined,
        })),
        rowCount: countResult.count,
        isSystemTable,
      };
    });
  }

  getTableData(tableName: string, limit: number = 100, offset: number = 0): {
    columns: string[];
    rows: unknown[][];
    total: number;
  } {
    const validTables = this.db.prepare(`
      SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?
    `).get(tableName);

    if (!validTables) {
      throw new Error(`Table "${tableName}" does not exist`);
    }

    const countResult = this.db.prepare(`SELECT COUNT(*) as count FROM "${tableName}"`).get() as { count: number };

    const rows = this.db.prepare(`SELECT * FROM "${tableName}" LIMIT ? OFFSET ?`).all(limit, offset) as Record<string, unknown>[];

    if (rows.length === 0) {
      return { columns: [], rows: [], total: countResult.count };
    }

    const columns = Object.keys(rows[0]);
    const rowsArray = rows.map(row => columns.map(col => row[col]));

    return {
      columns,
      rows: rowsArray,
      total: countResult.count,
    };
  }

  isSystemTable(tableName: string): boolean {
    return RuntimeDatabase.SYSTEM_TABLES.includes(tableName);
  }

  executeUserQuery(sql: string, params?: unknown[]): {
    columns: string[];
    rows: unknown[][];
    rowsAffected: number;
    error?: string;
  } {
    // Use centralized validator (replaces weak validateNotSystemTable regex)
    // This catches CTEs, subqueries, JOINs, and multi-table references
    // that the old regex-based approach missed
    const validation = validateRuntimeSQL(sql, { context: 'RuntimeDB.executeUserQuery' });
    if (!validation.valid) {
      return {
        columns: [],
        rows: [],
        rowsAffected: 0,
        error: validation.error,
      };
    }

    try {
      return this.executeRawSQL(sql, params);
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : String(e);
      return {
        columns: [],
        rows: [],
        rowsAffected: 0,
        error: message,
      };
    }
  }

  /**
   * @deprecated Use validateRuntimeSQL from @/lib/db/sql-validator instead.
   * Kept for backward compatibility but now delegates to the centralized validator.
   */
  private validateNotSystemTable(upperSql: string): string | null {
    // Delegate to centralized validator for consistency
    const validation = validateRuntimeSQL(upperSql, { context: 'RuntimeDB.validateNotSystemTable' });
    if (!validation.valid) {
      return validation.error ?? 'System table access denied';
    }
    return null;
  }

  getSchemaForExport(): string {
    const tables = this.getTableSchema();
    const userTables = tables.filter(t => !t.isSystemTable);

    if (userTables.length === 0) {
      return '-- No user tables defined\n-- Create tables using the SQL Editor or edge functions\n';
    }

    let sql = '-- Database Schema\n';
    sql += `-- ${userTables.length} user table(s)\n\n`;

    for (const table of userTables) {
      sql += `-- Table: ${table.name} (${table.rowCount} rows)\n`;
      sql += `CREATE TABLE ${table.name} (\n`;
      sql += table.columns.map(col => {
        let def = `  ${col.name} ${col.type}`;
        if (col.primaryKey) def += ' PRIMARY KEY';
        if (!col.nullable) def += ' NOT NULL';
        if (col.defaultValue !== undefined) def += ` DEFAULT ${col.defaultValue}`;
        return def;
      }).join(',\n');
      sql += '\n);\n\n';
    }

    return sql;
  }
}
