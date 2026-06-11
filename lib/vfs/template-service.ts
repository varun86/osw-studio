import { v4 as uuidv4 } from 'uuid';
import JSZip from 'jszip';
import { CustomTemplate, BackendFeatures, EdgeFunction, ServerFunction, Secret } from './types';
import { StorageAdapter } from './adapters/types';
import { logger } from '@/lib/utils';
import { validateZipEntries, extractZipEntryInfo } from '@/lib/security/zip-bomb-protection';

const MAX_TEMPLATE_SIZE = 25 * 1024 * 1024; // 25MB
const MAX_THUMBNAIL_SIZE = 500 * 1024; // 500KB
const MAX_PREVIEW_IMAGE_SIZE = 1024 * 1024; // 1MB
const MAX_PREVIEW_IMAGES = 5;

export interface TemplateMetadata {
  name: string;
  description: string;
  version: string;
  author?: string;
  authorUrl?: string;
  license: string;
  licenseLabel?: string;
  licenseDescription?: string;
  tags?: string[];
  thumbnail?: string;
  previewImages?: string[];
  downloadUrl?: string;
}

export class TemplateService {
  private adapter: StorageAdapter | null = null;
  private initPromise: Promise<void> | null = null;

  private async doInit(): Promise<void> {
    if (this.adapter) return;
    const { vfs } = await import('./index');
    await vfs.init();
    this.adapter = vfs.getStorageAdapter();
  }

  async init(): Promise<void> {
    if (!this.initPromise) {
      this.initPromise = this.doInit();
    }
    return this.initPromise;
  }

  private getAdapter(): StorageAdapter {
    if (!this.adapter) {
      throw new Error('TemplateService not initialized. Call init() first.');
    }
    return this.adapter;
  }

  /**
   * Export a project as a template (.oswt file)
   */
  async exportProjectAsTemplate(
    vfs: any,
    projectId: string,
    metadata: TemplateMetadata
  ): Promise<Blob> {
    try {
      logger.info('[TemplateService] Exporting project as template', { projectId, name: metadata.name });

      // Validate metadata
      this.validateMetadata(metadata);

      // Get project runtime setting
      const project = await vfs.getProject(projectId);
      const runtime = project?.settings?.runtime;

      // Get all files and directories from the project
      const items = await vfs.getAllFilesAndDirectories(projectId);

      // Separate files and directories
      const files = items.filter((item: any) => item.type !== 'directory');
      const directories = items
        .filter((item: any) => item.type === 'directory')
        .map((item: any) => item.path);

      // Extract backend features from project IndexedDB stores
      let backendFeatures: BackendFeatures | undefined;
      try {
        const adapter = vfs.getStorageAdapter();
        const edgeFunctions = adapter.listEdgeFunctions ? await adapter.listEdgeFunctions(projectId) : [];
        const serverFunctions = adapter.listServerFunctions ? await adapter.listServerFunctions(projectId) : [];
        const secrets = adapter.listSecrets ? await adapter.listSecrets(projectId) : [];

        if (edgeFunctions.length > 0 || serverFunctions.length > 0 || secrets.length > 0) {
          backendFeatures = {
            edgeFunctions: edgeFunctions.length > 0 ? edgeFunctions.map((fn: EdgeFunction) => ({
              name: fn.name,
              method: fn.method,
              code: fn.code,
              description: fn.description,
              enabled: fn.enabled,
              timeoutMs: fn.timeoutMs,
            })) : undefined,
            serverFunctions: serverFunctions.length > 0 ? serverFunctions.map((fn: ServerFunction) => ({
              name: fn.name,
              code: fn.code,
              description: fn.description,
              enabled: fn.enabled,
            })) : undefined,
            secrets: secrets.length > 0 ? secrets.map((s: Secret) => ({
              name: s.name,
              description: s.description,
            })) : undefined,
          };
        }
      } catch {
        logger.warn('[TemplateService] Could not extract backend features from project stores');
      }

      // Create template data
      const templateData = {
        version: backendFeatures ? '2.0.0' : '1.0.0', // Template format version
        name: metadata.name,
        description: metadata.description,
        templateVersion: metadata.version,
        author: metadata.author,
        authorUrl: metadata.authorUrl,
        license: metadata.license,
        licenseLabel: metadata.licenseLabel,
        licenseDescription: metadata.licenseDescription,
        tags: metadata.tags || [],
        thumbnail: metadata.thumbnail,
        previewImages: metadata.previewImages || [],
        downloadUrl: metadata.downloadUrl,
        runtime,
        directories,
        files: files.map((file: any) => ({
          path: file.path,
          content: file.content
        })),
        assets: [],
        backendFeatures,
      };

      // Create ZIP archive
      const zip = new JSZip();
      zip.file('template.json', JSON.stringify(templateData, null, 2));

      const blob = await zip.generateAsync({
        type: 'blob',
        compression: 'DEFLATE',
        compressionOptions: { level: 6 }
      });

      logger.info('[TemplateService] Template exported successfully', {
        name: metadata.name,
        size: blob.size
      });

      return blob;
    } catch (error) {
      logger.error('[TemplateService] Failed to export template:', error);
      throw new Error(`Failed to export template: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Save a project as a custom template directly to IndexedDB (no file download)
   */
  async saveProjectAsTemplate(
    vfs: any,
    projectId: string,
    metadata: TemplateMetadata
  ): Promise<CustomTemplate> {
    try {
      logger.info('[TemplateService] Saving project as template', { projectId, name: metadata.name });

      this.validateMetadata(metadata);

      const project = await vfs.getProject(projectId);
      const runtime = project?.settings?.runtime;

      const items = await vfs.getAllFilesAndDirectories(projectId);
      const files = items.filter((item: any) => item.type !== 'directory');
      const directories = items
        .filter((item: any) => item.type === 'directory')
        .map((item: any) => item.path);

      let backendFeatures: BackendFeatures | undefined;
      try {
        const adapter = vfs.getStorageAdapter();
        const edgeFunctions = adapter.listEdgeFunctions ? await adapter.listEdgeFunctions(projectId) : [];
        const serverFunctions = adapter.listServerFunctions ? await adapter.listServerFunctions(projectId) : [];
        const secrets = adapter.listSecrets ? await adapter.listSecrets(projectId) : [];

        if (edgeFunctions.length > 0 || serverFunctions.length > 0 || secrets.length > 0) {
          backendFeatures = {
            edgeFunctions: edgeFunctions.length > 0 ? edgeFunctions.map((fn: EdgeFunction) => ({
              name: fn.name, method: fn.method, code: fn.code,
              description: fn.description, enabled: fn.enabled, timeoutMs: fn.timeoutMs,
            })) : undefined,
            serverFunctions: serverFunctions.length > 0 ? serverFunctions.map((fn: ServerFunction) => ({
              name: fn.name, code: fn.code, description: fn.description, enabled: fn.enabled,
            })) : undefined,
            secrets: secrets.length > 0 ? secrets.map((s: Secret) => ({
              name: s.name, description: s.description,
            })) : undefined,
          };
        }
      } catch {
        logger.warn('[TemplateService] Could not extract backend features from project stores');
      }

      const template: CustomTemplate = {
        id: uuidv4(),
        name: metadata.name,
        description: metadata.description,
        version: metadata.version || '1.0.0',
        files: files.map((file: any) => ({ path: file.path, content: file.content })),
        directories,
        assets: [],
        metadata: {
          author: metadata.author,
          authorUrl: metadata.authorUrl,
          license: metadata.license,
          licenseLabel: metadata.licenseLabel,
          licenseDescription: metadata.licenseDescription,
          tags: metadata.tags || [],
          thumbnail: metadata.thumbnail,
          previewImages: metadata.previewImages || [],
          downloadUrl: metadata.downloadUrl,
        },
        runtime,
        importedAt: new Date(),
        backendFeatures,
      };

      await this.init();
      await this.getAdapter().saveCustomTemplate(template);

      // Background sync to server
      import('./auto-sync').then(({ autoSyncTemplate }) => autoSyncTemplate(template)).catch(() => {});

      logger.info('[TemplateService] Template saved successfully', { id: template.id, name: template.name });

      return template;
    } catch (error) {
      logger.error('[TemplateService] Failed to save template:', error);
      throw new Error(`Failed to save template: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Import a template file (.oswt)
   */
  async importTemplateFile(file: File): Promise<CustomTemplate> {
    try {
      logger.info('[TemplateService] Importing template file', { name: file.name, size: file.size });

      // Validate file
      if (!file.name.endsWith('.oswt')) {
        throw new Error('Invalid file type. Expected .oswt file.');
      }

      if (file.size > MAX_TEMPLATE_SIZE) {
        throw new Error(`File too large. Maximum size is ${Math.round(MAX_TEMPLATE_SIZE / 1024 / 1024)}MB.`);
      }

      // Read ZIP file
      const zip = new JSZip();
      const zipData = await zip.loadAsync(file);

      // ZIP bomb protection: check entry sizes before extracting content
      const entries = extractZipEntryInfo(zipData);
      validateZipEntries(entries);

      const templateFile = zipData.file('template.json');

      if (!templateFile) {
        throw new Error('Invalid template file format. Missing template.json.');
      }

      // Parse template data
      const templateJson = await templateFile.async('string');
      const templateData = this.safeJsonParse(templateJson);

      // Validate template structure
      this.validateTemplateStructure(templateData);

      // SECURITY: Validate file paths in template data
      this.validateTemplateFilePaths(templateData);

      // Create CustomTemplate object
      const template: CustomTemplate = {
        id: uuidv4(),
        name: templateData.name,
        description: templateData.description,
        version: templateData.templateVersion || '1.0.0',
        files: templateData.files || [],
        directories: templateData.directories || [],
        assets: templateData.assets,
        metadata: {
          author: templateData.author,
          authorUrl: templateData.authorUrl,
          license: templateData.license || 'personal',
          licenseLabel: templateData.licenseLabel,
          licenseDescription: templateData.licenseDescription,
          tags: templateData.tags || [],
          thumbnail: templateData.thumbnail,
          previewImages: templateData.previewImages || [],
          downloadUrl: templateData.downloadUrl
        },
        runtime: templateData.runtime,
        importedAt: new Date(),
        backendFeatures: templateData.backendFeatures || templateData.serverFeatures,
      };

      // Save to IndexedDB
      await this.init();
      await this.getAdapter().saveCustomTemplate(template);

      // Background sync to server
      import('./auto-sync').then(({ autoSyncTemplate }) => autoSyncTemplate(template)).catch(() => {});

      logger.info('[TemplateService] Template imported successfully', {
        id: template.id,
        name: template.name
      });

      return template;
    } catch (error) {
      logger.error('[TemplateService] Failed to import template:', error);
      throw new Error(`Failed to import template: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * List all custom templates
   */
  async listCustomTemplates(): Promise<CustomTemplate[]> {
    try {
      await this.init();
      const templates = await this.getAdapter().getAllCustomTemplates();
      return templates.sort((a, b) => b.importedAt.getTime() - a.importedAt.getTime());
    } catch (error) {
      logger.error('[TemplateService] Failed to list templates:', error);
      throw new Error('Failed to list templates');
    }
  }

  /**
   * Delete a custom template
   */
  async deleteCustomTemplate(id: string): Promise<void> {
    try {
      await this.init();
      await this.getAdapter().deleteCustomTemplate(id);

      // Background sync to server
      import('./auto-sync').then(({ autoDeleteTemplate }) => autoDeleteTemplate(id)).catch(() => {});

      logger.info('[TemplateService] Template deleted', { id });
    } catch (error) {
      logger.error('[TemplateService] Failed to delete template:', error);
      throw new Error('Failed to delete template');
    }
  }

  /**
   * Export a custom template back to .oswt file
   */
  async exportTemplateAsFile(template: CustomTemplate): Promise<Blob> {
    try {
      logger.info('[TemplateService] Re-exporting custom template', { id: template.id, name: template.name });

      const zip = new JSZip();

      // Add template.json
      zip.file('template.json', JSON.stringify(template, null, 2));

      // Add files
      for (const file of template.files) {
        if (file.content instanceof ArrayBuffer) {
          zip.file(file.path, file.content);
        } else {
          zip.file(file.path, file.content);
        }
      }

      return await zip.generateAsync({ type: 'blob' });
    } catch (error) {
      logger.error('[TemplateService] Failed to re-export template:', error);
      throw new Error(`Failed to export template: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Validate template metadata
   */
  private validateMetadata(metadata: TemplateMetadata): void {
    if (!metadata.name || metadata.name.length < 1 || metadata.name.length > 50) {
      throw new Error('Template name must be between 1 and 50 characters');
    }

    if (!metadata.description || metadata.description.length < 10 || metadata.description.length > 500) {
      throw new Error('Template description must be between 10 and 500 characters');
    }

    if (!metadata.version || !/^\d+\.\d+\.\d+$/.test(metadata.version)) {
      throw new Error('Template version must be in semantic version format (e.g., 1.0.0)');
    }

    if (metadata.author && metadata.author.length > 50) {
      throw new Error('Author name must be 50 characters or less');
    }

    if (metadata.authorUrl && !this.isValidUrl(metadata.authorUrl)) {
      throw new Error('Author URL must be a valid URL');
    }

    if (!metadata.license) {
      throw new Error('License is required');
    }

    if (metadata.tags && metadata.tags.length > 10) {
      throw new Error('Maximum 10 tags allowed');
    }

    if (metadata.thumbnail && metadata.thumbnail.length > MAX_THUMBNAIL_SIZE) {
      throw new Error(`Thumbnail too large. Maximum size is ${Math.round(MAX_THUMBNAIL_SIZE / 1024)}KB`);
    }

    if (metadata.previewImages && metadata.previewImages.length > MAX_PREVIEW_IMAGES) {
      throw new Error(`Maximum ${MAX_PREVIEW_IMAGES} preview images allowed`);
    }

    if (metadata.previewImages) {
      for (const img of metadata.previewImages) {
        if (img.length > MAX_PREVIEW_IMAGE_SIZE) {
          throw new Error(`Preview image too large. Maximum size is ${Math.round(MAX_PREVIEW_IMAGE_SIZE / 1024)}KB per image`);
        }
      }
    }
  }

  /**
   * Validate template structure after import
   */
  private validateTemplateStructure(data: any): void {
    if (!data.name || typeof data.name !== 'string') {
      throw new Error('Invalid template: missing or invalid name');
    }

    if (!data.description || typeof data.description !== 'string') {
      throw new Error('Invalid template: missing or invalid description');
    }

    if (!data.files || !Array.isArray(data.files)) {
      throw new Error('Invalid template: missing or invalid files array');
    }

    if (!data.directories || !Array.isArray(data.directories)) {
      throw new Error('Invalid template: missing or invalid directories array');
    }

    // Validate required fields in files
    for (const file of data.files) {
      if (!file.path || typeof file.path !== 'string') {
        throw new Error('Invalid template: file missing path');
      }
      if (file.content === undefined) {
        throw new Error('Invalid template: file missing content');
      }
    }

    // Validate backend features if present (accept legacy "serverFeatures" key too)
    const bf = data.backendFeatures || data.serverFeatures;
    if (bf) {
      if (typeof bf !== 'object') {
        throw new Error('Invalid template: backendFeatures must be an object');
      }
      if (bf.edgeFunctions && !Array.isArray(bf.edgeFunctions)) {
        throw new Error('Invalid template: backendFeatures.edgeFunctions must be an array');
      }
      if (bf.serverFunctions && !Array.isArray(bf.serverFunctions)) {
        throw new Error('Invalid template: backendFeatures.serverFunctions must be an array');
      }
      if (bf.secrets && !Array.isArray(bf.secrets)) {
        throw new Error('Invalid template: backendFeatures.secrets must be an array');
      }
    }
  }

  /**
   * Validate URL format
   */
  private isValidUrl(url: string): boolean {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * SECURITY: Safely parse JSON, preventing prototype pollution.
   * Strips __proto__, constructor, and prototype from parsed objects.
   */
  private safeJsonParse(json: string): any {
    const data = JSON.parse(json);
    return this.sanitizeObject(data);
  }

  /**
   * Recursively strip prototype pollution keys from an object.
   */
  private sanitizeObject(obj: any): any {
    if (obj === null || typeof obj !== 'object') {
      return obj;
    }

    if (Array.isArray(obj)) {
      return obj.map(item => this.sanitizeObject(item));
    }

    const sanitized: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      // Block prototype pollution keys
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        continue;
      }
      sanitized[key] = this.sanitizeObject(value);
    }
    return sanitized;
  }

  /**
   * SECURITY: Validate file paths in template data to prevent:
   * - Path traversal (..)
   * - Server directory access (/.server/)
   * - Disallowed file extensions
   * - Null bytes
   */
  private validateTemplateFilePaths(data: any): void {
    // Allowed file extensions for template files
    const ALLOWED_EXTENSIONS = new Set([
      // Web files
      'html', 'htm', 'css', 'js', 'ts', 'jsx', 'tsx', 'mjs', 'cjs',
      // Data files
      'json', 'yaml', 'yml', 'xml', 'csv', 'toml',
      // Text/Markdown
      'md', 'txt', 'rtf',
      // Config
      'env', 'gitignore', 'dockerignore', 'editorconfig',
      // Images (referenced, not stored as content typically)
      'svg', 'ico', 'webp', 'png', 'jpg', 'jpeg', 'gif',
      // Fonts
      'woff', 'woff2', 'ttf', 'eot',
      // Server-side
      'sql',
    ]);

    // Also allow files with no extension (like Makefile, Dockerfile)
    const ALLOWED_BASENAMES = new Set([
      'Makefile', 'Dockerfile', 'Vagrantfile', 'Gemfile', 'Rakefile',
      'Procfile', '.gitignore', '.env', '.env.local', '.env.production',
      '.eslintrc', '.prettierrc', '.babelrc', '.editorconfig',
    ]);

    if (data.files && Array.isArray(data.files)) {
      for (const file of data.files) {
        const filePath: string = file.path || '';

        // Reject paths with null bytes
        if (filePath.includes('\0')) {
          throw new Error(`Invalid template: file path contains null bytes: ${filePath}`);
        }

        // Reject path traversal
        if (filePath.includes('..')) {
          throw new Error(`Invalid template: file path contains path traversal (..): ${filePath}`);
        }

        // Reject server directory access
        if (filePath.startsWith('/.server/') || filePath.startsWith('.server/')) {
          throw new Error(`Invalid template: file path accesses server directory: ${filePath}`);
        }

        // Validate file extension
        const basename = filePath.split('/').pop() || '';
        const extension = basename.includes('.') ? basename.split('.').pop()!.toLowerCase() : '';

        if (!ALLOWED_BASENAMES.has(basename) && extension && !ALLOWED_EXTENSIONS.has(extension)) {
          throw new Error(`Invalid template: disallowed file extension ".${extension}" for path: ${filePath}`);
        }
      }
    }
  }
}

export const templateService = new TemplateService();
