/**
 * esbuild-wasm Bundler for Component-Framework Projects
 *
 * Lazy-loads esbuild-wasm and bundles TSX/TS/JSX/Svelte/Vue source files into
 * a single bundle.js (+ optional bundle.css). Bare npm imports are rewritten
 * to esm.sh CDN URLs and marked external so the browser fetches them at runtime.
 *
 * Svelte and Vue single-file components are pre-compiled via CDN-loaded
 * compilers before being fed to esbuild.
 *
 * Only loaded when a project contains recognized entry points — existing
 * HTML/CSS/JS projects never trigger this module.
 */

import type { VirtualFile, ProjectRuntime } from '../vfs/types';
import { getRuntimeConfig } from '@/lib/runtimes/registry';
import { validateCdnUrl } from '@/lib/security/cdn-whitelist';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface BundleInput {
  files: VirtualFile[];
  entryPoint: string;
  cdnBase?: string;
  runtime?: ProjectRuntime;
}

export interface BundleOutput {
  js: string;
  css: string | null;
  errors: string[];
  warnings: string[];
}

// ---------------------------------------------------------------------------
// Lazy esbuild singleton
// ---------------------------------------------------------------------------

let esbuildInstance: typeof import('esbuild-wasm') | null = null;
let initPromise: Promise<typeof import('esbuild-wasm')> | null = null;

async function ensureEsbuild(): Promise<typeof import('esbuild-wasm')> {
  if (esbuildInstance) return esbuildInstance;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    try {
      const esbuild = await import('esbuild-wasm');

      if (typeof window !== 'undefined') {
        try {
          await esbuild.initialize({ wasmURL: '/esbuild.wasm' });
        } catch (err: any) {
          // esbuild WASM persists across HMR / module re-evaluations —
          // if it's already initialized, that's fine, just keep going.
          if (!err?.message?.includes('more than once')) throw err;
        }
      }

      esbuildInstance = esbuild;
      return esbuild;
    } catch (err) {
      initPromise = null;
      throw err;
    }
  })();

  return initPromise;
}

// ---------------------------------------------------------------------------
// Entry point detection
// ---------------------------------------------------------------------------

const ENTRY_PRIORITY = [
  '/src/main.tsx',
  '/src/main.ts',
  '/src/index.tsx',
  '/src/index.ts',
  '/src/main.jsx',
  '/src/index.jsx',
  '/src/App.tsx',
  '/src/App.jsx',
  '/main.tsx',
  '/main.ts',
  '/index.tsx',
  '/index.ts',
];

/**
 * Returns the first matching entry point path, or null if the project
 * should use the existing HTML pipeline.
 */
export function detectBundleEntryPoint(files: VirtualFile[]): string | null {
  const paths = new Set(files.map(f => f.path));
  for (const candidate of ENTRY_PRIORITY) {
    if (paths.has(candidate)) return candidate;
  }
  return null;
}

/**
 * Returns true for source file extensions that get compiled into the bundle
 * and should be excluded from direct serving.
 */
export function isBundleableSource(path: string): boolean {
  return /\.(tsx|ts|jsx|svelte|vue)$/.test(path);
}

// ---------------------------------------------------------------------------
// VFS resolver plugin
// ---------------------------------------------------------------------------

const BASE_RESOLVE_EXTENSIONS = [
  '.ts', '.tsx', '.js', '.jsx', '.json', '.css',
  '/index.ts', '/index.tsx', '/index.js', '/index.jsx',
];

function getResolveExtensions(sfcExtension?: string): string[] {
  if (!sfcExtension) return BASE_RESOLVE_EXTENSIONS;
  // SFC extension first so `import Foo from './Foo'` finds Foo.svelte/Foo.vue
  // before Foo.ts in framework projects
  return [sfcExtension, ...BASE_RESOLVE_EXTENSIONS, `/index${sfcExtension}`];
}

function createVfsPlugin(
  fileMap: Map<string, string>,
  cdnBase: string,
  sfcExtension?: string,
) {
  return {
    name: 'vfs-resolver',
    setup(build: import('esbuild-wasm').PluginBuild) {
      // Bare imports → CDN external
      build.onResolve({ filter: /^[^./]/ }, (args) => {
        // Skip esbuild internal or already-resolved
        if (args.path.startsWith('data:') || args.path.startsWith('https://') || args.path.startsWith('http://')) {
          return { external: true };
        }
        return {
          path: `${cdnBase}/${args.path}`,
          external: true,
        };
      });

      // Relative / absolute imports → resolve against VFS
      build.onResolve({ filter: /^[./]/ }, (args) => {
        let resolved = resolvePath(args.resolveDir, args.path);

        // Direct hit
        if (fileMap.has(resolved)) {
          const loader = loaderForPath(resolved);
          return { path: resolved, namespace: 'vfs', pluginData: { loader } };
        }

        // Extension probing
        const extensions = getResolveExtensions(sfcExtension);
        for (const ext of extensions) {
          const candidate = resolved + ext;
          if (fileMap.has(candidate)) {
            const loader = loaderForPath(candidate);
            return { path: candidate, namespace: 'vfs', pluginData: { loader } };
          }
        }

        return { errors: [{ text: `Could not resolve "${args.path}" from "${args.resolveDir}"` }] };
      });

      // Load from VFS
      build.onLoad({ filter: /.*/, namespace: 'vfs' }, (args) => {
        const contents = fileMap.get(args.path);
        if (contents === undefined) {
          return { errors: [{ text: `File not found in VFS: ${args.path}` }] };
        }
        const loader = args.pluginData?.loader || loaderForPath(args.path);
        return {
          contents,
          loader: loader as import('esbuild-wasm').Loader,
          resolveDir: parentDir(args.path),
        };
      });
    },
  };
}

function resolvePath(dir: string, rel: string): string {
  if (rel.startsWith('/')) return rel;

  const parts = dir.split('/').filter(Boolean);
  for (const seg of rel.split('/')) {
    if (seg === '..') parts.pop();
    else if (seg !== '.') parts.push(seg);
  }
  return '/' + parts.join('/');
}

function parentDir(p: string): string {
  const idx = p.lastIndexOf('/');
  return idx > 0 ? p.slice(0, idx) : '/';
}

function loaderForPath(p: string): string {
  const ext = p.split('.').pop()?.toLowerCase();
  switch (ext) {
    case 'tsx': return 'tsx';
    case 'ts': return 'ts';
    case 'jsx': return 'jsx';
    case 'js': case 'mjs': return 'js';
    case 'json': return 'json';
    case 'css': return 'css';
    case 'svelte': return 'js';
    case 'vue': return 'js';
    default: return 'js';
  }
}

// ---------------------------------------------------------------------------
// CDN compiler loading (Svelte, Vue)
// ---------------------------------------------------------------------------

/**
 * Safe dynamic import wrapper with CDN domain whitelist validation.
 *
 * Replaces the previous `new Function('url', 'return import(url)')` pattern
 * which allowed importing from ANY URL — including attacker-controlled domains.
 * Now only URLs from whitelisted CDN domains (esm.sh, cdn.jsdelivr.net) are
 * allowed. See lib/security/cdn-whitelist.ts for the full domain list.
 *
 * We still use Function constructor for the dynamic import bypass (Next.js
 * bundler rewrites bare import() calls), but now with URL validation BEFORE
 * the import is performed.
 */
const safeDynamicImport = new Function('validateCdnUrl', 'url', `
  validateCdnUrl(url);
  return import(url);
`) as (validateCdnUrl: (url: string) => void, url: string) => Promise<any>;

const compilerCache = new Map<string, any>();

async function loadCdnCompiler(url: string): Promise<any> {
  const cached = compilerCache.get(url);
  if (cached) return cached;
  const mod = await safeDynamicImport(validateCdnUrl, url);
  compilerCache.set(url, mod);
  return mod;
}

// ---------------------------------------------------------------------------
// SFC compiler plugins
// ---------------------------------------------------------------------------

/**
 * Strip TypeScript from <script> blocks in a .svelte file.
 *
 * The Svelte CDN compiler does not handle TypeScript natively — we use
 * esbuild's `transform()` (already loaded) to strip type annotations
 * from every <script> block before passing the file to the Svelte compiler.
 */
export async function preprocessSvelteTS(source: string): Promise<string> {
  const esbuild = await ensureEsbuild();

  // Match <script ...> ... </script> blocks (non-greedy)
  const scriptRegex = /(<script\b[^>]*>)([\s\S]*?)(<\/script>)/g;
  const replacements: Array<{ original: string; replacement: string }> = [];

  let match;
  while ((match = scriptRegex.exec(source)) !== null) {
    const openTag = match[1];
    const body = match[2];
    const closeTag = match[3];

    // Only transform TypeScript script blocks — plain JS doesn't need esbuild
    const isTS = /lang\s*=\s*["']ts["']/.test(openTag);
    if (!isTS) continue;

    try {
      // Extract value import lines before transform — esbuild's transform
      // drops imports not referenced in the script body (but they may be used
      // in the Svelte/Vue template). Type-only imports should stay dropped.
      const valueImports = (body.match(/^\s*import\s+.+$/gm) || [])
        .filter(imp => !/^\s*import\s+type\b/.test(imp));

      const transformed = await esbuild.transform(body, {
        loader: 'ts',
        target: 'es2020',
      });

      // Re-inject value imports that esbuild stripped (template-only usage)
      let code = transformed.code;
      for (const imp of valueImports) {
        // Check if the imported identifier is already in the output
        const defaultMatch = imp.match(/import\s+(\w+)/);
        const namedMatch = imp.match(/import\s+\{([^}]+)\}/);
        const ids = [
          ...(defaultMatch ? [defaultMatch[1]] : []),
          ...(namedMatch ? namedMatch[1].split(',').map(s => s.trim().split(/\s+as\s+/).pop()!.trim()) : []),
        ];
        const alreadyPresent = ids.length > 0 && ids.some(id => code.includes(id));
        if (!alreadyPresent) {
          code = imp.trimStart().replace(/;?\s*$/, ';\n') + code;
        }
      }

      // Remove lang="ts" / lang='ts' from the opening tag
      const cleanOpenTag = openTag.replace(/\s+lang\s*=\s*["']ts["']/g, '');
      replacements.push({
        original: match[0],
        replacement: cleanOpenTag + code + closeTag,
      });
    } catch {
      // If esbuild can't transform it, leave as-is — the Svelte compiler
      // will surface the error with better context.
    }
  }

  let result = source;
  for (const { original, replacement } of replacements) {
    result = result.replace(original, replacement);
  }
  return result;
}

function createSveltePlugin(
  fileMap: Map<string, string>,
  compilerUrl: string,
) {
  return {
    name: 'svelte-compiler',
    setup(build: import('esbuild-wasm').PluginBuild) {
      build.onLoad({ filter: /\.svelte$/, namespace: 'vfs' }, async (args) => {
        const contents = fileMap.get(args.path);
        if (contents === undefined) {
          return { errors: [{ text: `File not found in VFS: ${args.path}` }] };
        }

        try {
          // Strip TypeScript from <script> blocks before Svelte compilation
          const preprocessed = await preprocessSvelteTS(contents);

          const compiler = await loadCdnCompiler(compilerUrl);
          const result = compiler.compile(preprocessed, {
            filename: args.path,
            generate: 'client',
            css: 'injected',
          });
          return {
            contents: result.js.code,
            loader: 'js' as import('esbuild-wasm').Loader,
            resolveDir: parentDir(args.path),
          };
        } catch (err: any) {
          return { errors: [{ text: `Svelte compile error in ${args.path}: ${err.message}` }] };
        }
      });
    },
  };
}

function createVuePlugin(
  fileMap: Map<string, string>,
  compilerUrl: string,
  cdnBase: string,
) {
  return {
    name: 'vue-compiler',
    setup(build: import('esbuild-wasm').PluginBuild) {
      build.onLoad({ filter: /\.vue$/, namespace: 'vfs' }, async (args) => {
        const contents = fileMap.get(args.path);
        if (contents === undefined) {
          return { errors: [{ text: `File not found in VFS: ${args.path}` }] };
        }

        try {
          const compiler = await loadCdnCompiler(compilerUrl);
          const id = args.path.replace(/[^a-zA-Z0-9]/g, '_');
          const descriptor = compiler.parse(contents, { filename: args.path });

          // Compile <script setup> or <script>
          let scriptCode = '';
          const scriptBlock = descriptor.descriptor.scriptSetup || descriptor.descriptor.script;
          if (scriptBlock) {
            const compiled = compiler.compileScript(descriptor.descriptor, {
              id,
              inlineTemplate: true,
            });
            scriptCode = compiled.content;

            // Strip TypeScript if <script setup lang="ts"> or <script lang="ts">.
            // The CDN Vue compiler-sfc may leave type annotations in the output
            // (e.g. defineProps<{...}>(), defineEmits<{...}>()) — esbuild chokes
            // on these when loader is 'js'. Use esbuild transform to strip them.
            if (scriptBlock.lang === 'ts') {
              const valueImports = (scriptCode.match(/^\s*import\s+.+$/gm) || [])
                .filter(imp => !/^\s*import\s+type\b/.test(imp));
              const esbuild = await ensureEsbuild();
              const transformed = await esbuild.transform(scriptCode, {
                loader: 'ts',
                target: 'es2020',
              });
              scriptCode = transformed.code;
              for (const imp of valueImports) {
                const defaultMatch = imp.match(/import\s+(\w+)/);
                const namedMatch = imp.match(/import\s+\{([^}]+)\}/);
                const ids = [
                  ...(defaultMatch ? [defaultMatch[1]] : []),
                  ...(namedMatch ? namedMatch[1].split(',').map(s => s.trim().split(/\s+as\s+/).pop()!.trim()) : []),
                ];
                const alreadyPresent = ids.length > 0 && ids.some(id => scriptCode.includes(id));
                if (!alreadyPresent) {
                  scriptCode = imp.trimStart().replace(/;?\s*$/, ';\n') + scriptCode;
                }
              }
            }
          } else if (descriptor.descriptor.template) {
            // Template-only SFC (no <script> block) — compile template into
            // a render function and export it as the default component.
            const templateResult = compiler.compileTemplate({
              source: descriptor.descriptor.template.content,
              filename: args.path,
              id,
              compilerOptions: { mode: 'module' },
            });
            scriptCode = templateResult.code + '\nexport default { render }';
          }

          // Handle <style> blocks — inject as a <style> tag at runtime
          let styleInjection = '';
          if (descriptor.descriptor.styles?.length > 0) {
            const allStyles = descriptor.descriptor.styles
              .map((s: any) => s.content)
              .join('\n');
            const escaped = JSON.stringify(allStyles);
            styleInjection = `
;(function(){
  const s = document.createElement('style');
  s.textContent = ${escaped};
  document.head.appendChild(s);
})();`;
          }

          // Rewrite bare `import { ... } from 'vue'` so it resolves to CDN
          const code = scriptCode
            .replace(/from\s+['"]vue['"]/g, `from '${cdnBase}/vue'`);

          return {
            contents: styleInjection + '\n' + code,
            loader: 'js' as import('esbuild-wasm').Loader,
            resolveDir: parentDir(args.path),
          };
        } catch (err: any) {
          return { errors: [{ text: `Vue compile error in ${args.path}: ${err.message}` }] };
        }
      });
    },
  };
}

// ---------------------------------------------------------------------------
// Main bundle function
// ---------------------------------------------------------------------------

export async function bundleProject(input: BundleInput): Promise<BundleOutput> {
  const cdnBase = input.cdnBase || 'https://esm.sh';
  const runtime = input.runtime || 'react';
  const config = getRuntimeConfig(runtime);

  // Build file map (path → content string)
  const fileMap = new Map<string, string>();
  for (const file of input.files) {
    if (typeof file.content === 'string') {
      fileMap.set(file.path, file.content);
    }
  }

  const esbuild = await ensureEsbuild();

  const plugins: any[] = [createVfsPlugin(fileMap, cdnBase, config.sfcExtension)];

  if (config.sfcExtension === '.svelte' && config.compilerCdnUrl) {
    plugins.unshift(createSveltePlugin(fileMap, config.compilerCdnUrl));
  }
  if (config.sfcExtension === '.vue' && config.compilerCdnUrl) {
    plugins.unshift(createVuePlugin(fileMap, config.compilerCdnUrl, cdnBase));
  }

  // JSX options — only for JSX-based runtimes
  const jsxOptions: Record<string, any> = {};
  if (config.jsxImportSource) {
    jsxOptions.jsx = 'automatic';
    jsxOptions.jsxImportSource = `${cdnBase}/${config.jsxImportSource}`;
  }

  let result;
  try {
    result = await esbuild.build({
      stdin: {
        contents: fileMap.get(input.entryPoint) || '',
        loader: loaderForPath(input.entryPoint) as import('esbuild-wasm').Loader,
        resolveDir: parentDir(input.entryPoint),
        sourcefile: input.entryPoint,
      },
      bundle: true,
      format: 'esm',
      target: ['es2020'],
      outdir: '/',
      write: false,
      ...jsxOptions,
      plugins,
      logLevel: 'silent',
    });
  } catch (buildError: any) {
    // esbuild throws on build failures — extract structured errors
    const errors = (buildError.errors || []).map(
      (e: any) => `[esbuild] ${e.location ? `${e.location.file}:${e.location.line}:${e.location.column} ` : ''}${e.text}`
    );
    if (errors.length === 0) {
      errors.push(`[esbuild] ${buildError.message}`);
    }
    return { js: '', css: null, errors, warnings: [] };
  }

  const errors = result.errors.map(
    e => `[esbuild] ${e.location ? `${e.location.file}:${e.location.line}:${e.location.column} ` : ''}${e.text}`
  );
  const warnings = result.warnings.map(
    w => `[esbuild] ${w.location ? `${w.location.file}:${w.location.line}:${w.location.column} ` : ''}${w.text}`
  );

  let js = '';
  let css: string | null = null;

  for (const file of result.outputFiles || []) {
    if (file.path.endsWith('.css')) {
      css = file.text;
    } else {
      js = file.text;
    }
  }

  // Strip esbuild module boundary comments
  js = js.replace(/^\/\/ [^\n]*\.(svelte|vue|[tj]sx?)\n/gm, '');

  return { js, css, errors, warnings };
}
