/**
 * Script Worker — Executes Python (Pyodide) and Lua (wasmoon) scripts
 * in a Web Worker to avoid blocking the UI thread.
 *
 * Receives: { type: 'execute', payload: { runtime, entryPoint, files } }
 *           { type: 'abort' }
 * Posts:    { type: 'stdout'|'stderr'|'status'|'error'|'complete'|'output-file', ... }
 *
 * SECURITY: CDN scripts are fetched with Subresource Integrity (SRI) verification.
 * The SHA-256 hashes are pinned below and must be updated when upgrading CDN versions.
 * FAIL-CLOSED: If SRI verification cannot be performed (e.g., crypto.subtle unavailable)
 * or if the hash does not match, the script is REFUSED — no fallback to unchecked loading.
 * Tampered or modified CDN responses will always be rejected before execution.
 */

/* global self, importScripts, postMessage, crypto, TextEncoder */

let pyodide = null;
let luaFactory = null;

// ─── SRI (Subresource Integrity) Configuration ─────────────────────
// Pinned SHA-256 hashes for CDN-loaded scripts.
// When upgrading Pyodide or wasmoon versions, update these hashes.
// To compute a hash: curl -sL '<url>' | sha256sum | cut -d' ' -f1 | xxd -r -p | base64

const SRI_HASHES = {
  // Pyodide v0.27.4 — https://cdn.jsdelivr.net/pyodide/v0.27.4/full/pyodide.js
  'pyodide': 'sha256-BXROd35lyIj4D6DJyyrIQCHq3eBSlub4Zb5hGCEQhC4=',
  // wasmoon@1 — https://esm.sh/wasmoon@1
  // NOTE: esm.sh URLs may serve different content over time. The hash below
  // was computed at build time. If wasmoon is upgraded, recompute the hash.
  'wasmoon': 'sha256-5SDyGWb8MXXHxtG1D8vLV7CT1rSfMvKa6kJTMYVEqrs=',
};

// Allowed CDN domains for script loading
const ALLOWED_CDN_DOMAINS = [
  'cdn.jsdelivr.net',
  'esm.sh',
];

/**
 * Verify the SHA-256 hash of a script against its expected SRI hash.
 * FAIL-CLOSED: If verification cannot be performed (e.g., crypto.subtle
 * unavailable), the check returns false — the script must NOT be loaded.
 * @param {string} content - The script content to verify
 * @param {string} expectedHash - The expected hash in SRI format: "sha256-<base64>"
 * @returns {Promise<boolean>} - True ONLY if the hash matches; false if mismatch or unverifiable
 */
async function verifySRI(content, expectedHash) {
  try {
    if (typeof crypto === 'undefined' || !crypto.subtle) {
      // FAIL-CLOSED: crypto.subtle is required for SRI verification.
      // If it's not available, we cannot verify integrity and must refuse to load.
      send('stderr', 'SECURITY: SRI verification impossible — crypto.subtle not available. Refusing to load script.');
      return false;
    }
    const encoder = new TextEncoder();
    const data = encoder.encode(content);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashBase64 = btoa(String.fromCharCode(...hashArray));
    const computedHash = 'sha256-' + hashBase64;
    return computedHash === expectedHash;
  } catch (err) {
    // FAIL-CLOSED: Any error during verification means we cannot confirm integrity.
    send('stderr', 'SECURITY: SRI verification failed with error. Refusing to load script: ' + String(err));
    return false;
  }
}

/**
 * Validate that a URL is from an allowed CDN domain.
 * @param {string} url - The URL to validate
 * @returns {boolean} - True if the URL is from an allowed domain
 */
function isAllowedCdnUrl(url) {
  try {
    const parsed = new URL(url);
    return ALLOWED_CDN_DOMAINS.some(domain =>
      parsed.hostname === domain || parsed.hostname.endsWith('.' + domain)
    );
  } catch {
    return false;
  }
}

/**
 * Fetch a script from CDN with SRI verification.
 * Downloads the script, verifies its hash, then executes via eval.
 * Falls back to importScripts if fetch is not available.
 * @param {string} url - The CDN URL to fetch
 * @param {string} sriKey - Key in SRI_HASHES for the expected hash
 * @returns {Promise<void>}
 */
async function fetchAndVerifyScript(url, sriKey) {
  const expectedHash = SRI_HASHES[sriKey];
  if (!expectedHash) {
    throw new Error(`No SRI hash configured for ${sriKey}. Refusing to load.`);
  }

  if (!isAllowedCdnUrl(url)) {
    throw new Error(`CDN URL not in allowlist: ${url}. Refusing to load.`);
  }

  // Fetch with SRI verification — FAIL-CLOSED: no fallback to importScripts
  // If fetch or SRI verification fails, the script is NOT loaded.
  // This ensures CDN tampering is always detected and prevented.
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status} fetching ${url}. Cannot verify integrity — refusing to load.`);
  }

  const content = await response.text();

  // Verify integrity — FAIL-CLOSED
  const isValid = await verifySRI(content, expectedHash);
  if (!isValid) {
    throw new Error(
      `SRI verification FAILED for ${url}. ` +
      `The CDN response does not match the expected hash. ` +
      `This could indicate a tampered CDN response or an outdated SRI hash. ` +
      `Expected: ${expectedHash}. Refusing to load.`
    );
  }

  // Execute the verified script
  // We use indirect eval to execute in the global scope (like importScripts)
  (0, eval)(content);
}

/**
 * Post a message back to the main thread.
 */
function send(type, data) {
  self.postMessage({ type, data });
}

function sendFile(path, content) {
  self.postMessage({ type: 'output-file', path, content });
}

// ─── Python (Pyodide) ──────────────────────────────────────────────

async function ensurePyodide() {
  if (pyodide) return pyodide;

  send('status', 'Loading Python runtime...');

  try {
    await fetchAndVerifyScript(
      'https://cdn.jsdelivr.net/pyodide/v0.27.4/full/pyodide.js',
      'pyodide'
    );
  } catch (err) {
    send('error', 'Failed to load Pyodide from CDN: ' + String(err));
    throw err;
  }

  try {
    pyodide = await self.loadPyodide({
      stdout: (msg) => send('stdout', msg),
      stderr: (msg) => send('stderr', msg),
    });
  } catch (err) {
    send('error', 'Failed to initialize Pyodide: ' + String(err));
    throw err;
  }

  // Pre-load micropip so users can install packages
  await pyodide.loadPackage('micropip');

  send('status', 'Python runtime ready');
  return pyodide;
}

async function executePython(entryPoint, files) {
  const py = await ensurePyodide();

  // Mount VFS files into Pyodide's filesystem
  // Create /output/ directory for visual output
  try { py.FS.mkdir('/output'); } catch (_e) { /* exists */ }

  for (const [path, content] of Object.entries(files)) {
    // Skip dotfiles
    if (path.startsWith('/.')) continue;
    const dir = path.substring(0, path.lastIndexOf('/')) || '/';
    // Ensure parent directories exist
    const parts = dir.split('/').filter(Boolean);
    let current = '';
    for (const part of parts) {
      current += '/' + part;
      try { py.FS.mkdir(current); } catch (_e) { /* exists */ }
    }
    py.FS.writeFile(path, content);
  }

  // Run the entry point script
  const code = files[entryPoint];
  if (!code) {
    send('error', `Entry point not found: ${entryPoint}`);
    return { exitCode: 1 };
  }

  // Set up Python environment so module imports work:
  const entryDir = entryPoint.substring(0, entryPoint.lastIndexOf('/')) || '/';
  try {
    await py.runPythonAsync(`
import sys, os
os.chdir(${JSON.stringify(entryDir)})
_ep_dir = ${JSON.stringify(entryDir)}
if _ep_dir not in sys.path:
    sys.path.insert(0, _ep_dir)
if '/' not in sys.path:
    sys.path.insert(0, '/')
__file__ = ${JSON.stringify(entryPoint)}
del _ep_dir
`);
  } catch (_e) { /* best effort */ }

  try {
    await py.runPythonAsync(code);
  } catch (err) {
    send('stderr', String(err));
    return { exitCode: 1 };
  }

  // Scan /output/ for new files and send them back
  try {
    const outputFiles = py.FS.readdir('/output').filter(f => f !== '.' && f !== '..');
    for (const filename of outputFiles) {
      const filePath = '/output/' + filename;
      try {
        const data = py.FS.readFile(filePath);
        const ext = filename.split('.').pop().toLowerCase();
        if (['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp'].includes(ext)) {
          let binary = '';
          for (let i = 0; i < data.length; i++) {
            binary += String.fromCharCode(data[i]);
          }
          const base64 = btoa(binary);
          sendFile(filePath, base64);
        } else {
          const decoder = new TextDecoder();
          sendFile(filePath, decoder.decode(data));
        }
      } catch (_e) { /* skip unreadable files */ }
    }
  } catch (_e) { /* /output/ may not have new files */ }

  return { exitCode: 0 };
}

// ─── Lua (wasmoon) ──────────────────────────────────────────────────

async function ensureLuaFactory() {
  if (luaFactory) return luaFactory;

  send('status', 'Loading Lua runtime...');

  try {
    // Dynamic import of wasmoon from CDN with SRI verification
    // Since import() doesn't support SRI, we fetch with verification first,
    // then create a blob URL for the verified content and import that.
    const wasmoonUrl = 'https://esm.sh/wasmoon@1';
    const expectedHash = SRI_HASHES['wasmoon'];

    if (!expectedHash) {
      throw new Error('No SRI hash configured for wasmoon. Refusing to load.');
    }

    if (!isAllowedCdnUrl(wasmoonUrl)) {
      throw new Error('CDN URL not in allowlist: ' + wasmoonUrl);
    }

    let wasmoonModule;
    // Fetch and verify — FAIL-CLOSED: no fallback to direct import without SRI
    // If fetch or SRI verification fails, the module is NOT loaded.
    const response = await fetch(wasmoonUrl);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status} fetching wasmoon. Cannot verify integrity — refusing to load.`);
    }
    const content = await response.text();

    const isValid = await verifySRI(content, expectedHash);
    if (!isValid) {
      throw new Error(
        'SRI verification FAILED for wasmoon. ' +
        'The CDN response does not match the expected hash. ' +
        'This could indicate a tampered CDN response or an outdated SRI hash. ' +
        'Refusing to load.'
      );
    }

    // Create a blob URL from verified content and import it
    const blob = new Blob([content], { type: 'application/javascript' });
    const blobUrl = URL.createObjectURL(blob);
    wasmoonModule = await import(blobUrl);
    URL.revokeObjectURL(blobUrl);

    luaFactory = new wasmoonModule.LuaFactory();
  } catch (err) {
    send('error', 'Failed to load Lua runtime: ' + String(err));
    throw err;
  }

  send('status', 'Lua runtime ready');
  return luaFactory;
}

async function executeLua(entryPoint, files) {
  const factory = await ensureLuaFactory();
  const engine = await factory.createEngine();

  try {
    // Override print to capture stdout
    engine.global.set('print', function (...args) {
      send('stdout', args.map(String).join('\t'));
    });

    // Pre-load module files so require() works
    const moduleFiles = {};
    for (const [path, content] of Object.entries(files)) {
      if (path.endsWith('.lua') && path !== entryPoint) {
        const modName = path
          .replace(/^\//, '')
          .replace(/\.lua$/, '')
          .replace(/\//g, '.');
        moduleFiles[modName] = content;
      }
    }

    // Register custom searcher for VFS modules
    engine.global.set('__vfs_modules', JSON.stringify(moduleFiles));

    await engine.doString(`
      local vfs_modules = {}
      local json_str = __vfs_modules
      -- Simple JSON parse for module map (keys and string values only)
      for key, value in json_str:gmatch('"([^"]+)":"(.-[^\\\\])"') do
        -- Unescape basic sequences
        value = value:gsub('\\\\n', '\\n'):gsub('\\\\t', '\\t'):gsub('\\\\"', '"'):gsub('\\\\\\\\', '\\\\')
        vfs_modules[key] = value
      end
      __vfs_modules = nil

      table.insert(package.searchers, 2, function(modname)
        local source = vfs_modules[modname]
        if source then
          local fn, err = load(source, "@" .. modname .. ".lua")
          if fn then return fn
          else return "\\n\\tload error: " .. err end
        end
        return "\\n\\tno VFS module '" .. modname .. "'"
      end)
    `);

    // Run the entry point
    const code = files[entryPoint];
    if (!code) {
      send('error', 'Entry point not found: ' + entryPoint);
      engine.global.close();
      return { exitCode: 1 };
    }

    await engine.doString(code);

    engine.global.close();
    return { exitCode: 0 };

  } catch (err) {
    send('stderr', String(err));
    try { engine.global.close(); } catch (_e) { /* best effort */ }
    return { exitCode: 1 };
  }
}

// ─── Message handler ────────────────────────────────────────────────

self.onmessage = async function (event) {
  const msg = event.data;

  if (msg.type === 'execute') {
    const { runtime, entryPoint, files } = msg.payload;

    try {
      let result;
      if (runtime === 'python') {
        result = await executePython(entryPoint, files);
      } else if (runtime === 'lua') {
        result = await executeLua(entryPoint, files);
      } else {
        send('error', 'Unknown runtime: ' + runtime);
        self.postMessage({ type: 'complete', exitCode: 1 });
        return;
      }

      self.postMessage({ type: 'complete', exitCode: result.exitCode });
    } catch (err) {
      send('error', String(err));
      self.postMessage({ type: 'complete', exitCode: 1 });
    }
  }
};
