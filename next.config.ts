import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  // output: 'standalone',
  devIndicators: false,
  // Externalize quickjs-emscripten packages to prevent webpack from mangling WASM loading
  serverExternalPackages: [
    'quickjs-emscripten',
    'quickjs-emscripten-core',
    '@jitl/quickjs-wasmfile-release-sync',
    'esbuild-wasm',
    'esbuild',
    'handlebars',
  ],
  // SECURITY (Step 44): ESLint is configured with security rules (no-eval,
  // no-implied-eval, no-new-func, no-with) in eslint.config.mjs.
  // Previously ignoreDuringBuilds was true, which nullified those checks entirely.
  eslint: {
    ignoreDuringBuilds: false,
  },
  typescript: {
    // We'll handle TypeScript errors separately
    ignoreBuildErrors: false,
  },
  webpack: (config, { isServer }) => {
    config.watchOptions = {
      ...config.watchOptions,
      ignored: ['**/e2e/**', '**/test-results/**', '**/node_modules/**'],
    };
    if (!isServer) {
      config.resolve.alias = {
        ...config.resolve.alias,
        'better-sqlite3': false,
        'esbuild': false,
      };
      // Also exclude native Node.js modules
      config.resolve.fallback = {
        ...config.resolve.fallback,
        fs: false,
        path: false,
        crypto: false,
      };
    }
    return config;
  },
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
          { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
          {
            key: 'Content-Security-Policy',
            value: "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' https://esm.sh https://cdn.jsdelivr.net; frame-src 'self'; worker-src 'self' blob:;",
          },
          { key: 'X-XSS-Protection', value: '0' }, // Deprecated but added for legacy browser support; CSP is the modern defense
        ],
      },
      {
        source: '/deployments/:path*',
        headers: [
          { key: 'Cache-Control', value: 'public, max-age=3600' },
        ],
      },
    ];
  },
  async rewrites() {
    return [
      // Handle published deployment URLs with standard web server behavior
      // /deployments/{projectId}/ -> index.html
      {
        source: '/deployments/:projectId',
        destination: '/deployments/:projectId/index.html',
      },
      {
        source: '/deployments/:projectId/',
        destination: '/deployments/:projectId/index.html',
      },
      // /deployments/{projectId}/page -> page.html (if no extension)
      {
        source: '/deployments/:projectId/:path([^.]+)',
        destination: '/deployments/:projectId/:path.html',
      },
    ];
  },
};

export default nextConfig;
