'use client';

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  // SECURITY: Do not render any gateway/redirect URLs on the client error page.
  // The gateway URL is server-side only (GATEWAY_URL env var, not NEXT_PUBLIC_).
  // Users can navigate back to the app manually or use the "Try again" button.

  return (
    <html>
      <body style={{
        margin: 0,
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
        background: '#0a0a0a',
        color: '#e5e5e5',
      }}>
        <div style={{ textAlign: 'center', maxWidth: 480, padding: '2rem' }}>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 600, marginBottom: '0.75rem' }}>
            Something went wrong
          </h1>
          <p style={{ color: '#a3a3a3', marginBottom: '1.5rem', lineHeight: 1.6 }}>
            This workspace is temporarily unavailable. This usually resolves on its own within a few minutes.
          </p>
          <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'center' }}>
            <button
              onClick={reset}
              style={{
                padding: '0.5rem 1.25rem',
                background: '#262626',
                color: '#e5e5e5',
                border: '1px solid #404040',
                borderRadius: '0.375rem',
                cursor: 'pointer',
                fontSize: '0.875rem',
              }}
            >
              Try again
            </button>
          </div>
        </div>
      </body>
    </html>
  );
}
