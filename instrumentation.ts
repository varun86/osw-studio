export async function register() {
  if (process.env.NEXT_RUNTIME === 'nodejs') {
    // SECURITY: Run startup validations
    validateGatewayUrl();
    validateSecurityConfig();

    try {
      // Dynamic imports — avoids bundling SQLite into client
      const { listDeploymentIds } = await import('@/lib/vfs/adapters/sqlite-connection');
      listDeploymentIds(); // Verify SQLite is available (throws in browser mode)

      const { Scheduler } = await import('@/lib/scheduler');
      const { createDeploymentSchedulerTask } = await import('@/lib/scheduler/deployment-scheduler');

      const scheduler = new Scheduler({ pollIntervalMs: 30000 });
      scheduler.registerTask(createDeploymentSchedulerTask());
      scheduler.start();
    } catch (err) {
      // Browser mode or SQLite not available — skip
      if (process.env.ADMIN_PASSWORD) {
        // Only log in server mode (ADMIN_PASSWORD indicates server deployment)
        console.warn('[Scheduler] Failed to initialize:', err instanceof Error ? err.message : err);
      }
    }
  }
}

/**
 * SECURITY: Validate gateway URLs at startup.
 * - GATEWAY_URL (server-only, preferred) — not exposed to client
 * - NEXT_PUBLIC_GATEWAY_URL (client-visible) — for backward compatibility
 *
 * Must be a valid HTTPS URL in production. HTTP is only allowed in development.
 * Invalid gateway URLs can lead to open redirect vulnerabilities.
 */
function validateGatewayUrl(): void {
  const urls = [
    { name: 'GATEWAY_URL', value: process.env.GATEWAY_URL },
    { name: 'NEXT_PUBLIC_GATEWAY_URL', value: process.env.NEXT_PUBLIC_GATEWAY_URL },
  ];

  for (const { name, value: url } of urls) {
    if (!url) continue;

    try {
      const parsed = new URL(url);

      // Must use HTTPS in production
      if (process.env.NODE_ENV === 'production' && parsed.protocol !== 'https:') {
        console.error(
          `[SECURITY] ${name} must use HTTPS in production. Got: ${parsed.protocol}//${parsed.host}`
        );
      }

      // Must have a valid hostname
      if (!parsed.hostname || parsed.hostname === '') {
        console.error(`[SECURITY] ${name} has no valid hostname`);
      }

      // Reject obviously malicious values
      if (parsed.hostname === 'localhost' && process.env.NODE_ENV === 'production') {
        console.warn(`[SECURITY] ${name} points to localhost in production`);
      }

      // Log that GATEWAY_URL is the preferred server-only variable
      if (name === 'NEXT_PUBLIC_GATEWAY_URL' && process.env.NODE_ENV === 'production') {
        console.warn(
          `[SECURITY] NEXT_PUBLIC_GATEWAY_URL is visible to the client. ` +
          `Consider using GATEWAY_URL (without NEXT_PUBLIC_ prefix) for server-side redirects.`
        );
      }
    } catch {
      console.error(
        `[SECURITY] ${name} is not a valid URL`
      );
    }
  }
}

/**
 * SECURITY: Validate security-related configuration at startup.
 * Warns about insecure configurations in production.
 */
function validateSecurityConfig(): void {
  const isProduction = process.env.NODE_ENV === 'production';

  // Step 38: Warn when SECURE_COOKIES=false in production
  if (isProduction && process.env.SECURE_COOKIES === 'false') {
    console.error(
      '[SECURITY] SECURE_COOKIES is explicitly set to "false" in production. ' +
      'Session cookies will be sent over HTTP, allowing session hijacking on insecure connections. ' +
      'Remove SECURE_COOKIES=false or set it to "true" immediately.'
    );
  }

  // Step 40: Warn loudly if OSW_DESKTOP=true + NEXT_PUBLIC_SERVER_MODE=true
  if (process.env.OSW_DESKTOP === 'true' && process.env.NEXT_PUBLIC_SERVER_MODE === 'true') {
    console.error(
      '[SECURITY] OSW_DESKTOP=true and NEXT_PUBLIC_SERVER_MODE=true are both enabled. ' +
      'Desktop mode skips authentication, which is extremely dangerous in a server deployment. ' +
      'Set OSW_DESKTOP=false for server deployments, or NEXT_PUBLIC_SERVER_MODE=false for desktop use.'
    );
  }
}
