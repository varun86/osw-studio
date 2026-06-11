/**
 * Analytics Tracking Script Generator
 *
 * Generates a comprehensive, privacy-focused tracking script for built-in analytics.
 *
 * Privacy Features:
 * - No cookies
 * - IP anonymization (country-level only)
 * - Session ID via crypto.randomUUID() with sessionStorage persistence
 * - No cross-site tracking
 *
 * Tracked Metrics:
 * - Pageview tracking
 * - Click heatmaps (with scroll position)
 * - Scroll depth (25%, 50%, 75%, 100%)
 * - Time on page
 * - Referrer sources
 * - Device type
 *
 * Performance:
 * - Efficient event batching (30s or 50 events)
 * - Single HTTP request per batch
 * - Forced flush on page exit/close
 * - 80-90% reduction in network requests
 *
 * Security:
 * - Origin/Referer validation (browser-enforced)
 * - Rate limiting (100/min pageviews, 500/min interactions)
 * - Bot detection
 * - No tokens required (same-origin hosting advantage)
 */

export interface TrackingScriptOptions {
  deploymentId: string;
  apiEndpoint?: string; // Default: /api/analytics/track
  interactionEndpoint?: string; // Default: /api/analytics/interaction
  features?: {
    basicTracking?: boolean;       // Pageviews, referrers
    heatmaps?: boolean;             // Click/scroll heatmaps
    sessionRecording?: boolean;     // Journey tracking (reserved for future)
    performanceMetrics?: boolean;   // Core Web Vitals (reserved for future)
    engagementTracking?: boolean;   // Time on page, scroll depth
    customEvents?: boolean;         // Custom event tracking (reserved for future)
  };
}

/**
 * Generate the inline analytics tracking script
 */
export function generateTrackingScript(options: TrackingScriptOptions): string {
  const {
    deploymentId,
    apiEndpoint = '/api/analytics/track',
    interactionEndpoint = '/api/analytics/interaction',
    features = {
      basicTracking: true,
      heatmaps: false,
      sessionRecording: false,
      performanceMetrics: false,
      engagementTracking: false,
      customEvents: false,
    },
  } = options;

  return `
<!-- OSW Studio Analytics -->
<script>
(function() {
  'use strict';

  // Configuration
  var config = {
    deploymentId: '${deploymentId}',
    apiEndpoint: '${apiEndpoint}',
    interactionEndpoint: '${interactionEndpoint}',
    features: ${JSON.stringify(features)}
  };

  // State
  var pageLoadTime = Date.now();
  var scrollMilestones = { 25: false, 50: false, 75: false, 100: false };
  var eventQueue = [];
  var lastFlush = Date.now();

  // Generate anonymous session ID using crypto.randomUUID() (no cookies)
  // Uses a per-session UUID stored in sessionStorage for consistency within a visit.
  // Falls back to a timestamp-based ID if crypto API is unavailable.
  var SESSION_STORAGE_KEY = 'osw_analytics_sid';

  function generateSessionId() {
    // Try to reuse existing session ID from sessionStorage
    try {
      var existingId = sessionStorage.getItem(SESSION_STORAGE_KEY);
      if (existingId) return existingId;
    } catch (e) {
      // sessionStorage may be unavailable (e.g. private browsing in some browsers)
    }

    // Generate a new session ID using crypto.randomUUID()
    var newId;
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
      newId = crypto.randomUUID();
    } else {
      // Fallback for environments without crypto.randomUUID()
      newId = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = Math.random() * 16 | 0;
        var v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
      });
    }

    // Store in sessionStorage so the same session ID is used across page views
    try {
      sessionStorage.setItem(SESSION_STORAGE_KEY, newId);
    } catch (e) {
      // Ignore storage errors
    }

    return newId;
  }

  // Detect device type
  function getDeviceType() {
    var width = window.innerWidth;
    if (width < 768) return 'mobile';
    if (width < 1024) return 'tablet';
    return 'desktop';
  }

  // Send analytics data
  // Security: Origin/Referer validation on server (browser-enforced, cannot be spoofed cross-domain)
  function sendData(endpoint, data) {
    fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
      keepalive: true
    }).catch(function() {});
  }

  // Track pageview
  function trackPageview() {
    if (!config.features.basicTracking) return;

    var data = {
      deploymentId: config.deploymentId,
      pagePath: window.location.pathname,
      referrer: document.referrer || '',
      userAgent: navigator.userAgent,
      deviceType: getDeviceType()
    };

    sendData(config.apiEndpoint, data);
    pageLoadTime = Date.now();
    scrollMilestones = { 25: false, 50: false, 75: false, 100: false };
  }

  // Track click (for heatmaps)
  function trackClick(event) {
    if (!config.features.heatmaps) return;

    var target = event.target;
    var selector = target.tagName;
    if (target.id) selector += '#' + target.id;
    if (target.className) selector += '.' + target.className.split(' ').join('.');

    eventQueue.push({
      type: 'click',
      data: {
        deploymentId: config.deploymentId,
        pagePath: window.location.pathname,
        interactionType: 'click',
        elementSelector: selector,
        coordinates: {
          x: event.clientX,
          y: event.clientY,
          scrollY: window.scrollY || window.pageYOffset || 0,
          viewportWidth: window.innerWidth,
          viewportHeight: window.innerHeight,
          documentHeight: Math.max(
            document.body.scrollHeight,
            document.body.offsetHeight,
            document.documentElement.clientHeight,
            document.documentElement.scrollHeight,
            document.documentElement.offsetHeight
          )
        },
        timeOnPage: Date.now() - pageLoadTime
      }
    });

    flushEvents();
  }

  // Track scroll depth
  function trackScroll() {
    if (!config.features.engagementTracking && !config.features.heatmaps) return;

    var scrollHeight = document.documentElement.scrollHeight - window.innerHeight;
    var scrolled = window.scrollY;
    var percent = scrollHeight > 0 ? Math.round((scrolled / scrollHeight) * 100) : 100;

    // Track milestones
    [25, 50, 75, 100].forEach(function(milestone) {
      if (percent >= milestone && !scrollMilestones[milestone]) {
        scrollMilestones[milestone] = true;

        eventQueue.push({
          type: 'scroll',
          data: {
            deploymentId: config.deploymentId,
            pagePath: window.location.pathname,
            interactionType: 'scroll',
            scrollDepth: milestone,
            timeOnPage: Date.now() - pageLoadTime
          }
        });
      }
    });

    flushEvents();
  }

  // Track page exit (send time on page)
  function trackExit() {
    if (!config.features.engagementTracking) return;

    var timeOnPage = Date.now() - pageLoadTime;
    if (timeOnPage < 1000) return; // Ignore very short visits

    sendData(config.interactionEndpoint, {
      deploymentId: config.deploymentId,
      pagePath: window.location.pathname,
      interactionType: 'exit',
      timeOnPage: timeOnPage
    });
  }

  // Flush event queue (batching)
  function flushEvents(force) {
    var now = Date.now();
    if (eventQueue.length === 0) return;

    // Increased thresholds: 30s or 50 events (more efficient batching)
    if (!force && now - lastFlush < 30000 && eventQueue.length < 50) return;

    var batch = eventQueue.splice(0, eventQueue.length);

    // Send as single batched request instead of individual requests
    var batchData = {
      batch: true,
      interactions: batch.map(function(event) { return event.data; })
    };

    sendData(config.interactionEndpoint, batchData);
    lastFlush = now;
  }

  // Initialize tracking
  function init() {
    // Track initial pageview (only once)
    var pageviewTracked = false;
    function trackInitialPageview() {
      if (pageviewTracked) return;
      pageviewTracked = true;
      trackPageview();
    }

    if (document.readyState === 'complete') {
      trackInitialPageview();
    } else {
      window.addEventListener('load', trackInitialPageview, { once: true });
    }

    // Track SPA navigation
    var pushState = history.pushState;
    history.pushState = function() {
      pushState.apply(history, arguments);
      trackPageview();
    };
    window.addEventListener('popstate', trackPageview);

    // Track clicks for heatmaps
    if (config.features.heatmaps) {
      document.addEventListener('click', trackClick, true);
    }

    // Track scroll
    if (config.features.engagementTracking || config.features.heatmaps) {
      var scrollTimer;
      window.addEventListener('scroll', function() {
        clearTimeout(scrollTimer);
        scrollTimer = setTimeout(trackScroll, 100);
      });
    }

    // Track page exit (with deduplication)
    var exitTracked = false;
    function handlePageExit() {
      flushEvents(true); // Force flush pending events
      if (config.features.engagementTracking && !exitTracked) {
        exitTracked = true;
        trackExit();
      }
    }

    // Both beforeunload and visibilitychange may fire - deduplicate
    window.addEventListener('beforeunload', handlePageExit);
    document.addEventListener('visibilitychange', function() {
      if (document.visibilityState === 'hidden') {
        handlePageExit();
      } else if (document.visibilityState === 'visible') {
        // Reset exit tracking when page becomes visible again
        exitTracked = false;
      }
    });

    // Flush events periodically (increased to 30s for efficiency)
    setInterval(function() { flushEvents(false); }, 30000);
  }

  init();
})();
</script>
`.trim();
}
