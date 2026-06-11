
import { ProviderId, ProviderModel, CodexAuthData, HFAuthData } from '@/lib/llm/providers/types';
import { getDefaultModel } from '@/lib/llm/providers/registry';
import { UsageInfo } from '@/lib/llm/types';

// Server-side API key storage interface
export interface ServerKeyHint {
  provider: string;
  keyHint: string;
}

export interface SessionCost {
  sessionId: string;
  startTime: Date;
  totalCost: number;
  messageCount: number;
  providerBreakdown: Record<string, {
    cost: number;
    tokenUsage: {
      input: number;
      output: number;
    };
    requestCount: number;
  }>;
}

export interface CostSettings {
  showCosts?: boolean;
  dailyLimit?: number;
  projectLimit?: number;
  warningThreshold?: number;
}

interface ModelCacheEntry {
  models: ProviderModel[];
  timestamp: string;
  expiresAt: string;
}

export interface ProviderPricingEntry {
  input: number;
  output: number;
  reasoning?: number;
}

export interface AppSettings {
  openRouterApiKey?: string;
  defaultModel?: string;
  selectedProvider?: ProviderId;
  providerKeys?: Partial<Record<ProviderId, string>>;
  providerModels?: Partial<Record<ProviderId, string>>;
  theme?: 'light' | 'dark' | 'system';
  costSettings?: CostSettings;
  currentSession?: SessionCost;
  lifetimeCosts?: {
    total: number;
    byProvider: Record<string, number>;
    lastReset?: Date;
  };
  hasSeenAboutModal?: boolean;
  hasSeenGuidedTour?: boolean;
  modelCache?: Partial<Record<ProviderId, ModelCacheEntry>>;
  modelPricing?: Partial<Record<ProviderId, Record<string, ProviderPricingEntry>>>;
  reasoningEnabled?: Record<string, boolean>;  // Per-model reasoning toggle (model ID -> enabled)
  /** Per-provider auto-compaction toggle. Default: true (enabled). */
  compactionEnabled?: Partial<Record<ProviderId, boolean>>;
  /** Per-provider compaction limit override (tokens). Empty = automatic. */
  compactionLimits?: Partial<Record<ProviderId, number>>;
  codexAuth?: CodexAuthData;
  hfAuth?: HFAuthData;
  telemetryOptIn?: boolean;
  /** When true, emit llm_request and stream_raw_chunk debug events (ephemeral, not persisted). */
  debugStreamEnabled?: boolean;
}

class ConfigManager {
  private readonly STORAGE_KEY = 'osw-studio-settings';
  /** Cached server-side key hints (provider → last-4-chars). Populated by fetchServerKeyHints(). */
  private _serverKeyHints: Record<string, string> = {};
  /** Whether we've attempted to fetch server key hints in this session. */
  private _serverKeyHintsFetched = false;

  /**
   * Check if running in server mode (multi-user with auth).
   * In server mode, API keys are stored encrypted on the server side.
   * In desktop mode, API keys stay in localStorage.
   */
  isServerMode(): boolean {
    return process.env.NEXT_PUBLIC_SERVER_MODE === 'true';
  }

  getSettings(): AppSettings {
    if (typeof window === 'undefined') {
      return {};
    }
    const stored = localStorage.getItem(this.STORAGE_KEY);
    if (!stored) return {};
    
    const settings = JSON.parse(stored);
    
    if ('autoSave' in settings || 'autoSaveInterval' in settings) {
      delete settings.autoSave;
      delete settings.autoSaveInterval;
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(settings));
    }
    
    return settings;
  }

  setSetting<K extends keyof AppSettings>(
    key: K,
    value: AppSettings[K]
  ): void {
    if (typeof window === 'undefined') {
      return;
    }
    const settings = this.getSettings();
    settings[key] = value;
    localStorage.setItem(this.STORAGE_KEY, JSON.stringify(settings));
  }

  hasSeenTour(): boolean {
    return Boolean(this.getSettings().hasSeenGuidedTour);
  }

  setHasSeenTour(seen: boolean): void {
    this.setSetting('hasSeenGuidedTour', seen);
  }

  getApiKey(): string | null {
    const provider = this.getSelectedProvider();
    if (provider) {
      return this.getProviderApiKey(provider);
    }
    return this.getSettings().openRouterApiKey || null;
  }

  setApiKey(key: string): void {
    const provider = this.getSelectedProvider();
    if (provider) {
      this.setProviderApiKey(provider, key);
    }
    this.setSetting('openRouterApiKey', key);
  }

  getDefaultModel(): string {
    const provider = this.getSelectedProvider();
    if (provider) {
      return this.getProviderModel(provider) || this.getProviderDefaultModel(provider);
    }
    return this.getSettings().defaultModel || 'deepseek/deepseek-chat';
  }

  setDefaultModel(model: string): void {
    const provider = this.getSelectedProvider();
    if (provider) {
      this.setProviderModel(provider, model);
    }
    this.setSetting('defaultModel', model);
  }

  getSelectedProvider(): ProviderId {
    return this.getSettings().selectedProvider
      || (process.env.NEXT_PUBLIC_DEFAULT_PROVIDER as ProviderId)
      || 'openrouter';
  }

  setSelectedProvider(provider: ProviderId): void {
    this.setSetting('selectedProvider', provider);
  }

  /**
   * Get a provider API key from localStorage.
   *
   * @deprecated In server mode, API keys are stored server-side and should NOT
   * be read from localStorage. Use `hasProviderApiKey()` for existence checks
   * and `getProviderApiKeyHint()` for display. The API routes will automatically
   * look up server-side keys when the client doesn't send one.
   *
   * This method still returns the key from localStorage for backward
   * compatibility during migration and for desktop mode.
   */
  getProviderApiKey(provider: ProviderId): string | null {
    // In server mode, do not return API keys from localStorage — they should
    // only exist on the server. Return null so callers fall through to the
    // server-side key lookup path in API routes.
    if (this.isServerMode()) {
      return null;
    }
    const settings = this.getSettings();
    if (settings.providerKeys?.[provider]) {
      return settings.providerKeys[provider];
    }
    if (provider === 'openrouter' && settings.openRouterApiKey) {
      return settings.openRouterApiKey;
    }
    return null;
  }

  /**
   * Check if an API key is stored for a provider (without revealing the key).
   * In server mode, checks the cached server-side hints.
   * In desktop mode, checks localStorage.
   */
  hasProviderApiKey(provider: ProviderId): boolean {
    if (this.isServerMode()) {
      return !!this._serverKeyHints[provider];
    }
    return !!this.getProviderApiKey(provider);
  }

  /**
   * Get the display hint (last 4 chars) for a provider's API key.
   * In server mode, returns from cached server-side hints.
   * In desktop mode, derives from the localStorage key.
   */
  getProviderApiKeyHint(provider: ProviderId): string | null {
    if (this.isServerMode()) {
      const hint = this._serverKeyHints[provider];
      return hint || null;
    }
    const key = this.getProviderApiKey(provider);
    if (!key) return null;
    return key.length >= 4 ? key.slice(-4) : '****';
  }

  /**
   * Set a provider API key.
   * In server mode, stores the key encrypted on the server via /api/user/keys.
   * In desktop mode, stores in localStorage.
   */
  setProviderApiKey(provider: ProviderId, key: string): void {
    if (this.isServerMode() && key) {
      // Fire-and-forget server-side storage — don't block the UI
      this._storeApiKeyServer(provider, key);
      // Update the cached hint immediately for responsive UI
      this._serverKeyHints[provider] = key.length >= 4 ? key.slice(-4) : '****';
    }
    // Always update localStorage for desktop mode and backward compatibility
    const settings = this.getSettings();
    const providerKeys = settings.providerKeys || {};
    providerKeys[provider] = key;
    this.setSetting('providerKeys', providerKeys);
    
    if (provider === 'openrouter') {
      this.setSetting('openRouterApiKey', key);
    }

    // In server mode, remove the key from localStorage after saving to server
    if (this.isServerMode() && key) {
      this._removeApiKeyFromLocalStorage(provider);
    }
  }

  /**
   * Remove a provider API key.
   * In server mode, deletes from the server-side store.
   * In desktop mode, removes from localStorage.
   */
  removeProviderApiKey(provider: ProviderId): void {
    if (this.isServerMode()) {
      // Fire-and-forget server-side deletion
      this._deleteApiKeyServer(provider);
      delete this._serverKeyHints[provider];
    }
    // Remove from localStorage
    const settings = this.getSettings();
    const providerKeys = settings.providerKeys || {};
    delete providerKeys[provider];
    this.setSetting('providerKeys', providerKeys);
    if (provider === 'openrouter') {
      this.setSetting('openRouterApiKey', '');
    }
  }

  /**
   * Fetch stored API key hints from the server.
   * Call this after login to populate the hints cache.
   */
  async fetchServerKeyHints(): Promise<void> {
    if (!this.isServerMode() || typeof window === 'undefined') return;
    if (this._serverKeyHintsFetched) return;

    try {
      const response = await fetch('/api/user/keys');
      if (response.ok) {
        const data = await response.json();
        const hints: Record<string, string> = {};
        for (const key of data.keys || []) {
          hints[key.provider] = key.keyHint;
        }
        this._serverKeyHints = hints;
        this._serverKeyHintsFetched = true;
      }
    } catch {
      // Silently fail — will retry on next access
    }
  }

  /**
   * Migrate API keys from localStorage to server-side encrypted storage.
   * Sends all existing providerKeys to /api/user/keys, then removes them
   * from localStorage. Returns the list of successfully migrated providers.
   *
   * Should be called once after login when the user has localStorage keys.
   */
  async migrateApiKeysToServer(): Promise<string[]> {
    if (!this.isServerMode() || typeof window === 'undefined') return [];

    const settings = this.getSettings();
    const providerKeys = settings.providerKeys || {};
    const keysToMigrate: Record<string, string> = {};

    // Collect non-empty keys that haven't already been migrated
    for (const [provider, key] of Object.entries(providerKeys)) {
      if (key && typeof key === 'string' && key.trim()) {
        // Skip if already stored server-side
        if (!this._serverKeyHints[provider]) {
          keysToMigrate[provider] = key;
        }
      }
    }

    // Also check openRouterApiKey (legacy field)
    if (settings.openRouterApiKey && !keysToMigrate['openrouter'] && !this._serverKeyHints['openrouter']) {
      keysToMigrate['openrouter'] = settings.openRouterApiKey;
    }

    if (Object.keys(keysToMigrate).length === 0) return [];

    try {
      const response = await fetch('/api/user/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'migrate',
          providerKeys: keysToMigrate,
        }),
      });

      if (response.ok) {
        const data = await response.json();
        const migratedProviders: string[] = (data.migrated || []).map((m: { provider: string; keyHint: string }) => m.provider);

        // Update cached hints
        for (const m of data.migrated || []) {
          this._serverKeyHints[m.provider] = m.keyHint;
        }

        // Remove migrated keys from localStorage
        for (const provider of migratedProviders) {
          this._removeApiKeyFromLocalStorage(provider as ProviderId);
        }

        return migratedProviders;
      }
    } catch {
      // Migration failed — keys remain in localStorage as fallback
    }
    return [];
  }

  // ---------------------------------------------------------------------------
  // Private helpers for server-side key storage
  // ---------------------------------------------------------------------------

  /**
   * Store an API key on the server. Fire-and-forget.
   */
  private async _storeApiKeyServer(provider: string, apiKey: string): Promise<void> {
    try {
      await fetch('/api/user/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider, apiKey }),
      });
    } catch {
      // Silently fail — key is also in localStorage as fallback
    }
  }

  /**
   * Delete an API key from the server. Fire-and-forget.
   */
  private async _deleteApiKeyServer(provider: string): Promise<void> {
    try {
      await fetch('/api/user/keys', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider }),
      });
    } catch {
      // Silently fail
    }
  }

  /**
   * Remove an API key from localStorage without triggering server calls.
   */
  private _removeApiKeyFromLocalStorage(provider: ProviderId): void {
    if (typeof window === 'undefined') return;
    const settings = this.getSettings();
    const providerKeys = { ...(settings.providerKeys || {}) };
    delete providerKeys[provider];
    settings.providerKeys = providerKeys;
    if (provider === 'openrouter') {
      delete settings.openRouterApiKey;
    }
    localStorage.setItem(this.STORAGE_KEY, JSON.stringify(settings));
  }

  getProviderModel(provider: ProviderId): string | null {
    const settings = this.getSettings();
    if (settings.providerModels?.[provider]) {
      return settings.providerModels[provider];
    }
    if (provider === 'openrouter' && settings.defaultModel) {
      return settings.defaultModel;
    }
    return null;
  }

  setProviderModel(provider: ProviderId, model: string): void {
    const settings = this.getSettings();
    const providerModels = settings.providerModels || {};
    providerModels[provider] = model;
    this.setSetting('providerModels', providerModels);
    
    if (provider === 'openrouter') {
      this.setSetting('defaultModel', model);
    }
  }

  getModelPricing(provider: ProviderId, model: string): ProviderPricingEntry | null {
    const settings = this.getSettings();
    const providerPricing = settings.modelPricing?.[provider];
    if (!providerPricing) {
      return null;
    }

    return (
      providerPricing[model] ||
      providerPricing[`${provider}/${model}`] ||
      (model.includes('/') ? providerPricing[model.split('/').pop() ?? ''] : null)
    ) || null;
  }

  setProviderPricing(provider: ProviderId, pricingMap: Record<string, ProviderPricingEntry>): void {
    if (typeof window === 'undefined') {
      return;
    }

    if (!pricingMap || Object.keys(pricingMap).length === 0) {
      return;
    }

    const settings = this.getSettings();
    const modelPricing = { ...(settings.modelPricing || {}) };
    const providerPricing = { ...(modelPricing[provider] || {}) };

    for (const [model, pricing] of Object.entries(pricingMap)) {
      providerPricing[model] = pricing;
    }

    modelPricing[provider] = providerPricing;
    this.setSetting('modelPricing', modelPricing);
  }

  private getProviderDefaultModel(provider: ProviderId): string {
    return getDefaultModel(provider);
  }

  getTheme(): 'light' | 'dark' | 'system' {
    return this.getSettings().theme || 'dark';
  }

  setTheme(theme: 'light' | 'dark' | 'system'): void {
    this.setSetting('theme', theme);
  }

  clearSettings(): void {
    if (typeof window !== 'undefined') {
      localStorage.removeItem(this.STORAGE_KEY);
    }
  }

  getCostSettings(): CostSettings {
    return this.getSettings().costSettings || {
      showCosts: true,
      warningThreshold: 80
    };
  }

  setCostSettings(settings: CostSettings): void {
    this.setSetting('costSettings', settings);
    // Broadcast the change to reactive components
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('osw-studio-cost-settings-changed'));
    }
  }

  getCurrentSession(): SessionCost | null {
    const session = this.getSettings().currentSession;
    if (!session) {
      return null;
    }
    return {
      ...session,
      startTime: new Date(session.startTime)
    };
  }

  startNewSession(): SessionCost {
    const session: SessionCost = {
      sessionId: Date.now().toString(),
      startTime: new Date(),
      totalCost: 0,
      messageCount: 0,
      providerBreakdown: {}
    };
    this.setSetting('currentSession', session);
    return session;
  }

  updateSessionCost(usage: UsageInfo, cost: number): void {
    let session = this.getCurrentSession();
    if (!session) {
      session = this.startNewSession();
    }

    session.totalCost += cost;
    session.messageCount += 1;

    const provider = usage.provider || 'unknown';
    if (!session.providerBreakdown[provider]) {
      session.providerBreakdown[provider] = {
        cost: 0,
        tokenUsage: { input: 0, output: 0 },
        requestCount: 0
      };
    }

    session.providerBreakdown[provider].cost += cost;
    session.providerBreakdown[provider].tokenUsage.input += usage.promptTokens;
    session.providerBreakdown[provider].tokenUsage.output += usage.completionTokens;
    session.providerBreakdown[provider].requestCount += 1;

    const lifetimeCosts = this.getSettings().lifetimeCosts || {
      total: 0,
      byProvider: {}
    };
    lifetimeCosts.total += cost;
    lifetimeCosts.byProvider[provider] = (lifetimeCosts.byProvider[provider] || 0) + cost;

    this.setSetting('currentSession', session);
    this.setSetting('lifetimeCosts', lifetimeCosts);
  }

  getLifetimeCosts() {
    return this.getSettings().lifetimeCosts || {
      total: 0,
      byProvider: {}
    };
  }

  resetLifetimeCosts(): void {
    this.setSetting('lifetimeCosts', {
      total: 0,
      byProvider: {},
      lastReset: new Date()
    });
  }

  // Model cache management
  getCachedModels(provider: ProviderId): ModelCacheEntry | null {
    const settings = this.getSettings();
    const cache = settings.modelCache?.[provider];
    
    if (!cache) return null;
    
    // Check if cache is expired
    const now = new Date();
    const expiresAt = new Date(cache.expiresAt);
    
    if (now > expiresAt) {
      // Cache expired, remove it
      this.clearModelCache(provider);
      return null;
    }
    
    return cache;
  }

  setCachedModels(provider: ProviderId, models: ProviderModel[]): void {
    const settings = this.getSettings();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000); // 24 hours
    
    const cache = settings.modelCache || {};
    cache[provider] = {
      models,
      timestamp: now.toISOString(),
      expiresAt: expiresAt.toISOString()
    };
    
    this.setSetting('modelCache', cache);
  }

  clearModelCache(provider?: ProviderId): void {
    if (provider) {
      const settings = this.getSettings();
      const cache = settings.modelCache || {};
      delete cache[provider];
      this.setSetting('modelCache', cache);
    } else {
      // Clear all cache
      this.setSetting('modelCache', {});
    }
  }

  // Codex auth management
  getCodexAuth(): CodexAuthData | null {
    return this.getSettings().codexAuth || null;
  }

  setCodexAuth(auth: CodexAuthData): void {
    this.setSetting('codexAuth', auth);
    // Also write access_token into providerKeys so getProviderApiKey() works
    this.setProviderApiKey('openai-codex', auth.access_token);
  }

  clearCodexAuth(): void {
    const settings = this.getSettings();
    delete settings.codexAuth;
    if (typeof window !== 'undefined') {
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(settings));
    }
    // Also clear the provider key
    const providerKeys = settings.providerKeys || {};
    delete providerKeys['openai-codex'];
    this.setSetting('providerKeys', providerKeys);
  }

  isCodexTokenExpired(): boolean {
    const auth = this.getCodexAuth();
    if (!auth) return true;
    // Expired if within 60s of expiry
    return Date.now() / 1000 >= auth.expires_at - 60;
  }

  // HuggingFace auth management
  getHFAuth(): HFAuthData | null {
    return this.getSettings().hfAuth || null;
  }

  setHFAuth(auth: HFAuthData): void {
    this.setSetting('hfAuth', auth);
    // Also write access_token into providerKeys so getProviderApiKey() works
    this.setProviderApiKey('huggingface', auth.access_token);
  }

  clearHFAuth(): void {
    const settings = this.getSettings();
    delete settings.hfAuth;
    if (typeof window !== 'undefined') {
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(settings));
    }
    // Also clear the provider key
    const providerKeys = settings.providerKeys || {};
    delete providerKeys['huggingface'];
    this.setSetting('providerKeys', providerKeys);
  }

  getModelContextLengthFromCache(provider: ProviderId, modelId: string): number | undefined {
    const cache = this.getCachedModels(provider);
    if (!cache?.models) return undefined;
    const model = cache.models.find(m => m.id === modelId);
    return model?.contextLength;
  }

  isCompactionEnabled(provider: ProviderId): boolean {
    const settings = this.getSettings();
    return settings.compactionEnabled?.[provider] ?? true;
  }

  setCompactionEnabled(provider: ProviderId, enabled: boolean): void {
    const settings = this.getSettings();
    const map = { ...settings.compactionEnabled };
    if (enabled) {
      delete map[provider];
    } else {
      map[provider] = false;
    }
    this.setSetting('compactionEnabled', map);
  }

  getCompactionLimit(provider: ProviderId): number | undefined {
    const settings = this.getSettings();
    return settings.compactionLimits?.[provider];
  }

  setCompactionLimit(provider: ProviderId, limit: number | undefined): void {
    const settings = this.getSettings();
    const limits = { ...settings.compactionLimits };
    if (limit === undefined) {
      delete limits[provider];
    } else {
      limits[provider] = limit;
    }
    this.setSetting('compactionLimits', limits);
  }

  // Reasoning toggle management
  getReasoningEnabled(modelId: string): boolean {
    const settings = this.getSettings();
    return settings.reasoningEnabled?.[modelId] ?? false;
  }

  getDebugStreamEnabled(): boolean {
    const settings = this.getSettings();
    return settings.debugStreamEnabled ?? false;
  }

  setDebugStreamEnabled(enabled: boolean): void {
    this.setSetting('debugStreamEnabled', enabled);
  }

  setReasoningEnabled(modelId: string, enabled: boolean): void {
    const settings = this.getSettings();
    const reasoningEnabled = { ...(settings.reasoningEnabled || {}) };
    reasoningEnabled[modelId] = enabled;
    this.setSetting('reasoningEnabled', reasoningEnabled);

    // Broadcast the change
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('osw-studio-reasoning-changed', {
        detail: { modelId, enabled }
      }));
    }
  }
}

export const configManager = new ConfigManager();

/**
 * Get the login URL — points to the external auth provider if configured, otherwise the local login page.
 */
export function getLoginUrl(): string {
  return process.env.NEXT_PUBLIC_GATEWAY_URL
    ? `${process.env.NEXT_PUBLIC_GATEWAY_URL}/login`
    : '/admin/login';
}

/**
 * Migrate legacy 'osw-server-features-{id}' localStorage key to 'osw-backend-{id}'
 * Returns the current backend enabled state for the project.
 */
export function migrateBackendKey(projectId: string): boolean {
  if (typeof window === 'undefined') return true;
  const legacyKey = `osw-server-features-${projectId}`;
  const newKey = `osw-backend-${projectId}`;
  if (localStorage.getItem(legacyKey) && !localStorage.getItem(newKey)) {
    localStorage.setItem(newKey, localStorage.getItem(legacyKey)!);
    localStorage.removeItem(legacyKey);
  }
  return localStorage.getItem(newKey) !== 'false';
}
