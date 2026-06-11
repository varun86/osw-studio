'use client';

import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { logger, cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover';
import {
  Loader2,
  Sparkles,
  Zap,
  Brain,
  Server,
  Cloud,
  Cpu,
  ChevronDown,
  Search,
  X,
  Lightbulb
} from 'lucide-react';
import { configManager } from '@/lib/config/storage';
import { ProviderId, ProviderModel } from '@/lib/llm/providers/types';
import { getProvider } from '@/lib/llm/providers/registry';
import { getAvailableModels } from '@/lib/llm/llm-client';
import {
  fetchAvailableModels,
  formatModelPrice
} from '@/lib/llm/models-api';
import { registerOpenRouterPricingFromApi, registerPricingFromProviderModels } from '@/lib/llm/pricing-cache';
import { toast } from 'sonner';
import { track } from '@/lib/telemetry';

interface ModelSelectorProps {
  provider?: ProviderId;
  value?: string;
  onChange?: (modelId: string) => void;
  className?: string;
  hideModelDetails?: boolean;
  mode?: 'popover' | 'inline';
  skipGlobalSync?: boolean;
  autoFocus?: boolean;
}

export function ModelSelector({ provider, value: _value, onChange, className, hideModelDetails, mode = 'popover', skipGlobalSync, autoFocus }: ModelSelectorProps) {
  const currentProvider = provider || configManager.getSelectedProvider();
  const providerConfig = getProvider(currentProvider);
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;
  const [models, setModels] = useState<ProviderModel[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedModel, setSelectedModel] = useState('');
  const [open, setOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [needsApiKey, setNeedsApiKey] = useState(false);
  const [reasoningEnabled, setReasoningEnabled] = useState(false);
  
  const getModelName = (model: ProviderModel) => {
    return model.name;
  };

  // Define loadModels before useEffects that use it
  const loadModels = useCallback(async () => {
    try {
      setLoading(true);
      
      const apiKey = configManager.getProviderApiKey(currentProvider);
      const hasApiKey = configManager.hasProviderApiKey(currentProvider);
      
      if (providerConfig.apiKeyRequired && !hasApiKey) {
        setNeedsApiKey(true);
        if (providerConfig.models) {
          setModels(providerConfig.models);
        } else {
          setModels([]);
        }
        return;
      }
      
      setNeedsApiKey(false);
      
      // Check cache first
      const cachedModels = configManager.getCachedModels(currentProvider);
      if (cachedModels) {
        const modelsFromCache = cachedModels.models as ProviderModel[];
        setModels(modelsFromCache);
        if (currentProvider === 'openrouter') {
          registerPricingFromProviderModels('openrouter', modelsFromCache);
        }
        return;
      }
      
      let loadedModels: ProviderModel[] = [];
      
      if (currentProvider === 'openrouter') {
        // Use the existing OpenRouter models API
        const availableModels = await fetchAvailableModels();
        registerOpenRouterPricingFromApi(availableModels);
        const norm = (desc: unknown): string => {
          if (typeof desc === 'string') {
            return desc;
          }

          if (desc && typeof desc === 'object') {
            const record = desc as Record<string, unknown>;
            const candidate = ['description', 'name', 'summary']
              .map((key) => record[key])
              .find((value): value is string => typeof value === 'string');

            if (candidate) {
              return candidate;
            }

            try {
              return JSON.stringify(record);
            } catch {
              /* ignore */
            }
          }

          if (desc == null) {
            return '';
          }

          return String(desc);
        };
        loadedModels = availableModels.map((model) => {
          const promptRate = model.pricing?.prompt ? Number(model.pricing.prompt) : undefined;
          const completionRate = model.pricing?.completion ? Number(model.pricing.completion) : undefined;
          const reasoningRate = model.pricing?.internal_reasoning ? Number(model.pricing.internal_reasoning) : undefined;

          const normalizeRate = (value?: number) => {
            if (value === undefined || !Number.isFinite(value)) return undefined;
            return value * 1_000_000;
          };

          const normalizedInput = normalizeRate(promptRate);
          const normalizedOutput = normalizeRate(completionRate);
          const normalizedReasoning = normalizeRate(reasoningRate);

          const pricing = (normalizedInput !== undefined && normalizedOutput !== undefined)
            ? {
                input: normalizedInput,
                output: normalizedOutput,
                reasoning: normalizedReasoning
              }
            : undefined;

          const orModalities = model.architecture?.input_modalities as import('@/lib/llm/providers/types').InputModality[] | undefined;
          const providerModel: ProviderModel = {
            id: model.id,
            name: model.name,
            description: norm(model.description),
            contextLength: model.context_length,
            maxTokens: model.top_provider?.max_completion_tokens,
            supportsFunctions: model.supported_parameters?.includes('tools'),
            supportsVision: orModalities?.includes('image'),
            supportsReasoning: model.supported_parameters?.includes('reasoning'),
            ...(orModalities ? { inputModalities: orModalities } : {}),
            pricing
          };

          return providerModel;
        });
      } else if (currentProvider === 'huggingface') {
        try {
          const hfResponse = await fetch('https://router.huggingface.co/v1/models');
          if (hfResponse.ok) {
            const hfData = await hfResponse.json();
            loadedModels = (hfData.data || []).map((model: any) => {
              const hfProviders = model.providers || [];
              const bestProvider = hfProviders.find((p: any) => p.supports_tools && p.status === 'live')
                || hfProviders.find((p: any) => p.status === 'live')
                || hfProviders[0];

              const contextLength = bestProvider?.context_length || 32768;
              const supportsFunctions = hfProviders.some((p: any) => p.supports_tools);
              const hfModalities = model.architecture?.input_modalities as import('@/lib/llm/providers/types').InputModality[] | undefined;
              const supportsVision = hfModalities?.includes('image');

              let pricing: { input: number; output: number } | undefined;
              if (bestProvider?.pricing?.input != null && bestProvider?.pricing?.output != null) {
                pricing = {
                  input: bestProvider.pricing.input,
                  output: bestProvider.pricing.output,
                };
              }

              return {
                id: model.id,
                name: model.id.split('/').pop() || model.id,
                contextLength,
                supportsFunctions,
                supportsVision,
                ...(hfModalities ? { inputModalities: hfModalities } : {}),
                pricing,
              } as ProviderModel;
            });
          }
        } catch (error) {
          logger.error('HuggingFace models fetch error:', error);
        }
        if (loadedModels.length > 0) {
          registerPricingFromProviderModels('huggingface', loadedModels);
        }
      } else if (providerConfig.supportsModelDiscovery) {
        // Try to discover models (we know API key exists at this point)
        const modelEntries = await getAvailableModels(apiKey || undefined, currentProvider);
        loadedModels = modelEntries.map(entry => {
          const id = typeof entry === 'string' ? entry : entry.id;
          const contextLength = typeof entry === 'object' && entry.contextLength ? entry.contextLength : 32000;
          const inputModalities = typeof entry === 'object' && entry.inputModalities
            ? entry.inputModalities as import('@/lib/llm/providers/types').InputModality[]
            : undefined;
          return {
            id,
            name: id.split('/').pop() || id,
            contextLength,
            supportsFunctions: true,
            ...(inputModalities ? { inputModalities, supportsVision: inputModalities.includes('image') } : {}),
          };
        });
      } else if (providerConfig.models) {
        // Use hardcoded models
        loadedModels = providerConfig.models;
      } else {
        loadedModels = [];
      }
      
      setModels(loadedModels);
      
      // Show warning for local providers with no models
      if (providerConfig.isLocal && loadedModels.length === 0) {
        toast.warning(
          `No models found in ${providerConfig.name}. Please load some models in the application.`,
          { duration: 5000 }
        );
      }
      
      // Cache the loaded models
      if (loadedModels.length > 0) {
        configManager.setCachedModels(currentProvider, loadedModels);
        if (currentProvider === 'openrouter') {
          registerPricingFromProviderModels('openrouter', loadedModels);
        }
      }
    } catch (error) {
      logger.error('Failed to load models:', error);
      
      // Show helpful message for local providers
      if (providerConfig.isLocal) {
        toast.error(
          `${providerConfig.name} server not running. Please start the server and load some models.`,
          { duration: 5000 }
        );
      }
      
      // Fall back to hardcoded models if available
      if (providerConfig.models) {
        setModels(providerConfig.models);
      }
    } finally {
      setLoading(false);
    }
  }, [currentProvider, providerConfig]);

  // Single effect to handle provider changes and model loading
  useEffect(() => {
    // Immediately clear models array to prevent stale state
    setModels([]);
    setSelectedModel('');
    setLoading(true);
    
    // Clear cache for this provider to get fresh models
    configManager.clearModelCache(currentProvider);
    
    // Load models immediately
    loadModels();
  }, [currentProvider, loadModels]);

  // Single effect to initialize selectedModel when models are loaded
  useEffect(() => {
    if (models.length === 0 || loading) return;

    // Get the saved model for this provider
    const savedModel = configManager.getProviderModel(currentProvider);
    // Check if saved model exists in loaded models
    if (savedModel && models.some(m => m.id === savedModel)) {
      setSelectedModel(savedModel);
      onChangeRef.current?.(savedModel);
    } else {
      // No saved model or saved model doesn't exist, use first model
      const firstModel = models[0]?.id;
      if (firstModel) {
        setSelectedModel(firstModel);
        if (!skipGlobalSync) {
          configManager.setProviderModel(currentProvider, firstModel);
        }
        onChangeRef.current?.(firstModel);
      }
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [models, loading, currentProvider]);

  // Method to refresh models (can be called externally)
  const _refreshModels = (forceRefresh = false) => {
    if (forceRefresh) {
      configManager.clearModelCache(currentProvider);
    }
    loadModels();
  };

  // Expose refresh method via ref or global method (for when API key is added)
  useEffect(() => {
    const handleApiKeyUpdate = () => {
      // Small delay to ensure config is saved
      setTimeout(() => {
        loadModels();
      }, 100);
    };

    // Listen for a custom event when API keys are updated
    window.addEventListener('apiKeyUpdated', handleApiKeyUpdate);
    
    return () => {
      window.removeEventListener('apiKeyUpdated', handleApiKeyUpdate);
    };
  }, [loadModels]);

  const handleModelSelect = (modelId: string) => {
    setSelectedModel(modelId);
    if (!skipGlobalSync) {
      configManager.setProviderModel(currentProvider, modelId);
    }
    onChange?.(modelId);
    track('model_selected', {
      provider: currentProvider,
      model: modelId,
      previous_model: selectedModel !== modelId ? selectedModel : undefined,
    });
    if (mode === 'popover') {
      setOpen(false);
      setSearchQuery('');
    }
    // Load reasoning state for the new model
    setReasoningEnabled(configManager.getReasoningEnabled(modelId));
  };

  const handleReasoningToggle = (enabled: boolean) => {
    setReasoningEnabled(enabled);
    if (selectedModel) {
      configManager.setReasoningEnabled(selectedModel, enabled);
    }
  };

  // Sync reasoning state when selected model changes
  useEffect(() => {
    if (selectedModel) {
      setReasoningEnabled(configManager.getReasoningEnabled(selectedModel));
    }
  }, [selectedModel]);

  const getModelIcon = (model: ProviderModel) => {
    const id = model.id.toLowerCase();
    if (id.includes('deepseek')) return <Brain className="h-3 w-3" />;
    if (id.includes('claude')) return <Sparkles className="h-3 w-3" />;
    if (id.includes('gpt')) return <Zap className="h-3 w-3" />;
    if (id.includes('gemini')) return <Cloud className="h-3 w-3" />;
    if (id.includes('llama')) return <Server className="h-3 w-3" />;
    if (id.includes('qwen')) return <Cpu className="h-3 w-3" />;
    return null;
  };

  const getProviderColor = (modelId: string) => {
    const id = modelId.toLowerCase();
    if (id.includes('deepseek')) return 'bg-blue-500/10 text-blue-500';
    if (id.includes('claude')) return 'bg-orange-500/10 text-orange-500';
    if (id.includes('openai') || id.includes('gpt')) return 'bg-green-500/10 text-green-500';
    if (id.includes('qwen')) return 'bg-orange-500/10 text-orange-500';
    if (id.includes('google')) return 'bg-red-500/10 text-red-500';
    if (id.includes('meta')) return 'bg-indigo-500/10 text-indigo-500';
    return 'bg-gray-500/10 text-gray-500';
  };

  // Filter models based on search query
  const filteredModels = useMemo(() => {
    if (!searchQuery.trim()) return models;
    
    const query = searchQuery.toLowerCase();
    return models.filter(model => {
      const modelId = model.id.toLowerCase();
      const modelName = getModelName(model).toLowerCase();
      const providerName = model.id.split('/')[0].toLowerCase();
      
      return (
        modelId.includes(query) ||
        modelName.includes(query) ||
        providerName.includes(query)
      );
    });
  }, [models, searchQuery]);

  const selectedModelData = models.find(m => m.id === selectedModel);

  if (loading) {
    return (
      <div className={className}>
        <Label>AI Model</Label>
        <div className="flex items-center gap-2 h-10 px-3 border rounded-md bg-muted">
          <Loader2 className="h-4 w-4 animate-spin" />
          <span className="text-sm text-muted-foreground">Loading models...</span>
        </div>
      </div>
    );
  }

  if (needsApiKey) {
    return (
      <div className={className}>
        <Label>AI Model</Label>
        <div className="flex items-center gap-2 h-10 px-3 border rounded-md bg-muted/50 border-orange-200 dark:border-orange-800">
          <span className="text-sm text-orange-600 dark:text-orange-400">
            API key required for {providerConfig.name}
          </span>
        </div>
        <p className="text-xs text-muted-foreground mt-1">
          Set your API key in settings to load available models
        </p>
      </div>
    );
  }

  const renderModelItem = (model: ProviderModel) => (
    <button
      key={model.id}
      onClick={() => handleModelSelect(model.id)}
      className={cn(
        "w-full text-left px-3 py-2 transition-colors rounded-lg",
        mode === 'inline'
          ? selectedModel === model.id
            ? "bg-primary/10 border border-primary/30"
            : "hover:bg-accent border border-transparent"
          : selectedModel === model.id
            ? "bg-accent"
            : "hover:bg-accent hover:text-accent-foreground"
      )}
    >
      <div className="flex flex-col gap-0.5">
        <div className="flex items-center gap-2">
          {getModelIcon(model)}
          <span className={cn("font-medium text-sm", selectedModel === model.id && mode === 'inline' && "text-primary")}>
            {getModelName(model)}
          </span>
          {currentProvider === 'openrouter' && (
            <Badge variant="secondary" className={`text-xs ${getProviderColor(model.id)}`}>
              {model.id.split('/')[0]}
            </Badge>
          )}
          {model.supportsFunctions === false && (
            <Badge variant="outline" className="text-[9px] px-1 py-0 text-muted-foreground/50">No tools</Badge>
          )}
        </div>
        <div className="flex items-center gap-3 text-xs text-muted-foreground">
          <span>Context: {Math.round(model.contextLength / 1000)}K</span>
          {model.pricing && (
            model.pricing.input === 0 && model.pricing.output === 0 ? (
              <>
                <span>·</span>
                <span>Free</span>
              </>
            ) : (
              <>
                <span>·</span>
                <span>
                  {formatModelPrice(model.pricing.input)}/K | {formatModelPrice(model.pricing.output)}/K
                </span>
              </>
            )
          )}
          {!model.pricing && currentProvider !== 'openrouter' && (
            <>
              <span>·</span>
              <span>Pricing varies</span>
            </>
          )}
        </div>
      </div>
    </button>
  );

  const modelDetailsSection = !hideModelDetails && selectedModelData && (
    <div className="mt-1 text-xs text-muted-foreground max-h-[150px] overflow-y-auto pr-2">
      <div className="font-medium mb-1">
        {selectedModelData.pricing ? (
          selectedModelData.pricing.input === 0 && selectedModelData.pricing.output === 0 ?
            'Free' :
            `Input: ${formatModelPrice(selectedModelData.pricing.input)}/K • Output: ${formatModelPrice(selectedModelData.pricing.output)}/K`
        ) : (
          'Pricing varies by provider'
        )}
      </div>
      <div className="flex flex-wrap gap-1 my-1">
        {selectedModelData.supportsFunctions && (
          <Badge variant="outline" className="text-[10px] px-1.5 py-0">Tools</Badge>
        )}
        {selectedModelData.supportsVision && (
          <Badge variant="outline" className="text-[10px] px-1.5 py-0">Vision</Badge>
        )}
        {selectedModelData.supportsReasoning && (
          <Badge variant="outline" className="text-[10px] px-1.5 py-0">Reasoning</Badge>
        )}
        {!selectedModelData.supportsFunctions && (
          <Badge variant="outline" className="text-[10px] px-1.5 py-0 text-muted-foreground/60">No native tools</Badge>
        )}
      </div>
      {selectedModelData.description && (
        <div>{selectedModelData.description}</div>
      )}
    </div>
  );

  const reasoningSection = selectedModelData?.supportsReasoning && (
    <div className="mt-3 flex items-center justify-between gap-2 p-2 rounded-md bg-muted/50 border">
      <div className="flex items-center gap-2">
        <Lightbulb className="h-4 w-4 text-amber-500" />
        <div>
          <Label htmlFor="reasoning-toggle" className="text-sm font-medium cursor-pointer">
            Enable Reasoning
          </Label>
          <p className="text-xs text-muted-foreground">
            Show step-by-step thinking process
          </p>
        </div>
      </div>
      <Switch
        id="reasoning-toggle"
        checked={reasoningEnabled}
        onCheckedChange={handleReasoningToggle}
      />
    </div>
  );

  // --- Inline mode ---
  if (mode === 'inline') {
    return (
      <div className={className}>
        <div className="border rounded-lg overflow-hidden">
          {/* Search bar */}
          <div className="flex items-center border-b px-3">
            <Search className="h-3.5 w-3.5 shrink-0 opacity-50" />
            <Input
              placeholder="Search models..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="h-9 border-0 bg-transparent dark:bg-transparent shadow-none focus:ring-0 focus-visible:ring-0 focus-visible:ring-offset-0 text-sm"
              autoFocus={autoFocus}
            />
            {searchQuery && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setSearchQuery('')}
                className="h-5 w-5 p-0"
              >
                <X className="h-3 w-3" />
              </Button>
            )}
          </div>
          {/* Model list */}
          <div className="max-h-[240px] overflow-y-auto p-1">
            {filteredModels.length === 0 ? (
              <div className="py-5 text-center text-sm text-muted-foreground">
                No models found
              </div>
            ) : (
              filteredModels.map(renderModelItem)
            )}
          </div>
        </div>
        {modelDetailsSection}
        {reasoningSection}
      </div>
    );
  }

  // --- Popover mode (default) ---
  return (
    <div className={className}>
      <Label htmlFor="model-select">AI Model</Label>
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button
            variant="outline"
            role="combobox"
            aria-expanded={open}
            className="justify-between font-normal min-w-[200px]"
          >
            {selectedModelData ? (
              <div className="flex items-center gap-2 truncate">
                {getModelIcon(selectedModelData)}
                <span className="truncate">{getModelName(selectedModelData)}</span>
              </div>
            ) : (
              <span className="text-muted-foreground">Select a model...</span>
            )}
            <ChevronDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
          </Button>
        </PopoverTrigger>
        <PopoverContent
          className="w-[32rem] p-0"
          align="start"
          side="bottom"
          sideOffset={5}
        >
          <div className="flex items-center border-b px-3">
            <Search className="h-4 w-4 shrink-0 opacity-50" />
            <Input
              placeholder="Search models..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="h-10 border-0 focus:ring-0 focus-visible:ring-0 focus-visible:ring-offset-0"
            />
            {searchQuery && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setSearchQuery('')}
                className="h-5 w-5 p-0"
              >
                <X className="h-3 w-3" />
              </Button>
            )}
          </div>
          <div className="max-h-[400px] min-h-[300px] overflow-y-auto">
            {filteredModels.length === 0 ? (
              <div className="py-6 text-center text-sm text-muted-foreground">
                No models found
              </div>
            ) : (
              filteredModels.map((model) => (
                <button
                  key={model.id}
                  onClick={() => handleModelSelect(model.id)}
                  className={cn(
                    "w-full text-left px-3 py-3 hover:bg-accent hover:text-accent-foreground transition-colors",
                    selectedModel === model.id && "bg-accent"
                  )}
                >
                  <div className="flex flex-col gap-1">
                    <div className="flex items-center gap-2">
                      {getModelIcon(model)}
                      <span className="font-medium">{getModelName(model)}</span>
                      {currentProvider === 'openrouter' && (
                        <Badge variant="secondary" className={`text-xs ${getProviderColor(model.id)}`}>
                          {model.id.split('/')[0]}
                        </Badge>
                      )}
                    </div>
                    <div className="flex items-center gap-3 text-xs text-muted-foreground">
                      <span>Context: {Math.round(model.contextLength / 1000)}K</span>
                      {model.pricing && (
                        model.pricing.input === 0 && model.pricing.output === 0 ? (
                          <>
                            <span>•</span>
                            <span>Free</span>
                          </>
                        ) : (
                          <>
                            <span>•</span>
                            <span>
                              {formatModelPrice(model.pricing.input)}/K | {formatModelPrice(model.pricing.output)}/K
                            </span>
                          </>
                        )
                      )}
                      {!model.pricing && currentProvider !== 'openrouter' && (
                        <>
                          <span>•</span>
                          <span>Pricing varies</span>
                        </>
                      )}
                    </div>
                  </div>
                </button>
              ))
            )}
          </div>
        </PopoverContent>
      </Popover>
      {modelDetailsSection}
      {reasoningSection}
    </div>
  );
}
