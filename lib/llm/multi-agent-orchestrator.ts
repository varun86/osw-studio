/**
 * Multi-Agent Orchestrator — Facade
 *
 * Thin wiring layer that connects OSWS-specific dependencies (VFS, configManager,
 * telemetry, checkpoints, skills) to the portable core (AgentLoop,
 * ContextManager, ProviderAdapter, ToolExecutor, Coordinator).
 *
 * The core agent loop lives in core/agent-loop.ts. This file only handles:
 * - Constructor wiring (configManager → adapters → coordinator → loop)
 * - execute(): skill evaluation + message construction, then delegates to AgentLoop
 * - stop() / continue() / importConversation(): thin pass-through
 * - completionGate: drains runtime errors from preview iframe
 * - onPausableError: pause/resume UI flow
 * - Checkpoint recording (onAfterExecute hook)
 * - Telemetry emission
 * - Cost accumulation (configManager.updateSessionCost, VFS project cost)
 */

import { Agent, AgentType, agentRegistry } from './agent';
import { vfs } from '@/lib/vfs';
import { checkpointManager, Checkpoint } from '@/lib/vfs/checkpoint';
import { saveManager } from '@/lib/vfs/save-manager';
import { configManager } from '@/lib/config/storage';
import { getProvider, getModelContextLength } from '@/lib/llm/providers/registry';
import type { ProviderId } from '@/lib/llm/providers/types';
import { CostCalculator } from './cost-calculator';
import { ToolCall, UsageInfo, ContentBlock } from './types';
import { logger } from '@/lib/utils';
import { buildFileTree, ReasoningDetail } from './streaming-parser';
import { drainRuntimeErrors, formatRuntimeErrors, resetRuntimeErrors } from '@/lib/preview/runtime-errors';
import { buildSystemPrompt, buildProjectContext, buildCompactionPrompt } from './system-prompt';
import { evaluateRelevantSkills } from './skill-evaluator';
import { skillsService } from '@/lib/vfs/skills';
import { track } from '@/lib/telemetry';
import { extractToolAnalytics } from '@/lib/telemetry/tool-analytics';
import type { ServerOrchestratorContext } from '@/lib/server-generate/types';

import { AgentLoop } from './core/agent-loop';
import { ContextManagerImpl } from './core/context-manager';
import { OswsProviderAdapter, PausableApiError } from './provider-adapter';
import { OswsToolExecutor } from './tool-executor';
import { MultiAgentCoordinator } from './coordinator';
import type { Message, ProgressReporter, CostTracker, AgentLoopConfig, CompactionConfig } from './core/types';

// ---------------------------------------------------------------------------
// Exported types — consumed by 15+ files, must not change shape
// ---------------------------------------------------------------------------

export interface AgentMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string | ContentBlock[];
  tool_calls?: ToolCall[];
  tool_call_id?: string;
  reasoning_details?: ReasoningDetail[];
  ui_metadata?: {
    checkpointId?: string;
    cost?: number;
    usage?: UsageInfo;
    isSyntheticError?: boolean;
    projectContext?: string;
    displayContent?: string | ContentBlock[];
    isCompactSummary?: boolean;
    focusContext?: { domPath: string; snippet: string };
    semanticBlocks?: Array<{ name: string; domPath: string; position: string; description: string }>;
  };
}

export interface PendingImage {
  id: string;
  data: string;
  mediaType: string;
  preview: string;
}

export interface ConversationNode {
  id: string;
  agent_type: AgentType;
  messages: AgentMessage[];
  metadata: {
    started_at: number;
    completed_at?: number;
    cost: number;
    status: 'running' | 'completed' | 'failed';
  };
}

export interface ContextBreakdown {
  systemPromptChars: number;
  userMessageChars: number;
  assistantTextChars: number;
  toolCallArgChars: number;
  toolResultChars: number;
  reasoningChars: number;
  totalChars: number;
}

export interface MultiAgentResult {
  success: boolean;
  summary: string;
  conversation: ConversationNode[];
  totalCost: number;
  totalUsage: UsageInfo;
  checkpointId?: string;
  toolCount?: number;
  turnCount?: number;
  apiErrorCount?: number;
  contextBreakdowns?: ContextBreakdown[];
}

// ---------------------------------------------------------------------------
// MultiAgentOrchestrator
// ---------------------------------------------------------------------------

export class MultiAgentOrchestrator {
  private projectId: string;
  private rootAgent: Agent;
  private conversations: Map<string, ConversationNode> = new Map();
  private currentConversationId: string;
  private onProgress?: (message: string, step?: unknown) => void;
  private chatMode: boolean;
  private model?: string;
  private serverContext: ServerOrchestratorContext | null;

  private stopped = false;
  private abortController = new AbortController();
  private pauseResolve: (() => void) | null = null;

  private totalCost = 0;
  private totalUsage: UsageInfo = { promptTokens: 0, completionTokens: 0, totalTokens: 0, cost: 0 };
  private taskCost = 0;
  private taskTokens = 0;
  private toolCallCount = 0;
  private turnCount = 0;
  private apiErrorCount = 0;
  private contextBreakdowns: ContextBreakdown[] = [];

  private static readonly COMPACTION_THRESHOLD = 0.60;
  private static readonly RECENT_KEEP_RATIO = 0.20;
  private static readonly SUMMARY_TOKEN_RATIO = 0.10;
  private static readonly DEFAULT_COMPACTION_LIMIT = 128000;

  constructor(
    projectId: string,
    agentType: AgentType = 'orchestrator',
    onProgress?: (message: string, step?: unknown) => void,
    options?: { chatMode?: boolean; model?: string; serverContext?: ServerOrchestratorContext }
  ) {
    this.projectId = projectId;
    this.onProgress = onProgress;
    this.chatMode = options?.chatMode ?? false;
    this.model = options?.model;
    this.serverContext = options?.serverContext ?? null;

    const agent = agentRegistry.get(agentType);
    if (!agent) throw new Error(`Agent type "${agentType}" not found`);
    this.rootAgent = agent;

    this.currentConversationId = this.createConversation(agentType);
  }

  continue(): void {
    if (this.pauseResolve) {
      this.abortController = new AbortController();
      this.pauseResolve();
      this.pauseResolve = null;
    }
  }

  stop(): void {
    this.stopped = true;
    this.abortController.abort();
    if (this.pauseResolve) {
      this.pauseResolve();
      this.pauseResolve = null;
    }
    logger.info('[MultiAgentOrchestrator] Execution stopped by user');
  }

  importConversation(messages: AgentMessage[]): void {
    const conversation = this.conversations.get(this.currentConversationId);
    if (!conversation) throw new Error('Cannot import conversation: root conversation not found');
    conversation.messages = messages;
    logger.info(`[MultiAgentOrchestrator] Imported ${messages.length} conversation messages`);
  }

  async execute(
    userPrompt: string,
    options?: {
      images?: Array<{ data: string; mediaType: string }>;
      focusContext?: { domPath: string; snippet: string };
      semanticBlocks?: Array<{ name: string; domPath: string; position: string; description: string }>;
      displayPrompt?: string;
    }
  ): Promise<MultiAgentResult> {
    logger.info('[MultiAgentOrchestrator] Starting execution', { agent: this.rootAgent.type });

    this.stopped = false;
    this.abortController = new AbortController();
    this.taskCost = 0;
    this.taskTokens = 0;

    // Strip trailing nudge messages from previous execution
    const conversation = this.conversations.get(this.currentConversationId)!;
    while (conversation.messages.length > 0) {
      const last = conversation.messages[conversation.messages.length - 1];
      if (last.role === 'user' && typeof last.content === 'string' && last.content.includes('Before finishing, run the status command')) {
        conversation.messages.pop();
      } else {
        break;
      }
    }

    try {
      // 1. Build system prompt and project context
      let fileTreeStr: string | undefined;
      try {
        const files = await this.getVFS().listDirectory(this.projectId, '/');
        if (files.length > 0) fileTreeStr = buildFileTree(files);
      } catch { /* ignore */ }

      const serverCtxMeta = this.getVFS().getServerContextMetadata();
      const modelSupportsTools = this.checkModelSupportsTools();
      const systemPrompt = await buildSystemPrompt(this.chatMode, serverCtxMeta, this.projectId, this.rootAgent.type, modelSupportsTools);

      const hasExistingSystemMessage = conversation.messages.some(m => m.role === 'system');
      if (!hasExistingSystemMessage) {
        this.addMessage(this.currentConversationId, { role: 'system', content: systemPrompt });
      }

      let projectContext = '';
      if (!hasExistingSystemMessage) {
        projectContext = await buildProjectContext(fileTreeStr, serverCtxMeta);
      }

      // 2. Skill evaluation (orchestrator only)
      let skillHint = '';
      try {
        const evalEnabled = await skillsService.isEvaluationEnabled();
        if (evalEnabled && this.rootAgent.type === 'orchestrator') {
          const skillsMeta = await skillsService.getEnabledSkillsMetadata();
          if (skillsMeta.length > 0) {
            const { provider, apiKey, model } = this.getProviderConfig();
            const evalResult = await evaluateRelevantSkills(userPrompt, skillsMeta, fileTreeStr || '', provider, apiKey, model);
            if (evalResult.usage) {
              const cost = CostCalculator.calculateCost(evalResult.usage, evalResult.usage.provider, evalResult.usage.model, true);
              this.totalCost += cost;
              this.taskCost += cost;
              this.totalUsage.completionTokens += evalResult.usage.completionTokens;
              this.totalUsage.totalTokens += evalResult.usage.totalTokens;
              this.taskTokens += evalResult.usage.totalTokens;
              this.getConfig().updateSessionCost({ ...evalResult.usage, cost }, cost);
            }
            this.onProgress?.('skill_evaluation', { skills: skillsMeta.map(s => s.id), matched: evalResult.skillIds, usage: evalResult.usage });
            if (evalResult.skillIds.length > 0) {
              skillHint = `Skill evaluation: read ${evalResult.skillIds.map(s => `/.skills/${s}.md`).join(', ')} before proceeding.\n\n`;
            }
          }
        }
      } catch { /* silent fallback */ }

      // 3. Build user message
      const messagePrefix = (projectContext ? projectContext + '\n\n' : '') + skillHint;
      const cleanPrompt = options?.displayPrompt ?? userPrompt;
      let userContent: string | ContentBlock[];
      let displayContent: string | ContentBlock[];

      if (options?.images && options.images.length > 0) {
        const imageBlocks: ContentBlock[] = options.images.map(img => ({
          type: 'image_url' as const,
          image_url: { url: `data:${img.mediaType};base64,${img.data}` },
        }));
        userContent = [{ type: 'text' as const, text: messagePrefix + userPrompt }, ...imageBlocks];
        displayContent = [{ type: 'text' as const, text: cleanPrompt }, ...imageBlocks];
      } else {
        userContent = messagePrefix + userPrompt;
        displayContent = cleanPrompt;
      }

      this.addMessage(this.currentConversationId, {
        role: 'user',
        content: userContent,
        ui_metadata: {
          displayContent,
          ...(projectContext ? { projectContext } : {}),
          ...(options?.focusContext ? { focusContext: options.focusContext } : {}),
          ...(options?.semanticBlocks?.length ? { semanticBlocks: options.semanticBlocks } : {}),
        },
      });

      // 4. Run agent loop via extracted modules
      await this.runLoop(systemPrompt, projectContext);

      // 5. Post-run: checkpoint
      if (this.rootAgent.type !== 'setup') {
        await this.recordAutoCheckpoint(`After: ${userPrompt.substring(0, 60)}`);
      }

      return {
        success: true,
        summary: 'Task completed',
        conversation: Array.from(this.conversations.values()),
        totalCost: this.totalCost,
        totalUsage: this.totalUsage,
        toolCount: this.toolCallCount,
        turnCount: this.turnCount,
        apiErrorCount: this.apiErrorCount,
        contextBreakdowns: this.contextBreakdowns.length > 0 ? this.contextBreakdowns : undefined,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      logger.error('[MultiAgentOrchestrator] Execution error:', errorMessage);
      this.onProgress?.('error', { message: errorMessage, type: 'execution_error', stack: error instanceof Error ? error.stack : undefined });
      if (this.rootAgent.type !== 'setup') {
        await this.recordAutoCheckpoint(`After failure: ${userPrompt.substring(0, 60)}`);
      }
      return {
        success: false,
        summary: `Error: ${errorMessage}`,
        conversation: Array.from(this.conversations.values()),
        totalCost: this.totalCost,
        totalUsage: this.totalUsage,
        toolCount: this.toolCallCount,
        turnCount: this.turnCount,
        apiErrorCount: this.apiErrorCount,
        contextBreakdowns: this.contextBreakdowns.length > 0 ? this.contextBreakdowns : undefined,
      };
    }
  }

  // ---------------------------------------------------------------------------
  // Private: runLoop — wire extracted modules and run
  // ---------------------------------------------------------------------------

  private async runLoop(systemPrompt: string, projectContext: string): Promise<void> {
    const conversation = this.conversations.get(this.currentConversationId)!;
    const compactionLimit = this.resolveCompactionLimit();

    // Build ContextManager from existing conversation
    const compactionConfig: CompactionConfig = {
      contextLength: compactionLimit,
      threshold: Math.floor(compactionLimit * MultiAgentOrchestrator.COMPACTION_THRESHOLD),
      recentKeepRatio: MultiAgentOrchestrator.RECENT_KEEP_RATIO,
      summaryTokenRatio: MultiAgentOrchestrator.SUMMARY_TOKEN_RATIO,
      buildCompactionPrompt,
    };
    const contextManager = new ContextManagerImpl(compactionConfig);

    // Import prior messages (everything except the last user message — loop.run adds it)
    const priorMessages = conversation.messages.slice(0, -1);
    const lastUserMsg = conversation.messages[conversation.messages.length - 1];
    contextManager.importMessages(this.toPortableMessages(priorMessages));

    // Sync new messages from ContextManager back to ConversationNode
    let skipNextUserMessage = true; // Skip the user message that loop.run() adds (already in conversation)
    contextManager.onMessageAdded = (msg: Message) => {
      if (skipNextUserMessage && msg.role === 'user') {
        skipNextUserMessage = false;
        return;
      }
      const agentMsg: AgentMessage = { role: msg.role, content: msg.content as string | ContentBlock[] };
      if (msg.tool_calls) agentMsg.tool_calls = msg.tool_calls;
      if (msg.tool_call_id) agentMsg.tool_call_id = msg.tool_call_id;
      if (msg.reasoning_details?.length) agentMsg.reasoning_details = msg.reasoning_details;
      if (msg.metadata?.isCompactSummary) agentMsg.ui_metadata = { isCompactSummary: true };
      conversation.messages.push(agentMsg);
      this.onProgress?.('conversation_message', { message: agentMsg });
    };

    // When compaction replaces the context, sync the conversation node
    contextManager.onMessagesReplaced = (newMessages: Message[]) => {
      conversation.messages = newMessages.map(msg => {
        const agentMsg: AgentMessage = { role: msg.role, content: msg.content as string | ContentBlock[] };
        if (msg.tool_calls) agentMsg.tool_calls = msg.tool_calls;
        if (msg.tool_call_id) agentMsg.tool_call_id = msg.tool_call_id;
        if (msg.reasoning_details?.length) agentMsg.reasoning_details = msg.reasoning_details;
        if (msg.metadata?.isCompactSummary) agentMsg.ui_metadata = { isCompactSummary: true };
        return agentMsg;
      });
      skipNextUserMessage = false;
    };

    // Build ProgressReporter (facade wraps onProgress + telemetry)
    const progress: ProgressReporter = {
      onEvent: (event: string, data?: Record<string, unknown>) => {
        this.onProgress?.(event, data);
      },
    };

    // Build CostTracker (tracks latest context size + cumulative output)
    const costTracker: CostTracker = {
      record: (usage, provider, model) => {
        const cost = CostCalculator.calculateCost(usage, provider, model, true);
        this.totalCost += cost;
        this.taskCost += cost;
        // promptTokens = current context window size (replace, not accumulate)
        this.totalUsage.promptTokens = usage.promptTokens;
        this.totalUsage.completionTokens += usage.completionTokens;
        this.totalUsage.totalTokens += usage.totalTokens;
        this.taskTokens += usage.totalTokens;
        this.getConfig().updateSessionCost({ ...usage, cost }, cost);

        const sessionId = this.getConfig().getCurrentSession?.()?.sessionId;
        if (!this.projectId.startsWith('test-') && this.rootAgent.type !== 'setup') {
          this.getVFS().updateProjectCost(this.projectId, {
            cost, provider: usage.provider || provider || 'unknown',
            tokenUsage: { input: usage.promptTokens, output: usage.completionTokens },
            sessionId, mode: 'absolute',
          }).catch(err => logger.error('Failed to update project cost:', err));
        }

        this.onProgress?.('usage', { usage, totalCost: this.totalCost, totalUsage: { ...this.totalUsage }, taskCost: this.taskCost, taskTokens: this.taskTokens });
      },
      getTurnCost: () => 0,
      getTotalCost: () => this.totalCost,
      getTotalUsage: () => ({ ...this.totalUsage }),
      resetTurn: () => { /* no-op for facade */ },
    };

    // Build ProviderAdapter
    const providerAdapter = new OswsProviderAdapter({
      getProviderConfig: () => this.getProviderConfig(),
      getApiUrl: () => this.getApiUrl(),
      getReasoningEnabled: (m) => this.getConfig().getReasoningEnabled(m),
      getDebugStreamEnabled: () => this.getConfig().getDebugStreamEnabled(),
      getModelPricing: (p, m) => this.getConfig().getModelPricing(p, m),
      getCachedModels: (p) => this.getConfig().getCachedModels(p),
      progress,
    });

    // Build ToolExecutor
    const toolExecutor = new OswsToolExecutor({
      projectId: this.projectId,
      progress,
      getAgent: () => this.rootAgent,
      chatMode: this.chatMode,
      abortSignal: this.abortController.signal,
    });
    toolExecutor.onAfterExecute = async (toolCall, result) => {
      track('tool_call', extractToolAnalytics(toolCall.function.name, toolCall.function.arguments, result.success));
    };

    // Build Coordinator (wraps executor for delegation)
    const coordinator = new MultiAgentCoordinator({
      innerExecutor: toolExecutor,
      provider: providerAdapter,
      progress,
      cost: costTracker,
      projectId: this.projectId,
      chatMode: this.chatMode,
      compactionConfig,
      buildSystemPrompt: async (agentType: string) => {
        const serverCtxMeta = this.getVFS().getServerContextMetadata();
        return buildSystemPrompt(
          this.chatMode || agentType === 'explore' || agentType === 'plan',
          serverCtxMeta, this.projectId, agentType as AgentType, true
        );
      },
    });

    // Build AgentLoop config
    const loopConfig: AgentLoopConfig = {
      maxIterations: this.rootAgent.maxIterations,
      maxNudges: 3,
      maxDuplicateToolCalls: 3,
      agentType: this.rootAgent.type,
      isReadOnly: this.chatMode || this.rootAgent.isReadOnly,
      completionGate: this.rootAgent.type === 'orchestrator' ? async () => {
        await new Promise(resolve => setTimeout(resolve, 400));
        const errors = this.drainErrors();
        if (errors.length > 0) {
          return formatRuntimeErrors(errors);
        }
        return null;
      } : undefined,
      onPausableError: async (error: Error) => {
        this.apiErrorCount++;
        const isPausable = error instanceof PausableApiError;
        this.onProgress?.('error_paused', {
          message: error.message,
          status: isPausable ? (error as PausableApiError).status : 0,
          errorType: isPausable ? (error as PausableApiError).errorType : 'unknown',
          provider: isPausable ? (error as PausableApiError).provider : '',
          model: isPausable ? (error as PausableApiError).model : '',
        });
        if (isPausable) {
          track('api_error', {
            provider: (error as PausableApiError).provider,
            model: (error as PausableApiError).model,
            error_type: (error as PausableApiError).errorType,
            error_category: (error as PausableApiError).errorCategory,
            status_code: (error as PausableApiError).status,
          });
        }
        await new Promise<void>(resolve => { this.pauseResolve = resolve; });
        return this.stopped ? 'stop' : 'continue';
      },
    };

    // Clear runtime errors before starting
    this.resetErrors();

    // Run
    const loop = new AgentLoop({
      config: loopConfig,
      provider: providerAdapter,
      executor: coordinator.createWrappedExecutor(),
      context: contextManager,
      progress,
      cost: costTracker,
    });

    // Propagate stop to coordinator and loop
    const originalStop = this.stop.bind(this);
    this.stop = () => {
      originalStop();
      loop.stop();
      coordinator.stop();
    };

    const userContent = lastUserMsg?.content ?? '';
    let result;
    try {
      result = await loop.run(userContent);
    } finally {
      this.stop = originalStop;
    }

    this.toolCallCount += result.toolCount;
    this.turnCount += result.turnCount;

    // Mark conversation completed
    conversation.metadata.completed_at = Date.now();
    conversation.metadata.status = 'completed';

    // Emit context breakdown
    const breakdown = this.measureContextBreakdown(conversation.messages);
    this.contextBreakdowns.push(breakdown);
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private getConfig(): any {
    return this.serverContext ? this.serverContext.config : configManager;
  }

  private getVFS() {
    return this.serverContext?.vfs ?? vfs;
  }

  private getApiUrl(): string {
    if (this.serverContext) return this.serverContext.apiBaseUrl + '/api/generate';
    return typeof window !== 'undefined' ? `${window.location.origin}/api/generate` : '/api/generate';
  }

  private checkModelSupportsTools(): boolean {
    const { provider, model } = this.getProviderConfig();
    const cached = this.getConfig().getCachedModels(provider);
    if (cached?.models?.length) {
      const entry = (cached.models as { id: string; supportsFunctions?: boolean }[]).find(m => m.id === model);
      if (entry && entry.supportsFunctions === false) return false;
    }
    return true;
  }

  private getProviderConfig(): { provider: string; apiKey: string; model: string } {
    if (this.serverContext) {
      const cfg = this.getConfig();
      const provider = cfg.getSelectedProvider();
      return { provider, apiKey: cfg.getProviderApiKey(provider) || '', model: cfg.getProviderModel(provider) || this.model || 'default-model' };
    }
    const provider = configManager.getSelectedProvider();
    const providerConfig = getProvider(provider);
    const apiKey = configManager.getProviderApiKey(provider);
    const hasApiKey = configManager.hasProviderApiKey(provider);
    const model = configManager.getProviderModel(provider) || this.model || undefined;
    if (providerConfig.apiKeyRequired && !hasApiKey && !providerConfig.usesOAuth) {
      throw new Error(`API key not configured for provider: ${provider}`);
    }
    return { provider, apiKey: apiKey || '', model: model || 'default-model' };
  }

  private resolveCompactionLimit(): number {
    const { provider, model } = this.getProviderConfig();
    const userLimit = this.getConfig().getCompactionLimit(provider);
    if (userLimit) return userLimit;
    const registryLimit = getModelContextLength(provider as ProviderId, model);
    if (registryLimit) return registryLimit;
    const cachedLimit = this.getConfig().getModelContextLengthFromCache(provider, model);
    if (cachedLimit) return cachedLimit;
    return MultiAgentOrchestrator.DEFAULT_COMPACTION_LIMIT;
  }

  private resetErrors(): void {
    if (!this.serverContext) resetRuntimeErrors();
  }

  private drainErrors() {
    return this.serverContext ? [] : drainRuntimeErrors();
  }

  private addMessage(conversationId: string, message: AgentMessage): void {
    const conv = this.conversations.get(conversationId);
    if (!conv) throw new Error(`Conversation ${conversationId} not found`);
    conv.messages.push(message);
    if (conversationId === this.currentConversationId) {
      this.onProgress?.('conversation_message', { message });
    }
  }

  private createConversation(agentType: AgentType): string {
    const id = `conv_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    this.conversations.set(id, {
      id,
      agent_type: agentType,
      messages: [],
      metadata: { started_at: Date.now(), cost: 0, status: 'running' },
    });
    return id;
  }

  private async recordAutoCheckpoint(description: string): Promise<Checkpoint | null> {
    if (this.serverContext) return null;
    const checkpoint = await checkpointManager.createCheckpoint(this.projectId, description, {
      kind: 'auto',
      baseRevisionId: saveManager.getSavedCheckpointId(this.projectId),
    });
    this.onProgress?.('checkpoint_created', { checkpointId: checkpoint.id, description, timestamp: checkpoint.timestamp });
    return checkpoint;
  }

  private measureContextBreakdown(messages: AgentMessage[]): ContextBreakdown {
    let systemPromptChars = 0, userMessageChars = 0, assistantTextChars = 0;
    let toolCallArgChars = 0, toolResultChars = 0, reasoningChars = 0;
    for (const msg of messages) {
      const contentLen = typeof msg.content === 'string' ? msg.content.length : JSON.stringify(msg.content).length;
      switch (msg.role) {
        case 'system': systemPromptChars += contentLen; break;
        case 'user': userMessageChars += contentLen; break;
        case 'assistant':
          assistantTextChars += contentLen;
          if (msg.tool_calls) for (const tc of msg.tool_calls) toolCallArgChars += (tc.function.arguments || '').length;
          if (msg.reasoning_details) for (const rd of msg.reasoning_details) reasoningChars += (rd.text || '').length + (rd.signature || '').length;
          break;
        case 'tool': toolResultChars += contentLen; break;
      }
    }
    const totalChars = systemPromptChars + userMessageChars + assistantTextChars + toolCallArgChars + toolResultChars + reasoningChars;
    return { systemPromptChars, userMessageChars, assistantTextChars, toolCallArgChars, toolResultChars, reasoningChars, totalChars };
  }

  private toPortableMessages(messages: AgentMessage[]): Message[] {
    return messages.map(({ ui_metadata, ...rest }) => rest as Message);
  }
}
