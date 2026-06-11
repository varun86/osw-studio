import { NextRequest, NextResponse } from 'next/server';
import { ProviderId } from '@/lib/llm/providers/types';
import { getProvider, getDefaultModel } from '@/lib/llm/providers/registry';
import { LLMMessage, ToolDefinition, ContentBlock, TextContentBlock, ImageContentBlock, ReasoningDetail } from '@/lib/llm/types';
import { logger } from '@/lib/utils';
import { handleCodexGeneration } from '@/lib/llm/codex-adapter';
import { requireAuth } from '@/lib/auth/session';
import { getApiKey as getServerApiKey, isServerKeyStorageAvailable } from '@/lib/auth/api-key-store';
import { RateLimiter } from '@/lib/analytics/rate-limiter';

// Per-user rate limiter for AI generation endpoints
// Prevents abuse: 20 requests per user per minute
const generateRateLimiter = new RateLimiter();
const GENERATE_RATE_LIMIT = {
  limit: 20,
  windowMs: 60 * 1000, // 1 minute
};

// Helper to extract text content from string or ContentBlock[]
function getTextContent(content: string | ContentBlock[]): string {
  if (typeof content === 'string') return content;
  return content
    .filter((b): b is TextContentBlock => b.type === 'text')
    .map(b => b.text)
    .join('\n');
}

// Parse data URL to extract media type and base64 data
function parseDataUrl(dataUrl: string): { mediaType: string; data: string } {
  const match = dataUrl.match(/^data:([^;]+);base64,(.+)$/);
  if (!match) {
    throw new Error('Invalid data URL format');
  }
  return { mediaType: match[1], data: match[2] };
}

// Transform content blocks for Anthropic (requires specific image format)
function toAnthropicContent(content: string | ContentBlock[]): any {
  if (typeof content === 'string') return content;
  return content.map(block => {
    if (block.type === 'text') {
      return { type: 'text', text: block.text };
    }
    if (block.type === 'input_audio') return block;
    const { mediaType, data } = parseDataUrl(block.image_url.url);
    return {
      type: 'image',
      source: {
        type: 'base64',
        media_type: mediaType,
        data
      }
    };
  });
}

// Transform messages to Gemini format
function toGeminiContents(messages: LLMMessage[]): { contents: any[]; systemInstruction?: any } {
  let systemInstruction: any = undefined;
  const contents: any[] = [];

  for (const msg of messages) {
    if (msg.role === 'system') {
      systemInstruction = { parts: [{ text: getTextContent(msg.content) }] };
      continue;
    }

    const role = msg.role === 'assistant' ? 'model' : 'user';
    const parts: any[] = [];

    if (typeof msg.content === 'string') {
      parts.push({ text: msg.content });
    } else if (Array.isArray(msg.content)) {
      for (const block of msg.content) {
        if (block.type === 'text') {
          parts.push({ text: block.text });
        } else if (block.type === 'image_url') {
          try {
            const { mediaType, data } = parseDataUrl(block.image_url.url);
            parts.push({ inline_data: { mime_type: mediaType, data } });
          } catch {
            logger.warn('[API] Failed to parse image data URL for Gemini');
          }
        }
      }
    }

    if (parts.length > 0) {
      contents.push({ role, parts });
    }
  }

  return { contents, systemInstruction };
}

// Build Gemini-format request body from the standard OpenAI-format parameters
function buildGeminiRequestBody(
  messages: LLMMessage[],
  options: {
    maxTokens?: number;
    temperature?: number;
    tools?: any[];
    toolChoice?: any;
    reasoning?: any;
  }
): Record<string, unknown> {
  const { contents, systemInstruction } = toGeminiContents(messages);
  const body: Record<string, unknown> = { contents };

  if (systemInstruction) {
    body.system_instruction = systemInstruction;
  }

  const generationConfig: Record<string, unknown> = {
    maxOutputTokens: options.maxTokens || 4096,
    temperature: options.temperature ?? 0.7,
  };

  if (options.reasoning) {
    generationConfig.thinkingConfig = { thinkingBudget: options.reasoning.max_tokens || 4096 };
  }

  body.generationConfig = generationConfig;

  if (options.tools && options.tools.length > 0) {
    body.tools = [{
      function_declarations: options.tools.map((t: any) => ({
        name: t.name,
        description: t.description,
        parameters: t.parameters,
      })),
    }];
  }

  return body;
}

// Extract images from messages for Ollama (images field at request level)
function extractOllamaImages(messages: LLMMessage[]): { processedMessages: LLMMessage[]; images: string[] } {
  const images: string[] = [];
  const processedMessages = messages.map(m => {
    if (typeof m.content === 'string') return m;

    const textBlocks = m.content.filter((b): b is TextContentBlock => b.type === 'text');
    const imageBlocks = m.content.filter((b): b is ImageContentBlock => b.type === 'image_url');

    // Extract base64 data (without data URL prefix) for each image
    for (const img of imageBlocks) {
      try {
        const { data } = parseDataUrl(img.image_url.url);
        images.push(data);
      } catch {
        logger.warn('[API] Failed to parse image data URL for Ollama');
      }
    }

    return {
      ...m,
      content: textBlocks.map(b => b.text).join('\n')
    };
  });

  return { processedMessages, images };
}

export async function POST(request: NextRequest) {
  // Require authentication — AI generation is an authenticated-only feature
  let session;
  try {
    session = await requireAuth();
  } catch {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  // Per-user rate limiting to prevent abuse
  const userId = session.userId;
  if (!generateRateLimiter.check(userId, GENERATE_RATE_LIMIT)) {
    const resetTime = generateRateLimiter.getResetTime(userId, GENERATE_RATE_LIMIT);
    return NextResponse.json(
      { error: 'Rate limit exceeded. Please wait before making more requests.' },
      {
        status: 429,
        headers: { 'Retry-After': String(resetTime) },
      }
    );
  }

  try {
    const { prompt, apiKey: clientApiKey, model, tools, context, messages, tool_choice, provider, max_tokens, reasoning, stream: requestStream } = await request.json();

    const selectedProvider: ProviderId = provider || 'openrouter';
    const providerConfig = getProvider(selectedProvider);

    let apiKey = clientApiKey;

    // If no client-provided API key, try to fetch from server-side encrypted store
    if (!apiKey && isServerKeyStorageAvailable()) {
      try {
        const serverKey = getServerApiKey(session.userId, selectedProvider);
        if (serverKey) {
          apiKey = serverKey;
        }
      } catch (err) {
        logger.warn('[API/generate] Failed to retrieve server-side API key:', err);
      }
    }

    if (!prompt && !messages) {
      return NextResponse.json(
        { error: 'Either prompt or messages is required' },
        { status: 400 }
      );
    }

    if (providerConfig.apiKeyRequired && !apiKey && !providerConfig.usesOAuth) {
      return NextResponse.json(
        { error: `${providerConfig.name} API key is required. Please set it in settings.` },
        { status: 400 }
      );
    }

    let systemPrompt = `You operate in a sandboxed virtual terminal.

Guidelines:
- Create semantic, accessible HTML5; modern CSS3; clean JS (ES6+).
- Use relative paths; keep structure simple; prefer early returns.

Capabilities:
- One tool: bash({ command: string }) for commands and file editing.
- Edit files with bash: cat > /file << 'EOF' for full rewrites, sed -i 's/old/new/g' for substitutions.
- Supported commands: ls, cat, nl [-ba], grep (-n -i), find (-name), mkdir -p, rm [-rfv], rmdir [-v], mv, cp [-r], echo, sed [-i] 's/pat/repl/[g]'.
- Supports pipes (|), redirects (> >>), and && chaining.
- No network; only /workspace paths exist.
  • Note: both '/path' and '/workspace/path' are accepted; '/workspace' is normalized to '/'.

Habits:
- Read with ls/cat/grep/find before editing.
- Persist file content changes with cat > or sed -i; use mv/rm/mkdir/cp for structure.
- Keep changes small and atomic.`;

    if (context?.fileTree) {
      systemPrompt += `\n\nCurrent project structure:\n${context.fileTree}`;
    }

    if (context?.existingFiles && Array.isArray(context.existingFiles)) {
      systemPrompt += `\n\nExisting files (modify via cat > or sed -i; use mv/rm for structure):\n${context.existingFiles.join('\n')}`;
    }

    if (context?.mainFiles && Object.keys(context.mainFiles).length > 0) {
      systemPrompt += `\n\nCurrent file contents (use exact text when crafting write operations):`;
      for (const [path, content] of Object.entries(context.mainFiles)) {
        const contentStr = String(content);
        const truncatedContent = contentStr.length > 1000 ? contentStr.substring(0, 1000) + '\n... (truncated)' : contentStr;
        systemPrompt += `\n\n=== ${path} ===\n${truncatedContent}`;
      }
    }

    if (context?.instructions) {
      systemPrompt += `\n\nAdditional instructions:\n${context.instructions}`;
    }

    const chatMessages = messages || [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: prompt }
    ];
    
    if (messages && !messages.some((m: LLMMessage) => m.role === 'system')) {
      chatMessages.unshift({ role: 'system', content: systemPrompt });
    }

    // --- Codex provider: delegate entirely to codex-adapter ---
    if (selectedProvider === 'openai-codex') {
      // Validate tools before passing to Codex
      const validTools = tools?.filter((tool: { name?: string; description?: string; parameters?: unknown }) => {
        if (!tool.name || tool.name.trim() === '') return false;
        return true;
      });

      return handleCodexGeneration({
        messages: chatMessages,
        model: model || 'gpt-5.3-codex',
        tools: validTools?.length > 0 ? validTools : undefined,
        accessToken: apiKey,
        signal: request.signal,
      });
    }

    const headers = buildHeaders(selectedProvider, apiKey, request, providerConfig);
    
    let processedMessages = chatMessages;
    let anthropicSystemPrompt = '';
    
    if (selectedProvider === 'anthropic') {
      const systemMessage = chatMessages.find((msg: LLMMessage) => msg.role === 'system');
      if (systemMessage) {
        anthropicSystemPrompt = getTextContent(systemMessage.content);
      }
      
      processedMessages = [];
      let currentUserMessage: any = null;
      
      for (const msg of chatMessages) {
        if (msg.role === 'system') {
          continue;
        } else if (msg.role === 'tool') {
          if (currentUserMessage && currentUserMessage.role === 'user') {
            if (!Array.isArray(currentUserMessage.content)) {
              currentUserMessage = {
                ...currentUserMessage,
                content: [{ type: 'text', text: currentUserMessage.content }]
              };
            }
            currentUserMessage.content.push({
              type: 'tool_result',
              tool_use_id: msg.tool_call_id,
              content: msg.content
            });
          } else {
            currentUserMessage = {
              role: 'user',
              content: [{
                type: 'tool_result',
                tool_use_id: msg.tool_call_id,
                content: msg.content
              }]
            };
          }
        } else {
          if (currentUserMessage && currentUserMessage.role === 'user') {
            processedMessages.push(currentUserMessage);
          }
          
          if (msg.role === 'assistant' && msg.tool_calls) {
            const content = [];
            if (msg.content) {
              content.push({ type: 'text', text: msg.content });
            }
            for (const toolCall of msg.tool_calls) {
              let input = {};
              try { input = JSON.parse(toolCall.function.arguments || '{}'); } catch { /* malformed args from truncated stream */ }
              content.push({
                type: 'tool_use',
                id: toolCall.id,
                name: toolCall.function.name,
                input,
              });
            }

            currentUserMessage = {
              role: 'assistant',
              content: content
            };
          } else {
            // Ensure non-empty content for Anthropic
            const messageContent = msg.content || '';
            if (!messageContent && msg.role === 'assistant') {
              // Skip empty assistant messages (Anthropic rejects them)
              currentUserMessage = null;
            } else if (msg.role === 'user' && typeof msg.content !== 'string') {
              // Handle multimodal user messages - transform to Anthropic format
              currentUserMessage = {
                ...msg,
                content: toAnthropicContent(msg.content)
              };
            } else {
              currentUserMessage = { ...msg };
            }
          }
          
          if (msg.role !== 'user' && currentUserMessage) {
            processedMessages.push(currentUserMessage);
            currentUserMessage = null;
          }
        }
      }
      
      if (currentUserMessage && currentUserMessage.role === 'user') {
        processedMessages.push(currentUserMessage);
      }
    }

    // Handle Ollama images - extract to request level
    let ollamaImages: string[] = [];
    if (selectedProvider === 'ollama') {
      const { processedMessages: ollamaMessages, images } = extractOllamaImages(processedMessages);
      processedMessages = ollamaMessages;
      ollamaImages = images;
    }

    const streamEnabled = requestStream !== false;
    const apiEndpoint = getApiEndpoint(selectedProvider, providerConfig, model, { apiKey, stream: streamEnabled });

    // --- Gemini: build entirely different request body ---
    if (selectedProvider === 'gemini') {
      // Validate tools if present
      let validTools: any[] = [];
      if (tools && tools.length > 0) {
        validTools = tools.filter((tool: { name?: string }) => tool.name && tool.name.trim() !== '');
        if (validTools.length === 0) {
          return NextResponse.json(
            { error: 'All tools are invalid. Tools must have a name field.' },
            { status: 400 }
          );
        }
      }

      const modelName = model || '';
      const needsReasoning = modelName.includes('thinking') || modelName.includes('2.5') || modelName.includes('3-pro');
      const geminiBody = buildGeminiRequestBody(processedMessages, {
        maxTokens: max_tokens,
        temperature: 0.7,
        tools: validTools.length > 0 ? validTools : undefined,
        reasoning: needsReasoning ? { max_tokens: 4096 } : undefined,
      });

      const response = await fetch(apiEndpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify(geminiBody),
        signal: request.signal,
      });

      if (!response.ok) {
        const errorText = await response.text();
        let cleanError: string;
        try {
          const parsed = JSON.parse(errorText);
          cleanError = parsed.error?.message || `HTTP ${response.status}`;
        } catch {
          cleanError = `HTTP ${response.status} — ${response.statusText || 'check your API key and try again'}`;
        }
        return NextResponse.json(
          { error: `Google Gemini API error: ${cleanError}` },
          { status: response.status }
        );
      }

      if (!streamEnabled) {
        const data = await response.json();
        return NextResponse.json(data);
      }

      return new Response(response.body, {
        headers: {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
        },
      });
    }

    // Convert reasoning_details → reasoning_content on assistant messages for providers
    // that require reasoning to be passed back as a string (OpenRouter/DeepSeek/Zhipu).
    // The streaming parser stores structured reasoning_details for internal use, but
    // the API expects reasoning_content (string) on input messages for multi-turn replay.
    if (selectedProvider !== 'anthropic') {
      for (const msg of processedMessages) {
        if (msg.role === 'assistant' && msg.reasoning_details?.length) {
          const reasoningText = msg.reasoning_details
            .filter((rd: ReasoningDetail) => rd.text)
            .map((rd: ReasoningDetail) => rd.text)
            .join('');
          if (reasoningText) {
            (msg as Record<string, unknown>).reasoning_content = reasoningText;
          }
          delete (msg as Record<string, unknown>).reasoning_details;
        }
      }
    }

    // Sanitize tool_calls: replace invalid JSON arguments with '{}' so providers
    // don't reject the request. Truncated streaming can leave malformed args in history.
    for (const msg of processedMessages) {
      if (msg.role === 'assistant' && msg.tool_calls) {
        for (const tc of msg.tool_calls) {
          if (tc.function?.arguments) {
            try { JSON.parse(tc.function.arguments); } catch {
              tc.function.arguments = '{}';
            }
          }
        }
      }
    }

    // --- All other providers: OpenAI-compatible request body ---
    const requestBody: Record<string, unknown> = {
      model: model || getDefaultModel(selectedProvider),
      messages: processedMessages,
      stream: streamEnabled
    };

    // Request usage stats in streaming responses (needed for compaction threshold).
    // Most OpenAI-compatible providers support this; skip for local servers that may reject it.
    if (streamEnabled && selectedProvider !== 'ollama' && selectedProvider !== 'lmstudio' && selectedProvider !== 'anthropic') {
      requestBody.stream_options = { include_usage: true };
    }

    // Add images for Ollama at request level
    if (selectedProvider === 'ollama' && ollamaImages.length > 0) {
      requestBody.images = ollamaImages;
    }

    if (selectedProvider === 'anthropic' && anthropicSystemPrompt) {
      requestBody.system = anthropicSystemPrompt;
    }

    if (tools && tools.length > 0) {
      // Validate tools to ensure all required fields are present
      const validTools = tools.filter((tool: { name?: string; description?: string; parameters?: unknown }) => {
        if (!tool.name || tool.name.trim() === '') {
          logger.error('[API] Tool missing required "name" field:', tool);
          return false;
        }
        if (!tool.description) {
          logger.warn('[API] Tool missing "description" field:', tool.name);
        }
        if (!tool.parameters) {
          logger.warn('[API] Tool missing "parameters" field:', tool.name);
        }
        return true;
      });

      if (validTools.length === 0) {
        return NextResponse.json(
          { error: 'All tools are invalid. Tools must have a name field.' },
          { status: 400 }
        );
      }

      if (selectedProvider === 'anthropic') {
        requestBody.tools = validTools.map((tool: { name: string; description: string; parameters: unknown }) => ({
          name: tool.name,
          description: tool.description,
          input_schema: tool.parameters
        }));
        if (tool_choice && typeof tool_choice === 'object') {
          requestBody.tool_choice = tool_choice;
        } else if (tool_choice === 'auto' || !tool_choice) {
          requestBody.tool_choice = { type: 'auto' };
        } else if (tool_choice === 'any') {
          requestBody.tool_choice = { type: 'any' };
        } else if (typeof tool_choice === 'string') {
          requestBody.tool_choice = { type: 'tool', name: tool_choice };
        } else {
          requestBody.tool_choice = { type: 'auto' };
        }
      } else {
        requestBody.tools = validTools.map((tool: { name: string; description: string; parameters: unknown }) => ({
          type: 'function',
          function: tool
        }));
        requestBody.tool_choice = tool_choice || 'auto';
      }
    }

    if (selectedProvider === 'openai') {
      requestBody.max_completion_tokens = max_tokens || 4096;

      const modelName = model || getDefaultModel(selectedProvider);
      if (modelName.includes('gpt-5-nano')) {
        // gpt-5-nano requires temperature=1; other values cause API errors
        requestBody.temperature = 1;
      } else {
        requestBody.temperature = 0.7;
      }
    } else if (selectedProvider === 'anthropic') {
      requestBody.max_tokens = max_tokens || 4096;
      requestBody.temperature = 0.7;
    } else {
      requestBody.max_tokens = max_tokens || 4096;
      requestBody.temperature = 0.7;
    }

    // Enable reasoning for models that support it
    const modelName = model || '';

    // Handle client-requested reasoning (for models that support toggleable reasoning)
    if (reasoning && selectedProvider === 'openrouter') {
      requestBody.reasoning = reasoning;
    }
    if (reasoning && selectedProvider === 'zhipu') {
      requestBody.thinking = { type: 'enabled' };
    }

    // DeepSeek V3.2+ models - some providers (e.g., AtlasCloud) may have issues with tool calling
    // Route to DeepSeek's native API for better reliability
    const isDeepSeekV3_2 = modelName.includes('deepseek') && modelName.includes('v3.2');
    if (selectedProvider === 'openrouter' && isDeepSeekV3_2) {
      // Use provider routing to prefer DeepSeek's native endpoint
      requestBody.provider = {
        order: ['DeepSeek'],  // Provider name from endpoints API
        allow_fallbacks: true
      };
    }

    const response = await fetch(apiEndpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(requestBody),
      signal: request.signal,
    });

    if (!response.ok) {
      const errorText = await response.text();

      // Try to parse and extract clean error message from JSON response
      let cleanError = errorText;
      try {
        const parsed = JSON.parse(errorText);
        // OpenRouter nested error structure: { error: { message: "...", metadata: { raw: "..." } } }
        if (parsed.error?.message) {
          cleanError = parsed.error.message;
          // Check for more detailed error in metadata.raw (OpenRouter provider errors)
          if (parsed.error.metadata?.raw) {
            try {
              const rawError = JSON.parse(parsed.error.metadata.raw);
              if (rawError.error?.message) {
                cleanError = `${parsed.error.message}: ${rawError.error.message}`;
              }
            } catch {
              // raw isn't JSON, append as-is if it adds info
              if (parsed.error.metadata.raw !== parsed.error.message) {
                cleanError = `${parsed.error.message} (${parsed.error.metadata.raw})`;
              }
            }
          }
          // Also check for provider_name in metadata
          if (parsed.error.metadata?.provider_name) {
            cleanError = `[${parsed.error.metadata.provider_name}] ${cleanError}`;
          }
        } else if (typeof parsed.error === 'string') {
          cleanError = parsed.error;
        }
        // Log full error for debugging
        logger.error('[API] Provider error details:', JSON.stringify(parsed, null, 2));
      } catch {
        // Not JSON — check if it's HTML (provider returned a web page instead of API error)
        if (errorText.trimStart().startsWith('<!') || errorText.trimStart().startsWith('<html')) {
          cleanError = `HTTP ${response.status} — ${response.statusText || 'check your API key and try again'}`;
        }
        logger.error('[API] Provider error (raw):', errorText.slice(0, 500));
      }

      const rateLimitHeaders: Record<string, string> = {};
      if (response.status === 429) {
        const retryAfter = response.headers.get('Retry-After');
        const rateLimitReset = response.headers.get('X-RateLimit-Reset');
        const rateLimitRemaining = response.headers.get('X-RateLimit-Remaining');

        if (retryAfter) rateLimitHeaders['Retry-After'] = retryAfter;
        if (rateLimitReset) rateLimitHeaders['X-RateLimit-Reset'] = rateLimitReset;
        if (rateLimitRemaining) rateLimitHeaders['X-RateLimit-Remaining'] = rateLimitRemaining;
      }
      // --- Provider-specific error handling ---
      const lowerError = cleanError.toLowerCase();

      // Auth errors — actionable message for all providers
      if (response.status === 401 || response.status === 403) {
        const providerName = providerConfig.name;
        const authHint = providerConfig.usesOAuth
          ? `Try reconnecting your ${providerName} account in Settings.`
          : `Check your ${providerName} API key in Settings.`;
        return NextResponse.json(
          { error: `${providerName} authentication failed. ${authHint}` },
          { status: response.status }
        );
      }

      // Transient rate-limit (429 with rate-limit phrasing or a Retry-After header).
      // Checked BEFORE credit-exhaustion so messages like "temporarily rate-limited
      // upstream, retry shortly" don't get misclassified as credit exhaustion just
      // because the substring "limit" appears inside "rate-limited".
      if (response.status === 429 && (
        rateLimitHeaders['Retry-After'] ||
        lowerError.includes('rate-limited') ||
        lowerError.includes('rate limit') ||
        lowerError.includes('too many requests') ||
        lowerError.includes('temporarily') ||
        lowerError.includes('retry shortly') ||
        lowerError.includes('retry after')
      )) {
        return NextResponse.json(
          { error: `${providerConfig.name} is temporarily rate-limited. Try again in a moment.` },
          { status: 429, headers: rateLimitHeaders }
        );
      }

      // Credit/quota exhaustion (402, or 429 with usage-related keywords).
      // Note: "limit" is intentionally excluded because it false-matches "rate-limited".
      if (response.status === 402 || (response.status === 429 && (
        lowerError.includes('credit') || lowerError.includes('quota') ||
        lowerError.includes('billing') || lowerError.includes('exceeded') ||
        lowerError.includes('insufficient') || lowerError.includes('usage')
      ))) {
        if (selectedProvider === 'huggingface') {
          return NextResponse.json(
            { error: 'HuggingFace free usage limit reached. You get $0.10/month in free inference. Upgrade at huggingface.co/pricing or wait for your credits to reset.' },
            { status: 429 }
          );
        }
        if (selectedProvider === 'openrouter') {
          return NextResponse.json(
            { error: 'OpenRouter credit limit reached. Add credits at openrouter.ai/credits or switch to a provider with your own API key.' },
            { status: 429 }
          );
        }
        return NextResponse.json(
          { error: `${providerConfig.name} usage limit reached. Check your billing or plan at your provider's dashboard.` },
          { status: 429 }
        );
      }

      // Model not found / removed (400 or 404)
      if ((response.status === 400 || response.status === 404) && (
        lowerError.includes('not found') || lowerError.includes('does not exist') ||
        lowerError.includes('no such model') || lowerError.includes('invalid model')
      )) {
        return NextResponse.json(
          { error: `Model not available on ${providerConfig.name}. It may have been removed or renamed. Try selecting a different model in Settings.` },
          { status: 400 }
        );
      }

      // Tool/function calling not supported (400)
      if (response.status === 400 && (
        lowerError.includes('does not support tools') ||
        (lowerError.includes('tool') && lowerError.includes('not supported')) ||
        (lowerError.includes('function call') && lowerError.includes('not supported'))
      )) {
        // Local providers: fall back to JSON-based tool calling
        if (providerConfig.isLocal && tools && tools.length > 0) {
        const fallbackSystemPrompt = systemPrompt + `

IMPORTANT: This model doesn't support native function calling, so you must use JSON format for tool calls.

Available tools:
${tools.map((tool: ToolDefinition) => `
- ${tool.name}: ${tool.description}
  Parameters: ${JSON.stringify(tool.parameters, null, 2)}
`).join('')}

When you need to use a tool, respond with:
\`\`\`json
{
  "tool_calls": [
    {
      "id": "call_1",
      "function": {
        "name": "tool_name",
        "arguments": "{\"param1\": \"value1\"}"
      }
    }
  ]
}
\`\`\`

You can make multiple tool calls in a single response. Always include the tool_calls array even for a single tool call.`;

        const fallbackMessages = [...chatMessages];
        const systemMsgIndex = fallbackMessages.findIndex(m => m.role === 'system');
        if (systemMsgIndex >= 0) {
          fallbackMessages[systemMsgIndex].content = fallbackSystemPrompt;
        }

        const fallbackBody: any = {
          ...requestBody,
          messages: fallbackMessages
        };
        delete fallbackBody.tools;
        delete fallbackBody.tool_choice;

        const fallbackResponse = await fetch(apiEndpoint, {
          method: 'POST',
          headers,
          body: JSON.stringify(fallbackBody),
          signal: request.signal,
        });

        if (!fallbackResponse.ok) {
          let fallbackError = await fallbackResponse.text();
          if (fallbackError.trimStart().startsWith('<!') || fallbackError.trimStart().startsWith('<html')) {
            fallbackError = `HTTP ${fallbackResponse.status} — ${fallbackResponse.statusText || 'unknown error'}`;
          }
          return NextResponse.json(
            { error: `${providerConfig.name} API error (after fallback): ${fallbackError}` },
            { status: fallbackResponse.status }
          );
        }

        const fallbackHeaders: Record<string, string> = {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
          'X-Tool-Fallback': 'json-parsing'
        };

        return new Response(fallbackResponse.body, {
          headers: fallbackHeaders,
        });
        }
        // Non-local providers: actionable error message
        return NextResponse.json(
          { error: `This model does not support tool/function calling. Try a different model or switch to OpenRouter with MiniMax M2.7.` },
          { status: 400 }
        );
      }

      // Anthropic overloaded (529) — transient, will be retried by orchestrator
      if (response.status === 529) {
        return NextResponse.json(
          { error: `${providerConfig.name} is temporarily overloaded. The request will be retried automatically.` },
          { status: 529 }
        );
      }

      // OpenRouter 503 — no provider available for this model/routing config
      if (selectedProvider === 'openrouter' && response.status === 503) {
        return NextResponse.json(
          { error: `No provider currently available for this model on OpenRouter. The model may be temporarily down. Try a different model or wait a few minutes.` },
          { status: 503 }
        );
      }

      return NextResponse.json(
        { error: `${providerConfig.name} API error: ${cleanError}` },
        { status: response.status, headers: rateLimitHeaders }
      );
    }

    // Non-streaming: return JSON directly
    if (!streamEnabled) {
      const data = await response.json();
      return NextResponse.json(data);
    }

    const responseHeaders: Record<string, string> = {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    };

    if (selectedProvider === 'openrouter') {
      const openRouterHeaders = [
        'x-openrouter-generation-id',
        'x-openrouter-usage',
        'x-openrouter-tokens',
        'x-openrouter-cost'
      ];

      for (const headerName of openRouterHeaders) {
        const value = response.headers.get(headerName);
        if (value) {
          responseHeaders[headerName] = value;
        }
      }
    }

    return new Response(response.body, {
      headers: responseHeaders,
    });
  } catch (error) {
    // Client disconnected — abort is expected, no error response needed
    if (error instanceof Error && error.name === 'AbortError') {
      return new Response(null, { status: 499 });
    }
    const message = error instanceof Error ? error.message : 'Unknown error';
    const isNetwork = /fetch failed|Failed to fetch|NetworkError/i.test(message);
    const friendly = isNetwork
      ? 'Network error: unable to reach the model API. Check your internet connection or proxy settings.'
      : message;
    return NextResponse.json(
      { error: friendly },
      { status: isNetwork ? 503 : 500 }
    );
  }
}

function getApiEndpoint(provider: ProviderId, config: ReturnType<typeof getProvider>, model?: string, options?: { apiKey?: string; stream?: boolean }): string {
  const baseUrl = config.baseUrl || 'https://openrouter.ai/api/v1';

  if (provider === 'anthropic') {
    return 'https://api.anthropic.com/v1/messages';
  } else if (provider === 'gemini') {
    const geminiModel = model || 'gemini-2.5-flash';
    const action = options?.stream ? 'streamGenerateContent?alt=sse' : 'generateContent';
    const key = options?.apiKey ? `${options.stream ? '&' : '?'}key=${options.apiKey}` : '';
    return `https://generativelanguage.googleapis.com/v1beta/models/${geminiModel}:${action}${key}`;
  } else {
    return `${baseUrl}/chat/completions`;
  }
}

function buildHeaders(
  provider: ProviderId, 
  apiKey: string | undefined,
  request: NextRequest,
  config: ReturnType<typeof getProvider>
): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json'
  };
  
  if (provider === 'anthropic') {
    headers['x-api-key'] = apiKey || '';
    headers['anthropic-version'] = '2023-06-01';
    if (config.supportsFunctions) {
      headers['anthropic-beta'] = 'tools-2024-04-04';
    }
  } else if (provider === 'gemini') {
    // Gemini uses query-param key auth; no auth headers needed
  } else {
    if (apiKey) {
      headers['Authorization'] = `Bearer ${apiKey}`;
    }
    
    if (provider === 'openrouter') {
      headers['HTTP-Referer'] = request.headers.get('referer') || 'http://localhost:3000';
      headers['X-Title'] = 'OSW-Studio';
    }
  }
  
  return headers;
}
