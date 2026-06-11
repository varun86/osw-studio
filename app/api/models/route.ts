import { NextRequest, NextResponse } from 'next/server';
import { ProviderId } from '@/lib/llm/providers/types';
import { getProvider } from '@/lib/llm/providers/registry';
import { logger } from '@/lib/utils';
import { requireAuth } from '@/lib/auth/session';
import { getApiKey as getServerApiKey, isServerKeyStorageAvailable } from '@/lib/auth/api-key-store';

export async function POST(request: NextRequest) {
  // Require authentication — this endpoint proxies API keys to external providers
  let session;
  try {
    session = await requireAuth();
  } catch {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  try {
    const { apiKey: clientApiKey, provider } = await request.json();
    
    if (!provider) {
      return NextResponse.json(
        { error: 'Provider is required' },
        { status: 400 }
      );
    }

    let apiKey = clientApiKey;

    // If no client-provided API key, try to fetch from server-side encrypted store
    if (!apiKey && isServerKeyStorageAvailable()) {
      try {
        const serverKey = getServerApiKey(session.userId, provider as ProviderId);
        if (serverKey) {
          apiKey = serverKey;
        }
      } catch (err) {
        logger.warn('[API/models] Failed to retrieve server-side API key:', err);
      }
    }

    const providerConfig = getProvider(provider as ProviderId);
    
    // If no API key but required (and not OAuth), return empty array
    if (providerConfig.apiKeyRequired && !apiKey && !providerConfig.usesOAuth) {
      return NextResponse.json({ models: [] });
    }

    let models: Array<string | { id: string; contextLength?: number; inputModalities?: string[] }> = [];

    try {
      switch (provider) {
        case 'openrouter':
          const orResponse = await fetch('https://openrouter.ai/api/v1/models', {
            headers: {
              'Authorization': `Bearer ${apiKey}`,
              'HTTP-Referer': request.headers.get('referer') || 'http://localhost:3000',
              'X-Title': 'OSW-Studio'
            }
          });
          if (orResponse.ok) {
            const orData = await orResponse.json();
            models = orData.data
              ?.filter((model: { id: string }) =>
                model.id.includes('deepseek') ||
                model.id.includes('qwen') ||
                model.id.includes('claude') ||
                model.id.includes('gpt') ||
                model.id.includes('llama')
              )
              ?.map((model: { id: string; context_length: number; architecture?: { input_modalities?: string[] } }) => ({
                id: model.id,
                contextLength: model.context_length,
                inputModalities: model.architecture?.input_modalities,
              })) || [];
          }
          break;

        case 'anthropic':
          const anthropicResponse = await fetch('https://api.anthropic.com/v1/models', {
            headers: {
              'x-api-key': apiKey,
              'anthropic-version': '2023-06-01'
            }
          });
          if (anthropicResponse.ok) {
            const anthropicData = await anthropicResponse.json();
            models = anthropicData.data?.map((model: { id: string; capabilities?: Record<string, { supported?: boolean }> }) => {
              const modalities: string[] = ['text'];
              if (model.capabilities?.image_input?.supported) modalities.push('image');
              return { id: model.id, inputModalities: modalities };
            }) || [];
          }
          break;

        case 'openai':
        case 'openai-codex':
          const openaiResponse = await fetch('https://api.openai.com/v1/models', {
            headers: {
              'Authorization': `Bearer ${apiKey}`
            }
          });
          if (openaiResponse.ok) {
            const openaiData = await openaiResponse.json();
            models = openaiData.data?.map((model: { id: string }) => model.id) || [];
          }
          break;

        case 'groq':
          const groqResponse = await fetch('https://api.groq.com/openai/v1/models', {
            headers: {
              'Authorization': `Bearer ${apiKey}`
            }
          });
          if (groqResponse.ok) {
            const groqData = await groqResponse.json();
            models = groqData.data?.map((model: { id: string }) => model.id) || [];
          }
          break;

        case 'ollama':
          try {
            // Use Ollama's native API endpoint for model discovery
            const ollamaResponse = await fetch(`http://localhost:11434/api/tags`);
            if (ollamaResponse.ok) {
              const ollamaData = await ollamaResponse.json();
              // Ollama returns models array directly in the response
              models = ollamaData.models?.map((m: any) => m.name) || [];
            }
          } catch (error) {
            logger.error('Ollama models fetch error:', error);
          }
          break;

        case 'lmstudio':
          try {
            // LM Studio REST API returns capabilities (vision, tool_use)
            const lmsRestUrl = providerConfig.baseUrl?.replace('/v1', '') || 'http://localhost:1234';
            const lmsResponse = await fetch(`${lmsRestUrl}/api/v1/models`);
            if (lmsResponse.ok) {
              const lmsData = await lmsResponse.json();
              const lmsModels = Array.isArray(lmsData) ? lmsData : lmsData.data || [];
              models = lmsModels
                .filter((m: any) => m.type === 'llm' || !m.type)
                .map((m: any) => {
                  const modalities: string[] = ['text'];
                  if (m.capabilities?.vision) modalities.push('image');
                  return { id: m.id, inputModalities: modalities };
                });
            }
          } catch (error) {
            logger.error('LM Studio models fetch error:', error);
          }
          break;

        case 'llamacpp':
        case 'meshllm':
          try {
            const lmResponse = await fetch(`${providerConfig.baseUrl}/models`);
            if (lmResponse.ok) {
              const lmData = await lmResponse.json();
              models = lmData.data?.map((m: any) => m.id) || [];
            }
          } catch (error) {
            logger.error(`${provider} models fetch error:`, error);
          }
          break;

        case 'gemini':
          const geminiResponse = await fetch(
            `https://generativelanguage.googleapis.com/v1beta/models?pageSize=100&key=${apiKey}`
          );
          if (geminiResponse.ok) {
            const geminiData = await geminiResponse.json();
            models = (geminiData.models || [])
              .filter((m: any) =>
                m.supportedGenerationMethods?.includes('generateContent') &&
                /gemini/i.test(m.name)
              )
              .map((m: any) => ({
                id: m.name.replace('models/', ''),
                contextLength: m.inputTokenLimit,
                inputModalities: m.supportedGenerationMethods?.includes('generateContent')
                  ? ['text', 'image'] : ['text'],
              }));
          }
          break;

        case 'huggingface':
          try {
            const hfHeaders: Record<string, string> = {};
            if (apiKey) {
              hfHeaders['Authorization'] = `Bearer ${apiKey}`;
            }
            const hfResponse = await fetch('https://router.huggingface.co/v1/models', {
              headers: hfHeaders,
            });
            if (hfResponse.ok) {
              const hfData = await hfResponse.json();
              models = hfData.data?.map((m: any) => ({
                id: m.id,
                inputModalities: m.architecture?.input_modalities,
              })) || [];
            }
          } catch (error) {
            logger.error('HuggingFace models fetch error:', error);
          }
          break;

        default:
          // For other OpenAI-compatible providers
          if (providerConfig.baseUrl && apiKey) {
            const defaultResponse = await fetch(`${providerConfig.baseUrl}/models`, {
              headers: {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/json'
              }
            });
            if (defaultResponse.ok) {
              const defaultData = await defaultResponse.json();
              models = defaultData.data?.map((m: any) => m.id) || [];
            }
          }
          break;
      }
    } catch (error) {
      logger.error(`Error fetching models for ${provider}:`, error);
      // Fall back to hardcoded models if available
      if (providerConfig.models) {
        models = providerConfig.models.map(m => m.id);
      }
    }

    return NextResponse.json({ models });

  } catch (error) {
    logger.error('Models API error:', error);
    return NextResponse.json({ models: [] });
  }
}
