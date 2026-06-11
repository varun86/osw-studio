import { NextRequest, NextResponse } from 'next/server';
import { ProviderId } from '@/lib/llm/providers/types';
import { getProvider } from '@/lib/llm/providers/registry';
import { logger } from '@/lib/utils';
import { requireAuth } from '@/lib/auth/session';
import { getApiKey as getServerApiKey, isServerKeyStorageAvailable } from '@/lib/auth/api-key-store';

export async function POST(request: NextRequest) {
  // Require authentication — this endpoint validates API keys against external providers
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

    // Use client-provided key, or fall back to server-side stored key
    let apiKey = clientApiKey;
    if (!apiKey && isServerKeyStorageAvailable()) {
      try {
        const serverKey = getServerApiKey(session.userId, provider as ProviderId);
        if (serverKey) {
          apiKey = serverKey;
        }
      } catch (err) {
        logger.warn('[API/validate-key] Failed to retrieve server-side API key:', err);
      }
    }

    if (!apiKey) {
      return NextResponse.json(
        { error: 'API key is required' },
        { status: 400 }
      );
    }

    const providerConfig = getProvider(provider as ProviderId);
    let isValid = false;

    switch (provider) {
      case 'openrouter':
        const openrouterResp = await fetch('https://openrouter.ai/api/v1/auth/key', {
          headers: { 'Authorization': `Bearer ${apiKey}` }
        });
        isValid = openrouterResp.ok;
        break;

      case 'openai':
      case 'openai-codex':
        const openaiResp = await fetch('https://api.openai.com/v1/models', {
          headers: { 'Authorization': `Bearer ${apiKey}` }
        });
        isValid = openaiResp.ok;
        break;

      case 'anthropic':
        const anthropicResp = await fetch('https://api.anthropic.com/v1/models', {
          headers: {
            'x-api-key': apiKey,
            'anthropic-version': '2023-06-01'
          }
        });
        isValid = anthropicResp.ok;
        break;

      case 'groq':
        const groqResp = await fetch('https://api.groq.com/openai/v1/models', {
          headers: { 'Authorization': `Bearer ${apiKey}` }
        });
        isValid = groqResp.ok;
        break;

      case 'ollama':
      case 'lmstudio':
      case 'llamacpp':
        const localResp = await fetch(`${providerConfig.baseUrl}/models`);
        isValid = localResp.ok;
        break;

      case 'gemini':
        isValid = !!apiKey && apiKey.length > 10;
        break;

      case 'zhipu':
      case 'minimax':
        isValid = !!apiKey && apiKey.length > 10;
        break;

      case 'huggingface':
        const hfResp = await fetch('https://huggingface.co/api/whoami-v2', {
          headers: { 'Authorization': `Bearer ${apiKey}` }
        });
        isValid = hfResp.ok;
        break;

      default:
        // For other OpenAI-compatible providers
        if (providerConfig.baseUrl) {
          const defaultResp = await fetch(`${providerConfig.baseUrl}/models`, {
            headers: { 'Authorization': `Bearer ${apiKey}` }
          });
          isValid = defaultResp.ok;
        } else {
          isValid = false;
        }
        break;
    }

    return NextResponse.json({ valid: isValid });

  } catch (error) {
    logger.error('Validation error:', error);
    return NextResponse.json({ valid: false });
  }
}
