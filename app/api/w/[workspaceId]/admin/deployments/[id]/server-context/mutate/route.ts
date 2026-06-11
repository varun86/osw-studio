/**
 * Workspace-Scoped Admin API: Server Context Mutations
 *
 * POST - Handles create/update/delete operations on server context files
 */

import { logger } from '@/lib/utils';
import { NextRequest, NextResponse } from 'next/server';
import { getWorkspaceContext } from '@/lib/api/workspace-context';
import { DeploymentDatabase } from '@/lib/vfs/adapters/deployment-database';
import {
  validateEdgeFunctionData,
  validateServerFunctionData,
  validateSecretData,
  validateScheduledFunctionData,
  generateEdgeFunctionFile,
  generateServerFunctionFile,
  generateSecretFile,
  generateScheduledFunctionFile,
} from '@/lib/vfs/server-context';
import cronParser from 'cron-parser';

interface MutationRequest {
  operation: 'update' | 'create' | 'delete';
  path: string;
  content?: string;
}

interface MutationResponse {
  success: boolean;
  error?: string;
  file?: {
    path: string;
    content: string;
    isReadOnly: boolean;
  };
}

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ workspaceId: string; id: string }> }
): Promise<NextResponse<MutationResponse>> {
  try {
    const { adapter } = await getWorkspaceContext(params);
    const { id: deploymentId } = await params;
    const body: MutationRequest = await request.json();
    const { operation, path, content } = body;

    if (!path) {
      return NextResponse.json({ success: false, error: 'Path is required' }, { status: 400 });
    }

    const deployment = await adapter.getDeployment(deploymentId);
    if (!deployment) {
      return NextResponse.json({ success: false, error: 'Deployment not found' }, { status: 404 });
    }

    const deploymentDb = adapter.getDeploymentDatabaseForAnalytics(deploymentId);
    if (!deploymentDb) {
      return NextResponse.json({ success: false, error: 'Deployment database not available' }, { status: 500 });
    }

    if (operation === 'delete') {
      return handleDelete(path, deploymentDb);
    }

    if (!content) {
      return NextResponse.json({ success: false, error: 'Content is required for create/update' }, { status: 400 });
    }

    if (path === '/.server/db/schema.sql') {
      return NextResponse.json({ success: false, error: `Cannot modify ${path} - read-only file` }, { status: 400 });
    }

    if (path.startsWith('/.server/secrets/') && path.endsWith('.json')) {
      return handleSecretUpdate(path, content, deploymentDb);
    }

    if (path.startsWith('/.server/edge-functions/') && path.endsWith('.json')) {
      return await handleEdgeFunctionUpdate(path, content, deploymentDb);
    }

    if (path.startsWith('/.server/server-functions/') && path.endsWith('.json')) {
      return await handleServerFunctionUpdate(path, content, deploymentDb);
    }

    if (path.startsWith('/.server/scheduled-functions/') && path.endsWith('.json')) {
      return handleScheduledFunctionUpdate(path, content, deploymentDb);
    }

    return NextResponse.json({ success: false, error: `Unrecognized server context path: ${path}` }, { status: 400 });
  } catch (error) {
    if (error instanceof Error && error.message === 'Unauthorized') {
      return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
    }
    if (error instanceof Error && (error.message === 'Workspace access denied' || error.message === 'Insufficient workspace permissions')) {
      return NextResponse.json({ success: false, error: error.message }, { status: 403 });
    }
    logger.error('[API] Server context mutation failed:', error);
    return NextResponse.json(
      { success: false, error: 'Mutation failed' },
      { status: 500 }
    );
  }
}

function handleDelete(path: string, deploymentDb: DeploymentDatabase): NextResponse<MutationResponse> {
  if (path.startsWith('/.server/secrets/') && path.endsWith('.json')) {
    const filename = path.split('/').pop()!.replace('.json', '');
    const secret = deploymentDb.getSecretByName(filename);
    if (!secret) {
      return NextResponse.json({ success: false, error: `Secret not found: ${filename}` }, { status: 404 });
    }
    deploymentDb.deleteSecret(secret.id);
    return NextResponse.json({ success: true });
  }

  if (path.startsWith('/.server/edge-functions/') && path.endsWith('.json')) {
    const filename = path.split('/').pop()!.replace('.json', '');
    const fn = deploymentDb.getFunctionByName(filename);
    if (!fn) {
      return NextResponse.json({ success: false, error: `Edge function not found: ${filename}` }, { status: 404 });
    }
    deploymentDb.deleteFunction(fn.id);
    return NextResponse.json({ success: true });
  }

  if (path.startsWith('/.server/server-functions/') && path.endsWith('.json')) {
    const filename = path.split('/').pop()!.replace('.json', '');
    const fn = deploymentDb.getServerFunctionByName(filename);
    if (!fn) {
      return NextResponse.json({ success: false, error: `Server function not found: ${filename}` }, { status: 404 });
    }
    deploymentDb.deleteServerFunction(fn.id);
    return NextResponse.json({ success: true });
  }

  if (path.startsWith('/.server/scheduled-functions/') && path.endsWith('.json')) {
    const filename = path.split('/').pop()!.replace('.json', '');
    const fn = deploymentDb.getScheduledFunctionByName(filename);
    if (!fn) {
      return NextResponse.json({ success: false, error: `Scheduled function not found: ${filename}` }, { status: 404 });
    }
    deploymentDb.deleteScheduledFunction(fn.id);
    return NextResponse.json({ success: true });
  }

  return NextResponse.json({ success: false, error: `Cannot delete ${path}` }, { status: 400 });
}

function handleSecretUpdate(path: string, content: string, deploymentDb: DeploymentDatabase): NextResponse<MutationResponse> {
  let data: unknown;
  try {
    data = JSON.parse(content);
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    return NextResponse.json({ success: false, error: `Invalid JSON: ${message}` }, { status: 400 });
  }

  const validation = validateSecretData(data);
  if (!validation.valid) {
    return NextResponse.json({ success: false, error: `Validation failed: ${validation.errors.join('; ')}` }, { status: 400 });
  }

  const secretData = data as { name: string; description?: string };
  const filename = path.split('/').pop()!.replace('.json', '');
  const existingSecret = deploymentDb.getSecretByName(filename);

  if (existingSecret) {
    deploymentDb.updateSecretMetadata(existingSecret.id, {
      name: secretData.name,
      description: secretData.description || ''
    });
  } else {
    deploymentDb.createSecretPlaceholder(secretData.name, secretData.description || '');
  }

  const updated = deploymentDb.getSecretByName(secretData.name)!;
  const newPath = `/.server/secrets/${secretData.name}.json`;

  return NextResponse.json({
    success: true,
    file: {
      path: newPath,
      content: generateSecretFile(updated),
      isReadOnly: false,
    }
  });
}

async function handleEdgeFunctionUpdate(path: string, content: string, deploymentDb: DeploymentDatabase): Promise<NextResponse<MutationResponse>> {
  let data: unknown;
  try {
    data = JSON.parse(content);
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    return NextResponse.json({ success: false, error: `Invalid JSON: ${message}` }, { status: 400 });
  }

  const validation = await validateEdgeFunctionData(data);
  if (!validation.valid) {
    return NextResponse.json({ success: false, error: `Validation failed: ${validation.errors.join('; ')}` }, { status: 400 });
  }

  const fnData = data as { name: string; method: string; code: string; description?: string; enabled?: boolean; timeoutMs?: number };
  const filename = path.split('/').pop()!.replace('.json', '');
  const existingFn = deploymentDb.getFunctionByName(filename);

  if (existingFn) {
    deploymentDb.updateFunction(existingFn.id, {
      name: fnData.name,
      code: fnData.code,
      method: fnData.method as 'GET' | 'POST' | 'PUT' | 'DELETE' | 'ANY',
      description: fnData.description,
      enabled: fnData.enabled ?? true,
      timeoutMs: fnData.timeoutMs ?? 5000,
    });
  } else {
    deploymentDb.createFunction({
      name: fnData.name,
      code: fnData.code,
      method: fnData.method as 'GET' | 'POST' | 'PUT' | 'DELETE' | 'ANY',
      description: fnData.description,
      enabled: fnData.enabled ?? true,
      timeoutMs: fnData.timeoutMs ?? 5000,
    });
  }

  const updated = deploymentDb.getFunctionByName(fnData.name)!;
  const newPath = `/.server/edge-functions/${fnData.name}.json`;

  return NextResponse.json({
    success: true,
    file: {
      path: newPath,
      content: generateEdgeFunctionFile(updated),
      isReadOnly: false,
    }
  });
}

async function handleServerFunctionUpdate(path: string, content: string, deploymentDb: DeploymentDatabase): Promise<NextResponse<MutationResponse>> {
  let data: unknown;
  try {
    data = JSON.parse(content);
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    return NextResponse.json({ success: false, error: `Invalid JSON: ${message}` }, { status: 400 });
  }

  const validation = await validateServerFunctionData(data);
  if (!validation.valid) {
    return NextResponse.json({ success: false, error: `Validation failed: ${validation.errors.join('; ')}` }, { status: 400 });
  }

  const fnData = data as { name: string; code: string; description?: string; enabled?: boolean };
  const filename = path.split('/').pop()!.replace('.json', '');
  const existingFn = deploymentDb.getServerFunctionByName(filename);

  if (existingFn) {
    deploymentDb.updateServerFunction(existingFn.id, {
      name: fnData.name,
      code: fnData.code,
      description: fnData.description,
      enabled: fnData.enabled ?? true,
    });
  } else {
    deploymentDb.createServerFunction({
      name: fnData.name,
      code: fnData.code,
      description: fnData.description,
      enabled: fnData.enabled ?? true,
    });
  }

  const updated = deploymentDb.getServerFunctionByName(fnData.name)!;
  const newPath = `/.server/server-functions/${fnData.name}.json`;

  return NextResponse.json({
    success: true,
    file: {
      path: newPath,
      content: generateServerFunctionFile(updated),
      isReadOnly: false,
    }
  });
}

function handleScheduledFunctionUpdate(path: string, content: string, deploymentDb: DeploymentDatabase): NextResponse<MutationResponse> {
  let data: unknown;
  try {
    data = JSON.parse(content);
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    return NextResponse.json({ success: false, error: `Invalid JSON: ${message}` }, { status: 400 });
  }

  const validation = validateScheduledFunctionData(data);
  if (!validation.valid) {
    return NextResponse.json({ success: false, error: `Validation failed: ${validation.errors.join('; ')}` }, { status: 400 });
  }

  const fnData = data as { name: string; functionName: string; cronExpression: string; timezone?: string; description?: string; enabled?: boolean; config?: Record<string, unknown> };

  try {
    const checkInterval = cronParser.parseExpression(fnData.cronExpression);
    const first = checkInterval.next().toDate().getTime();
    const second = checkInterval.next().toDate().getTime();
    if (second - first < 5 * 60 * 1000 - 1000) {
      return NextResponse.json({ success: false, error: 'Minimum interval is 5 minutes' }, { status: 400 });
    }
  } catch {
    return NextResponse.json({ success: false, error: 'Invalid cron expression' }, { status: 400 });
  }

  const edgeFn = deploymentDb.getFunctionByName(fnData.functionName);
  if (!edgeFn) {
    return NextResponse.json({ success: false, error: `Edge function not found: ${fnData.functionName}` }, { status: 400 });
  }

  const filename = path.split('/').pop()!.replace('.json', '');
  const existingFn = deploymentDb.getScheduledFunctionByName(filename);

  if (!existingFn) {
    const allScheduled = deploymentDb.listScheduledFunctions();
    if (allScheduled.length >= 50) {
      return NextResponse.json({ success: false, error: 'Maximum of 50 scheduled functions per deployment' }, { status: 400 });
    }
  }

  let nextRunAt: Date | undefined;
  try {
    const interval = cronParser.parseExpression(fnData.cronExpression, { tz: fnData.timezone || 'UTC', currentDate: new Date() });
    nextRunAt = interval.next().toDate();
  } catch {
    // Leave undefined
  }

  if (existingFn) {
    deploymentDb.updateScheduledFunction(existingFn.id, {
      name: fnData.name,
      functionId: edgeFn.id,
      cronExpression: fnData.cronExpression,
      timezone: fnData.timezone || 'UTC',
      description: fnData.description,
      enabled: fnData.enabled ?? true,
      config: fnData.config || {},
      nextRunAt,
    });
  } else {
    deploymentDb.createScheduledFunction({
      name: fnData.name,
      functionId: edgeFn.id,
      cronExpression: fnData.cronExpression,
      timezone: fnData.timezone || 'UTC',
      description: fnData.description,
      enabled: fnData.enabled ?? true,
      config: fnData.config || {},
      nextRunAt,
    });
  }

  const updated = deploymentDb.getScheduledFunctionByName(fnData.name)!;
  const newPath = `/.server/scheduled-functions/${fnData.name}.json`;

  return NextResponse.json({
    success: true,
    file: {
      path: newPath,
      content: generateScheduledFunctionFile(updated, edgeFn.name),
      isReadOnly: false,
    }
  });
}
