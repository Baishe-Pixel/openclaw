import type { AgentExecutionAuthBinding } from "./execution-auth-binding.js";

export type SessionSuccessfulAuthBinding = {
  sessionKey: string;
  sessionId: string;
  lifecycleRevision: string;
  provider: string;
  model: string;
  modelApi?: string;
  authProfileId: string;
  authFingerprint: string;
};

const MAX_SESSION_BINDINGS = 2_048;
const bindings = new Map<string, SessionSuccessfulAuthBinding>();

/** Publish only the credential that completed an accepted terminal-success chat turn. */
export function recordSessionSuccessfulAuthBinding(params: {
  sessionKey: string | undefined;
  sessionId: string | undefined;
  lifecycleRevision: string | undefined;
  provider: string;
  model: string;
  binding: AgentExecutionAuthBinding | undefined;
}): void {
  const sessionKey = params.sessionKey?.trim();
  const sessionId = params.sessionId?.trim();
  const authProfileId = params.binding?.authProfileId?.trim();
  const authFingerprint = params.binding?.authFingerprint?.trim();
  if (
    !sessionKey ||
    !sessionId ||
    params.lifecycleRevision === undefined ||
    !authProfileId ||
    !authFingerprint
  ) {
    if (sessionKey) {
      bindings.delete(sessionKey);
    }
    return;
  }
  bindings.delete(sessionKey);
  bindings.set(sessionKey, {
    sessionKey,
    sessionId,
    lifecycleRevision: params.lifecycleRevision,
    provider: params.provider,
    model: params.model,
    ...(params.binding?.modelApi ? { modelApi: params.binding.modelApi } : {}),
    authProfileId,
    authFingerprint,
  });
  while (bindings.size > MAX_SESSION_BINDINGS) {
    const oldest = bindings.keys().next().value;
    if (oldest === undefined) {
      break;
    }
    bindings.delete(oldest);
  }
}

/** Exact session identity and selected route must still match at the read edge. */
export function readSessionSuccessfulAuthBinding(params: {
  sessionKey: string;
  sessionId: string | undefined;
  lifecycleRevision: string | undefined;
  provider: string | undefined;
  model: string | undefined;
}): SessionSuccessfulAuthBinding | undefined {
  const binding = bindings.get(params.sessionKey);
  if (
    !binding ||
    binding.sessionId !== params.sessionId ||
    binding.lifecycleRevision !== params.lifecycleRevision ||
    binding.provider !== params.provider ||
    binding.model !== params.model
  ) {
    return undefined;
  }
  return binding;
}

export function invalidateSessionSuccessfulAuthBinding(sessionKey: string): void {
  bindings.delete(sessionKey);
}

export function clearSessionSuccessfulAuthBindingsForTest(): void {
  bindings.clear();
}
