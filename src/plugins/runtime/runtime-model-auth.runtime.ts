// Runtime model auth helpers expose provider auth resolution to plugin runtimes.
import { resolveApiKeyForProfile, type AuthProfileStore } from "../../agents/auth-profiles.js";
import {
  fingerprintAuthAccountIdentity,
  fingerprintResolvedAuthProfileCredential,
} from "../../agents/execution-auth-binding.js";
import { getApiKeyForModelCore } from "../../agents/model-auth.js";
import {
  readReplySuccessfulAuthBinding,
  replaceSessionSuccessfulAuthFingerprint,
} from "../../agents/session-successful-auth-binding.js";
import type { OpenClawConfig } from "../../config/types.openclaw.js";
import { loadCredentialUsageStatusStaleWhileRevalidate } from "../../gateway/server-methods/models-auth-status-usage-cache.js";
import { getProviderUsageRuntimeSnapshot } from "../../gateway/server-methods/provider-usage-runtime.js";
import type { UsageSummary } from "../../infra/provider-usage.types.js";
import type { Model } from "../../llm/types.js";
import { isUserModelAuthProfileId } from "../../state/user-model-account-id.js";
import { prepareProviderRuntimeAuth } from "../provider-runtime.runtime.js";
import type { ResolvedProviderRuntimeAuth } from "./model-auth-types.js";

export {
  getApiKeyForModelCore as getApiKeyForModel,
  resolveApiKeyForProviderCore as resolveProviderRuntimeApiKey,
} from "../../agents/model-auth.js";

/**
 * Resolve request-ready auth for a runtime model, applying any provider-owned
 * `prepareRuntimeAuth` exchange on top of the standard credential lookup.
 */
export async function getRuntimeAuthForModelCore(params: {
  model: Model;
  cfg?: OpenClawConfig;
  workspaceDir?: string;
}): Promise<ResolvedProviderRuntimeAuth> {
  const resolvedAuth = await getApiKeyForModelCore({
    model: params.model,
    cfg: params.cfg,
    workspaceDir: params.workspaceDir,
  });

  if (!resolvedAuth.apiKey || resolvedAuth.mode === "aws-sdk") {
    return resolvedAuth;
  }

  const preparedAuth = await prepareProviderRuntimeAuth({
    provider: params.model.provider,
    config: params.cfg,
    workspaceDir: params.workspaceDir,
    env: process.env,
    context: {
      config: params.cfg,
      workspaceDir: params.workspaceDir,
      env: process.env,
      provider: params.model.provider,
      modelId: params.model.id,
      model: params.model,
      apiKey: resolvedAuth.apiKey,
      authMode: resolvedAuth.mode,
      profileId: resolvedAuth.profileId,
    },
  });

  if (!preparedAuth) {
    return resolvedAuth;
  }

  return {
    ...resolvedAuth,
    ...preparedAuth,
    apiKey: preparedAuth.apiKey ?? resolvedAuth.apiKey,
  };
}

function unavailableReplyUsage(
  sessionKey: string,
  reason: NonNullable<UsageSummary["sessionScope"]>["reason"],
): UsageSummary {
  return {
    updatedAt: Date.now(),
    providers: [],
    sessionScope: {
      status: "unavailable",
      requestedSessionKey: sessionKey,
      effectiveSessionKey: sessionKey,
      reason,
      credential: { consistency: "unavailable" },
      account: { consistency: "unavailable" },
    },
    cache: { status: "unavailable" },
  };
}

/** Resolve quota for the exact accepted reply run without granting general Gateway RPC access. */
export async function getReplyUsageCore(params: {
  runId: string;
  sessionKey: string;
  sessionId: string;
  provider: string;
  model: string;
  agentId: string;
  cfg: OpenClawConfig;
}): Promise<UsageSummary> {
  const bindingParams = {
    runId: params.runId,
    sessionKey: params.sessionKey,
    sessionId: params.sessionId,
    provider: params.provider,
    model: params.model,
  };
  const successful = readReplySuccessfulAuthBinding(bindingParams);
  if (!successful) return unavailableReplyUsage(params.sessionKey, "binding-missing");
  const isCurrent = (expectedFingerprint = successful.authFingerprint) => {
    const current = readReplySuccessfulAuthBinding(bindingParams);
    return (
      current?.lifecycleRevision === successful.lifecycleRevision &&
      current.authProfileId === successful.authProfileId &&
      current.authFingerprint === expectedFingerprint
    );
  };
  const profileId = successful.authProfileId;
  // A historical run proves provenance, not current authority over a personal account.
  // Personal quota remains available only through the Gateway path, which carries a
  // live owner/admin grant to the final provider I/O boundary.
  if (isUserModelAuthProfileId(profileId)) {
    return unavailableReplyUsage(params.sessionKey, "personal-account-authority-required");
  }
  const runtime = getProviderUsageRuntimeSnapshot({ config: params.cfg, agentId: params.agentId });
  const credential = runtime.store.profiles[profileId];
  if (!isCurrent()) return unavailableReplyUsage(params.sessionKey, "credential-changed");
  if (!credential) return unavailableReplyUsage(params.sessionKey, "credential-missing");
  if (credential.provider.trim() !== successful.provider) {
    return unavailableReplyUsage(params.sessionKey, "provider-mismatch");
  }
  const authStore: AuthProfileStore = {
    version: runtime.store.version,
    profiles: { [profileId]: credential },
    order: { [successful.provider]: [profileId] },
    lastGood: { [successful.provider]: profileId },
  };
  let resolvedProfile: Awaited<ReturnType<typeof resolveApiKeyForProfile>>;
  try {
    resolvedProfile = await resolveApiKeyForProfile({
      cfg: params.cfg,
      store: authStore,
      profileId,
      agentDir: runtime.agentDir,
      allowProfileFallback: false,
    });
  } catch {
    return unavailableReplyUsage(params.sessionKey, "auth-unavailable");
  }
  if (!isCurrent() || !resolvedProfile || resolvedProfile.profileId !== profileId) {
    return unavailableReplyUsage(params.sessionKey, "auth-unavailable");
  }
  const resolvedAuth = {
    apiKey: resolvedProfile.apiKey,
    profileId,
    source: "profile:" + profileId,
    mode:
      credential.type === "api_key" ? "api-key" : credential.type === "token" ? "token" : "oauth",
  } as const;
  const boundFingerprint = fingerprintResolvedAuthProfileCredential({
    profileId,
    credential,
    resolvedAuth,
  });
  if (!boundFingerprint || boundFingerprint !== successful.authFingerprint) {
    return unavailableReplyUsage(params.sessionKey, "credential-changed");
  }
  const effectiveCredential =
    credential.type === "oauth" && resolvedProfile.credential?.type === "oauth"
      ? resolvedProfile.credential
      : credential;
  const sampledFingerprint = fingerprintResolvedAuthProfileCredential({
    profileId,
    credential: effectiveCredential,
    resolvedAuth,
  });
  if (!sampledFingerprint || resolvedProfile.provider.trim() !== successful.provider) {
    return unavailableReplyUsage(params.sessionKey, "auth-unavailable");
  }
  const assertCurrent = () => {
    if (!isCurrent()) throw new Error("reply usage authority changed");
  };
  assertCurrent();
  const exactAuth = {
    provider: successful.provider,
    token: resolvedProfile.apiKey,
    authProfileId: profileId,
    ...(effectiveCredential.type === "oauth" && effectiveCredential.authFlow
      ? { authFlow: effectiveCredential.authFlow }
      : {}),
    ...(effectiveCredential.type === "oauth" && effectiveCredential.accountId
      ? { accountId: effectiveCredential.accountId }
      : {}),
    ...(effectiveCredential.type === "oauth" && effectiveCredential.subscriptionType
      ? { subscriptionType: effectiveCredential.subscriptionType }
      : {}),
    ...(effectiveCredential.type === "oauth" && effectiveCredential.rateLimitTier
      ? { rateLimitTier: effectiveCredential.rateLimitTier }
      : {}),
    ...(effectiveCredential.email ? { email: effectiveCredential.email } : {}),
  };
  const summary = await loadCredentialUsageStatusStaleWhileRevalidate({
    agentId: params.agentId,
    agentDir: runtime.agentDir,
    authStore,
    exactAuth,
    config: params.cfg,
    credentialFingerprint: sampledFingerprint,
    accountBindingId: fingerprintAuthAccountIdentity(effectiveCredential.email),
    sessionKey: successful.sessionKey,
    sessionId: successful.sessionId,
    lifecycleRevision: successful.lifecycleRevision,
    providerId: successful.provider,
    authScope: "shared",
    assertCurrent,
  });
  if (!isCurrent()) return unavailableReplyUsage(params.sessionKey, "credential-changed");
  if (sampledFingerprint !== successful.authFingerprint) {
    const replaced = replaceSessionSuccessfulAuthFingerprint({
      sessionKey: successful.sessionKey,
      sessionId: successful.sessionId,
      lifecycleRevision: successful.lifecycleRevision,
      expectedFingerprint: successful.authFingerprint,
      nextFingerprint: sampledFingerprint,
    });
    if (!replaced || !isCurrent(sampledFingerprint)) {
      return unavailableReplyUsage(params.sessionKey, "credential-changed");
    }
  }
  return summary;
}
