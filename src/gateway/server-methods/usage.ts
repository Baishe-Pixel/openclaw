// Gateway usage methods validate requests and assemble owner-scoped usage reports.
import { normalizeOptionalString } from "@openclaw/normalization-core/string-coerce";
import {
  GATEWAY_CLIENT_CAPS,
  hasGatewayClientCap,
} from "../../../packages/gateway-protocol/src/client-info.js";
import {
  ErrorCodes,
  errorShape,
  validateSessionsUsageParams,
  validateUsageStatusParams,
} from "../../../packages/gateway-protocol/src/index.js";
import { resolveApiKeyForProfile, type AuthProfileStore } from "../../agents/auth-profiles.js";
import { readUserModelAuthProfileAsync } from "../../agents/auth-profiles/sqlite-read.js";
import {
  fingerprintAuthAccountIdentity,
  fingerprintResolvedAuthProfileCredential,
} from "../../agents/execution-auth-binding.js";
import {
  readSessionSuccessfulAuthBinding,
  replaceSessionSuccessfulAuthFingerprint,
  type SessionSuccessfulAuthBinding,
} from "../../agents/session-successful-auth-binding.js";
import { sessionCreatorProfileId } from "../../config/sessions/session-entry-provenance.js";
import type { OpenClawConfig } from "../../config/types.openclaw.js";
import type { UsageSummary } from "../../infra/provider-usage.types.js";
import { loadSessionLogs, loadSessionUsageTimeSeries } from "../../infra/session-cost-usage.js";
import { normalizeAgentId } from "../../routing/session-key.js";
import {
  createUsageAggregateAccumulator,
  UNKNOWN_USAGE_CREATOR_KEY,
} from "../../shared/usage-aggregates.js";
import type {
  SessionUsageEntry,
  SessionUsageCreator,
  SessionsUsageAggregates,
  SessionsUsageResult,
} from "../../shared/usage-types.js";
import { captureOpenClawStateWorkerContext } from "../../state/openclaw-state-worker-context.js";
import { isUserModelAuthProfileId } from "../../state/user-model-account-id.js";
import {
  sessionDeliveryChannel,
  sessionDeliveryOrigin,
} from "../../utils/delivery-context.read.js";
import { ModelAccountConnectAuthorityError } from "../model-account-connect.js";
import { operatorSessionCap } from "../operator-role-policy.js";
import { projectSessionActor } from "../session-identity-projection.js";
import { resolveRequestedSessionAgentId } from "../session-request-agent.js";
import { createSessionListEntryFilter, isGatewayAdmin } from "../session-sharing.js";
import { resolveChatMetadataReadParams } from "./chat-metadata-handler.js";
import { gatewayClientSessionCreator } from "./gateway-client-identity.js";
import {
  loadCredentialUsageStatusStaleWhileRevalidate,
  loadUsageStatusStaleWhileRevalidate,
} from "./models-auth-status-usage-cache.js";
import { getProviderUsageRuntimeSnapshot } from "./provider-usage-runtime.js";
import type { GatewayRequestHandlerOptions, GatewayRequestHandlers, RespondFn } from "./types.js";
import {
  formatDateLabel,
  resolveDateInterpretation,
  resolveDateRange,
  resolveDayBucket,
  type DateInterpretation,
  type DateRange,
} from "./usage-date-range.js";
import { loadCostUsageSummaryCached, loadSessionsUsageResultCached } from "./usage-result-cache.js";
import { loadUsageSessionSummaries } from "./usage-session-loading.js";
import {
  loadUsageSessionContext,
  resolveSessionUsageTarget,
  selectUsageSessions,
  UsageSessionInvalidRequestError,
  type UsageGroupingMode,
  type UsageSessionSelection,
} from "./usage-session-selection.js";
import { preparePersonalModelAccountRead } from "./users-model-account-access.js";
import { assertValidParams } from "./validation.js";

function resolveSessionUsageFileOrRespond(
  params: { key?: unknown; agentId?: unknown } | undefined,
  detail: "timeseries" | "logs",
  respond: RespondFn,
  config: OpenClawConfig,
) {
  const key = normalizeOptionalString(params?.key);
  if (!key) {
    respond(
      false,
      undefined,
      errorShape(ErrorCodes.INVALID_REQUEST, `key is required for ${detail}`),
    );
    return null;
  }
  const sessionOwner = resolveRequestedSessionAgentId(
    config,
    key,
    normalizeOptionalString(params?.agentId),
  );
  if (!sessionOwner.ok) {
    respond(false, undefined, sessionOwner.error);
    return null;
  }
  let resolved: NonNullable<ReturnType<typeof resolveSessionUsageTarget>> | undefined;
  try {
    resolved = resolveSessionUsageTarget(key, config, sessionOwner.agentId);
  } catch {
    resolved = undefined;
  }
  if (!resolved) {
    respond(
      false,
      undefined,
      errorShape(ErrorCodes.INVALID_REQUEST, `Invalid session key: ${key}`),
    );
    return null;
  }
  return { config, key, ...resolved };
}

function resolveUsageDateRangeOrRespond(
  params: Parameters<typeof resolveDateRange>[0],
  respond: RespondFn,
): { interpretation: DateInterpretation; range: DateRange } | null {
  const interpretation = resolveDateInterpretation(params);
  if (!interpretation.ok) {
    respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, interpretation.error));
    return null;
  }

  const range = resolveDateRange(params, interpretation.value);
  if (!range.ok) {
    respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, range.error));
    return null;
  }
  return { interpretation: interpretation.value, range: range.value };
}

export type { SessionUsageEntry, SessionsUsageAggregates, SessionsUsageResult };

function projectUsageCreator(
  session: UsageSessionSelection,
  profiles: Parameters<typeof projectSessionActor>[1],
  config: OpenClawConfig,
): SessionUsageCreator {
  const entry = session.storeEntry ?? session.creatorEntry;
  const actor = entry?.createdActor;
  if (!actor) {
    return { key: UNKNOWN_USAGE_CREATOR_KEY };
  }
  const projected = projectSessionActor(
    actor,
    profiles,
    config,
    Boolean(sessionCreatorProfileId(actor)),
  );
  if (!projected?.id && actor.type !== "system") {
    return { key: UNKNOWN_USAGE_CREATOR_KEY };
  }
  const identity = projected?.identity;
  const origin = sessionDeliveryOrigin(entry);
  const channel = sessionDeliveryChannel(entry);
  if (actor.type === "human" && actor.source !== "profile" && !channel) {
    return { key: UNKNOWN_USAGE_CREATOR_KEY };
  }
  const key =
    identity?.type === "profile"
      ? JSON.stringify(["profile", identity.id])
      : actor.type === "human"
        ? JSON.stringify([
            "human",
            actor.source,
            session.agentId,
            channel ?? null,
            origin?.accountId ?? null,
            projected?.id,
          ])
        : actor.type === "agent"
          ? JSON.stringify([identity?.type ?? "agent", identity?.id ?? projected?.id])
          : JSON.stringify(["system", projected?.id ?? null]);
  return { key, ...(projected ? { actor: projected } : {}) };
}

function unavailableSessionCredentialUsage(
  reason: NonNullable<UsageSummary["sessionScope"]>["reason"],
  sessionKey: string,
  successful?: SessionSuccessfulAuthBinding,
): UsageSummary {
  return {
    updatedAt: Date.now(),
    providers: [],
    sessionScope: {
      status: "unavailable",
      requestedSessionKey: sessionKey,
      effectiveSessionKey: sessionKey,
      reason,
      credential: {
        ...(successful ? { sessionBindingId: successful.authFingerprint } : {}),
        consistency: "unavailable",
      },
      account: { consistency: "unavailable" },
    },
    cache: { status: "unavailable" },
  };
}

async function loadSessionCredentialUsage(
  options: GatewayRequestHandlerOptions,
  coldRead: "refresh-marker" | undefined,
) {
  const scope = resolveChatMetadataReadParams(options, {
    sessionKey: normalizeOptionalString(options.params.sessionKey),
  });
  if (!scope) {
    return undefined;
  }
  try {
    const sessionKey = scope.sessionKey;
    if (!sessionKey) {
      scope.assertCurrent?.();
      return undefined;
    }
    const config = options.context.getRuntimeConfig();
    const successful = readSessionSuccessfulAuthBinding({
      sessionKey,
      sessionId: scope.sessionEntry?.sessionId,
      lifecycleRevision: scope.sessionEntry?.lifecycleRevision,
      provider: scope.sessionEntry?.modelProvider,
      model: scope.sessionEntry?.model,
    });
    if (!successful) {
      scope.assertCurrent?.();
      return unavailableSessionCredentialUsage("binding-missing", sessionKey);
    }
    const profileId = successful.authProfileId;
    const personal = isUserModelAuthProfileId(profileId);
    const personalAuthority = personal
      ? await preparePersonalModelAccountRead(options, profileId)
      : undefined;
    personalAuthority?.assertCurrent();

    const runtime = getProviderUsageRuntimeSnapshot({
      config,
      agentId: scope.agentId,
    });
    const credential = personal
      ? (await readUserModelAuthProfileAsync(profileId, captureOpenClawStateWorkerContext()))
          ?.credential
      : runtime.store.profiles[profileId];
    if (!credential) {
      scope.assertCurrent?.();
      return unavailableSessionCredentialUsage("credential-missing", sessionKey, successful);
    }
    const providerId = successful.provider;
    if (credential.provider.trim() !== providerId) {
      scope.assertCurrent?.();
      return unavailableSessionCredentialUsage("provider-mismatch", sessionKey, successful);
    }
    const authStore: AuthProfileStore = {
      version: runtime.store.version,
      profiles: { [profileId]: credential },
      order: { [providerId]: [profileId] },
      lastGood: { [providerId]: profileId },
    };
    let resolvedProfile: Awaited<ReturnType<typeof resolveApiKeyForProfile>>;
    try {
      resolvedProfile = await resolveApiKeyForProfile({
        cfg: config,
        store: authStore,
        profileId,
        agentDir: runtime.agentDir,
        allowProfileFallback: false,
      });
    } catch {
      personalAuthority?.assertCurrent();
      scope.assertCurrent?.();
      return unavailableSessionCredentialUsage("auth-unavailable", sessionKey, successful);
    }
    if (!resolvedProfile || resolvedProfile.profileId !== profileId) {
      personalAuthority?.assertCurrent();
      scope.assertCurrent?.();
      return unavailableSessionCredentialUsage("auth-unavailable", sessionKey, successful);
    }
    const resolvedAuth = {
      apiKey: resolvedProfile.apiKey,
      profileId,
      source: `profile:${profileId}`,
      mode: credential.type === "api_key" ? "api-key" : credential.type,
    } as const;
    const boundCredentialFingerprint = fingerprintResolvedAuthProfileCredential({
      profileId,
      credential,
      resolvedAuth,
    });
    if (!boundCredentialFingerprint || boundCredentialFingerprint !== successful.authFingerprint) {
      scope.assertCurrent?.();
      return unavailableSessionCredentialUsage("credential-changed", sessionKey, successful);
    }
    const effectiveCredential =
      credential.type === "oauth" && resolvedProfile.credential?.type === "oauth"
        ? resolvedProfile.credential
        : credential;
    const sampledCredentialFingerprint = fingerprintResolvedAuthProfileCredential({
      profileId,
      credential: effectiveCredential,
      resolvedAuth,
    });
    if (!sampledCredentialFingerprint || resolvedProfile.provider.trim() !== providerId) {
      personalAuthority?.assertCurrent();
      scope.assertCurrent?.();
      return unavailableSessionCredentialUsage("auth-unavailable", sessionKey, successful);
    }
    const assertCurrent = () => {
      personalAuthority?.assertCurrent();
      scope.assertCurrent?.();
    };
    assertCurrent();
    const exactAuth = {
      provider: providerId,
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
    const accountBindingId = fingerprintAuthAccountIdentity(effectiveCredential.email);
    const summary = await loadCredentialUsageStatusStaleWhileRevalidate({
      agentId: scope.agentId,
      agentDir: runtime.agentDir,
      authStore,
      exactAuth,
      config,
      credentialFingerprint: sampledCredentialFingerprint,
      accountBindingId,
      sessionKey: successful.sessionKey,
      sessionId: successful.sessionId,
      lifecycleRevision: successful.lifecycleRevision,
      providerId,
      authScope: personal ? "personal" : "shared",
      coldRead,
      assertCurrent,
    });
    assertCurrent();
    if (sampledCredentialFingerprint !== successful.authFingerprint) {
      const replaced = replaceSessionSuccessfulAuthFingerprint({
        sessionKey: successful.sessionKey,
        sessionId: successful.sessionId,
        lifecycleRevision: successful.lifecycleRevision,
        expectedFingerprint: successful.authFingerprint,
        nextFingerprint: sampledCredentialFingerprint,
      });
      if (!replaced) {
        return unavailableSessionCredentialUsage("credential-changed", sessionKey, successful);
      }
    } else {
      const current = readSessionSuccessfulAuthBinding({
        sessionKey: successful.sessionKey,
        sessionId: successful.sessionId,
        lifecycleRevision: successful.lifecycleRevision,
        provider: successful.provider,
        model: successful.model,
      });
      if (current?.authFingerprint !== successful.authFingerprint) {
        return unavailableSessionCredentialUsage("credential-changed", sessionKey, successful);
      }
    }
    return summary;
  } finally {
    scope.release?.();
  }
}

export const usageHandlers: GatewayRequestHandlers = {
  "usage.status": async (options) => {
    const { respond, context, client, params } = options;
    if (!assertValidParams(params, validateUsageStatusParams, "usage.status", respond)) {
      return;
    }
    // Only clients with bounded retry machinery may receive an incomplete cold result.
    // In-process dispatch reuses the originating request's client, capabilities
    // included, so a plugin proxying this method inside a capable UI request
    // would inherit the marker without any way to converge it. Such a caller
    // must pass a capless client, the way board bindings force `client: null`.
    const coldRead = hasGatewayClientCap(
      client?.connect?.caps,
      GATEWAY_CLIENT_CAPS.USAGE_REFRESHING,
    )
      ? ("refresh-marker" as const)
      : undefined;
    let summary;
    try {
      summary = params.sessionKey
        ? await loadSessionCredentialUsage(options, coldRead)
        : await loadUsageStatusStaleWhileRevalidate({
            config: context.getRuntimeConfig(),
            coldRead,
          });
    } catch (error) {
      if (!(error instanceof ModelAccountConnectAuthorityError)) throw error;
      respond(false, undefined, errorShape(ErrorCodes.FORBIDDEN, error.message));
      return;
    }
    if (!summary) {
      return;
    }
    respond(true, summary, undefined);
  },
  "usage.cost": async ({ respond, params, context, client }) => {
    const dateRange = resolveUsageDateRangeOrRespond(params ?? {}, respond);
    if (!dateRange) {
      return;
    }
    const { interpretation: dateInterpretation, range } = dateRange;
    const config = context.getRuntimeConfig();
    if (!isGatewayAdmin(client ?? null) && operatorSessionCap(client ?? null, config) === "none") {
      respond(
        false,
        undefined,
        errorShape(
          ErrorCodes.FORBIDDEN,
          "Aggregate usage includes sessions hidden by your operator role; ask an administrator to review Gateway-wide usage.",
        ),
      );
      return;
    }
    const { startMs, endMs } = range;
    const agentId = normalizeOptionalString(params?.agentId);
    if (params?.agentScope === "all" && agentId) {
      respond(
        false,
        undefined,
        errorShape(ErrorCodes.INVALID_REQUEST, "agentScope=all cannot be combined with agentId"),
      );
      return;
    }
    const agentScope = params?.agentScope === "all" ? "all" : undefined;
    let effectiveAgentId = agentId;
    if (!agentScope && !effectiveAgentId) {
      const requestedAgent = resolveRequestedSessionAgentId(config, "main");
      if (!requestedAgent.ok) {
        respond(false, undefined, requestedAgent.error);
        return;
      }
      effectiveAgentId = requestedAgent.agentId;
    }
    const summary = await loadCostUsageSummaryCached({
      startMs,
      endMs,
      dayBucket: resolveDayBucket(dateInterpretation),
      config,
      agentId: effectiveAgentId,
      agentScope,
    });
    respond(true, summary, undefined);
  },
  "sessions.usage": async ({ respond, params, context, client }) => {
    if (!assertValidParams(params, validateSessionsUsageParams, "sessions.usage", respond)) {
      return;
    }

    const p = params;
    const dateRange = resolveUsageDateRangeOrRespond(p, respond);
    if (!dateRange) {
      return;
    }
    const { interpretation: dateInterpretation, range } = dateRange;
    const config = context.getRuntimeConfig();
    const sessionCap = operatorSessionCap(client ?? null, config);
    const visibilityFilter =
      sessionCap === "none"
        ? createSessionListEntryFilter({ client: client ?? null, cfg: config })
        : undefined;
    const profileId = gatewayClientSessionCreator(client ?? null)?.id;
    const visibilityIdentity = sessionCap && profileId ? `${profileId}:${sessionCap}` : undefined;
    const { startMs, endMs, includeUntimestamped } = range;
    const dayBucket = resolveDayBucket(dateInterpretation);
    const limit = typeof p.limit === "number" && Number.isFinite(p.limit) ? p.limit : 50;
    const includeContextWeight = p.includeContextWeight ?? false;
    const creatorKey = normalizeOptionalString(p.creatorKey);
    const specificKey = normalizeOptionalString(p.key) ?? null;
    const requestedAgentId = normalizeOptionalString(p.agentId);
    const requestedAllAgents = p.agentScope === "all";
    if (requestedAllAgents && (requestedAgentId || specificKey)) {
      respond(
        false,
        undefined,
        errorShape(
          ErrorCodes.INVALID_REQUEST,
          "agentScope=all cannot be combined with key or agentId",
        ),
      );
      return;
    }
    const specificSessionOwner = specificKey
      ? resolveRequestedSessionAgentId(config, specificKey, requestedAgentId)
      : undefined;
    if (specificSessionOwner && !specificSessionOwner.ok) {
      respond(false, undefined, specificSessionOwner.error);
      return;
    }
    const implicitAgent =
      !requestedAllAgents && !specificSessionOwner?.agentId && !requestedAgentId
        ? resolveRequestedSessionAgentId(config, "main")
        : undefined;
    if (implicitAgent && !implicitAgent.ok) {
      respond(false, undefined, implicitAgent.error);
      return;
    }
    const effectiveAgentId = requestedAllAgents
      ? undefined
      : normalizeAgentId(
          specificSessionOwner?.agentId ?? requestedAgentId ?? implicitAgent?.agentId,
        );
    const groupingMode: UsageGroupingMode =
      p.groupBy === "family" || p.includeHistorical === true ? "family" : "instance";

    let result: SessionsUsageResult;
    try {
      result = await loadSessionsUsageResultCached({
        configRef: config,
        ...(effectiveAgentId ? { agentId: effectiveAgentId } : { agentScope: "all" }),
        startMs,
        endMs,
        includeUntimestamped,
        dayBucket,
        limit,
        groupingMode,
        specificKey,
        includeContextWeight,
        creatorKey,
        ...(visibilityIdentity ? { visibilityIdentity } : {}),
        load: async () => {
          const now = Date.now();
          const visibleEntries = await selectUsageSessions({
            config,
            agentId: effectiveAgentId,
            specificKey,
            groupingMode,
            startMs,
            endMs,
            visibilityFilter,
          });
          const profiles: Parameters<typeof projectSessionActor>[1] = new Map();
          const creatorOptions = new Map<string, SessionUsageCreator>();
          const matchedEntries = visibleEntries.flatMap((entry) => {
            const creator = projectUsageCreator(entry, profiles, config);
            creatorOptions.set(creator.key, creator);
            return !creatorKey || creator.key === creatorKey ? [{ entry, creator }] : [];
          });
          const mergedEntries = matchedEntries.map(({ entry }) => entry);

          // Load usage for each session
          const sessions: SessionUsageEntry[] = [];
          const accumulator = createUsageAggregateAccumulator();
          const { summaries: usageByEntryIndex, cacheStatus } = await loadUsageSessionSummaries({
            entries: mergedEntries,
            config,
            startMs,
            endMs,
            includeUntimestamped,
            dayBucket,
          });
          loadUsageSessionContext(mergedEntries.slice(0, limit), visibilityFilter);

          for (const [entryIndex, { entry: merged, creator }] of matchedEntries.entries()) {
            const agentId = merged.agentId;
            const usage = usageByEntryIndex[entryIndex] ?? null;
            const channel = sessionDeliveryChannel(merged.storeEntry);
            const origin = sessionDeliveryOrigin(merged.storeEntry);
            const chatType = merged.storeEntry?.chatType ?? origin?.chatType;
            // Aggregate every matched row before limiting the visible list.
            accumulator.add({
              usage,
              agentId,
              channel,
              creatorKey: creator.key,
              createdActor: creator.actor,
            });

            if (entryIndex < limit) {
              sessions.push({
                key: merged.key,
                label: merged.label,
                sessionId: merged.sessionId,
                scope: merged.scope ?? "instance",
                sessionFamilyKey: merged.sessionFamilyKey,
                currentSessionId: merged.currentSessionId,
                includedSessionIds: merged.includedSessionIds,
                historicalInstanceCount: merged.includedSessionIds?.length,
                updatedAt: merged.updatedAt,
                agentId,
                creatorKey: creator.key,
                createdActor: creator.actor,
                channel,
                chatType,
                origin,
                modelOverride: merged.storeEntry?.modelOverride,
                providerOverride: merged.storeEntry?.providerOverride,
                modelProvider: merged.storeEntry?.modelProvider,
                model: merged.storeEntry?.model,
                usage,
                ...(!usage ? { computing: true } : {}),
                hasContextWeight: Boolean(merged.contextWeight),
                contextWeight: includeContextWeight ? (merged.contextWeight ?? null) : undefined,
              });
            }
          }

          return {
            updatedAt: now,
            startDate: formatDateLabel(startMs, dateInterpretation),
            endDate: formatDateLabel(endMs, dateInterpretation),
            sessions,
            totals: accumulator.totals,
            aggregates: accumulator.finish(),
            creatorOptions: Array.from(creatorOptions.values()),
            cacheStatus,
          };
        },
      });
    } catch (err) {
      if (err instanceof UsageSessionInvalidRequestError) {
        respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, err.message));
        return;
      }
      throw err;
    }
    respond(true, result, undefined);
  },
  "sessions.usage.timeseries": async ({ respond, params, context }) => {
    const resolved = resolveSessionUsageFileOrRespond(
      params,
      "timeseries",
      respond,
      context.getRuntimeConfig(),
    );
    if (!resolved) {
      return;
    }
    const { config, key, entry, agentId, sessionId, sessionFile } = resolved;

    const timeseries = await loadSessionUsageTimeSeries({
      sessionId,
      sessionEntry: entry,
      sessionFile,
      config,
      agentId,
      maxPoints: 200,
    });

    if (!timeseries) {
      respond(
        false,
        undefined,
        errorShape(ErrorCodes.INVALID_REQUEST, `No transcript found for session: ${key}`),
      );
      return;
    }

    respond(true, timeseries, undefined);
  },
  "sessions.usage.logs": async ({ respond, params, context }) => {
    const limit =
      typeof params?.limit === "number" && Number.isFinite(params.limit)
        ? Math.min(params.limit, 1000)
        : 200;

    const resolved = resolveSessionUsageFileOrRespond(
      params,
      "logs",
      respond,
      context.getRuntimeConfig(),
    );
    if (!resolved) {
      return;
    }
    const { config, entry, agentId, sessionId, sessionFile } = resolved;

    const logs = await loadSessionLogs({
      sessionId,
      sessionEntry: entry,
      sessionFile,
      config,
      agentId,
      limit,
    });

    respond(true, { logs: logs ?? [] }, undefined);
  },
};
