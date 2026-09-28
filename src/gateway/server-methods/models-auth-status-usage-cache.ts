// Stale-while-revalidate cache for models.authStatus provider usage enrichment.
import type { AuthProfileStore } from "../../agents/auth-profiles.js";
import { fingerprintAuthAccountIdentity } from "../../agents/execution-auth-binding.js";
import type { OpenClawConfig } from "../../config/types.openclaw.js";
import type { ProviderAuth } from "../../infra/provider-usage.auth.js";
import { loadProviderUsageSummary } from "../../infra/provider-usage.load.js";
import { PROVIDER_USAGE_TIMEOUT_MS } from "../../infra/provider-usage.shared.js";
import type {
  ProviderUsageSnapshot,
  UsageProviderId,
  UsageSummary,
} from "../../infra/provider-usage.types.js";
import { createSubsystemLogger } from "../../logging/subsystem.js";
import { trackAsyncWork } from "../../shared/async-work-scope.js";
import { formatForLog } from "../ws-log.js";
import {
  clearProviderUsageRuntimeSnapshot,
  getProviderUsageRuntimeSnapshot,
} from "./provider-usage-runtime.js";

const log = createSubsystemLogger("provider-usage-cache");
const USAGE_CACHE_TTL_MS = 60_000;

export type ProviderUsageStatus = Pick<
  ProviderUsageSnapshot,
  "windows" | "summary" | "plan" | "billing" | "accountEmail"
>;

type ProviderUsageCacheIdentity = {
  agentDir: string;
  configRef: OpenClawConfig;
  credentialKey: string;
  providerKey: string;
  cacheScopeKey?: string;
};

type ProviderUsageCacheEntry = ProviderUsageCacheIdentity & {
  agentId: string;
  refreshedAt: number;
  summary: UsageSummary;
  usageByProvider: Map<string, ProviderUsageStatus>;
};

type ProviderUsageRefresh = ProviderUsageCacheIdentity & {
  promise: Promise<UsageSummary>;
};

const usageCacheByCredential = new Map<string, ProviderUsageCacheEntry>();
const usageRefreshByCredential = new Map<string, ProviderUsageRefresh>();
const MAX_CREDENTIAL_CACHE_ENTRIES_PER_AGENT = 8;
let cacheGeneration = 0;

export function clearModelAuthStatusUsageCache(): void {
  cacheGeneration += 1;
  usageCacheByCredential.clear();
  usageRefreshByCredential.clear();
  clearProviderUsageRuntimeSnapshot();
}

function scopeProviderUsageCredentialKey(
  credentialKey: string,
  providerIds: readonly UsageProviderId[],
): string {
  // models.authStatus fingerprints every direct provider. Scope that evidence to
  // this fetch set so usage.status can share the same credential-bound snapshot.
  // SAFETY: fingerprintProviderUsageCredentials always serializes this shape.
  const parsed = JSON.parse(credentialKey) as {
    direct: Array<[string, string | null]>;
    [key: string]: unknown;
  };
  const providers = new Set(providerIds);
  return JSON.stringify({
    ...parsed,
    direct: parsed.direct.filter(
      ([provider, fingerprint]) => providers.has(provider) && fingerprint !== null,
    ),
  });
}

function mapProviderUsage(usage: Awaited<ReturnType<typeof loadProviderUsageSummary>>) {
  const usageByProvider = new Map<string, ProviderUsageStatus>();
  for (const snap of usage.providers) {
    usageByProvider.set(snap.provider, {
      windows: snap.windows,
      ...(snap.summary ? { summary: snap.summary } : {}),
      ...(snap.plan ? { plan: snap.plan } : {}),
      ...(snap.billing?.length ? { billing: snap.billing } : {}),
      ...(snap.accountEmail ? { accountEmail: snap.accountEmail } : {}),
    });
  }
  return usageByProvider;
}

function publishProviderUsageCache(cacheKey: string, entry: ProviderUsageCacheEntry): void {
  usageCacheByCredential.delete(cacheKey);
  usageCacheByCredential.set(cacheKey, entry);
  const siblings = [...usageCacheByCredential].filter(
    ([, candidate]) => candidate.agentId === entry.agentId,
  );
  for (const [oldestKey] of siblings.slice(0, -MAX_CREDENTIAL_CACHE_ENTRIES_PER_AGENT)) {
    usageCacheByCredential.delete(oldestKey);
  }
}

function retainLastGoodOnTimeout(
  summary: UsageSummary,
  lastGood: UsageSummary | undefined,
): UsageSummary {
  if (!lastGood) {
    return summary;
  }
  const lastGoodByProvider = new Map(
    lastGood.providers
      .filter((provider) => provider.error === undefined)
      .map((provider) => [provider.provider, provider]),
  );
  const retainedLastGood = summary.providers.some(
    (provider) => provider.error === "Timeout" && lastGoodByProvider.has(provider.provider),
  );
  return {
    ...summary,
    updatedAt: retainedLastGood ? lastGood.updatedAt : summary.updatedAt,
    providers: summary.providers.map((provider) =>
      provider.error === "Timeout"
        ? (lastGoodByProvider.get(provider.provider) ?? provider)
        : provider,
    ),
  };
}

function scheduleProviderUsageRefresh(
  params: ProviderUsageCacheIdentity & {
    agentId: string;
    authStore?: AuthProfileStore;
    exactAuth?: ProviderAuth;
    providerIds: UsageProviderId[];
    lastGood?: UsageSummary;
    resultCredentialFingerprint?: string;
    resultAccountBindingId?: string;
    resultRequestedSessionKey?: string;
    resultEffectiveSessionKey?: string;
    authScope?: "personal" | "shared";
    assertCurrent?: () => void;
  },
): Promise<UsageSummary> {
  const cacheKey = JSON.stringify([
    params.agentId,
    params.cacheScopeKey ?? null,
    params.credentialKey,
    params.providerKey,
  ]);
  const active = usageRefreshByCredential.get(cacheKey);
  if (
    active?.agentDir === params.agentDir &&
    active.configRef === params.configRef &&
    active.credentialKey === params.credentialKey &&
    active.providerKey === params.providerKey &&
    active.cacheScopeKey === params.cacheScopeKey
  ) {
    return active.promise;
  }
  const publishGeneration = cacheGeneration;
  // SWR replies and invalidation must retain publication and finalization ownership.
  const promise = trackAsyncWork(() =>
    loadProviderUsageSummary({
      providers: params.providerIds,
      agentDir: params.agentDir,
      authStore: params.authStore,
      ...(params.exactAuth ? { auth: [params.exactAuth] } : {}),
      config: params.configRef,
      timeoutMs: PROVIDER_USAGE_TIMEOUT_MS,
      assertCurrent: params.assertCurrent,
    })
      .then((freshUsage) => {
        const scopedProviders = params.resultCredentialFingerprint
          ? freshUsage.providers.map(({ accountEmail, ...provider }) => {
              const accountBindingId = fingerprintAuthAccountIdentity(accountEmail);
              return {
                ...provider,
                credentialFingerprint: params.resultCredentialFingerprint,
                ...(accountBindingId ? { accountBindingId } : {}),
              };
            })
          : undefined;
        const sampledAccountBindingIds = [
          ...new Set(
            (scopedProviders ?? [])
              .map((provider) => provider.accountBindingId)
              .filter((value): value is string => Boolean(value)),
          ),
        ];
        const sampledAccountBindingId =
          sampledAccountBindingIds.length === 1 ? sampledAccountBindingIds[0] : undefined;
        const accountConsistency =
          params.resultAccountBindingId && sampledAccountBindingId
            ? params.resultAccountBindingId === sampledAccountBindingId
              ? ("match" as const)
              : ("mismatch" as const)
            : ("unavailable" as const);
        // A known provider-account conflict must never publish quota values. Providers
        // without account identity may still expose exact credential-scoped results and
        // let clients apply their stricter provider-specific policy.
        const accountMismatch = accountConsistency === "mismatch";
        const scopeStatus = accountMismatch ? ("unavailable" as const) : ("verified" as const);
        const scopedUsage = params.resultCredentialFingerprint
          ? {
              ...freshUsage,
              authScope: params.authScope,
              credentialFingerprint: params.resultCredentialFingerprint,
              providers: accountMismatch ? [] : (scopedProviders ?? []),
              sessionScope: {
                status: scopeStatus,
                ...(accountMismatch ? { reason: "account-binding-mismatch" as const } : {}),
                requestedSessionKey: params.resultRequestedSessionKey ?? "",
                effectiveSessionKey: params.resultEffectiveSessionKey ?? "",
                authScope: params.authScope,
                credential: {
                  sessionBindingId: params.resultCredentialFingerprint,
                  sampledBindingId: params.resultCredentialFingerprint,
                  consistency: "match" as const,
                },
                account: {
                  ...(params.resultAccountBindingId
                    ? { sessionBindingId: params.resultAccountBindingId }
                    : {}),
                  ...(sampledAccountBindingId ? { sampledBindingId: sampledAccountBindingId } : {}),
                  consistency: accountConsistency,
                },
              },
            }
          : freshUsage;
        const usage = retainLastGoodOnTimeout(scopedUsage, params.lastGood);
        if (
          publishGeneration === cacheGeneration &&
          usageRefreshByCredential.get(cacheKey) === refresh
        ) {
          publishProviderUsageCache(cacheKey, {
            agentId: params.agentId,
            agentDir: params.agentDir,
            configRef: params.configRef,
            credentialKey: params.credentialKey,
            providerKey: params.providerKey,
            cacheScopeKey: params.cacheScopeKey,
            refreshedAt: Date.now(),
            summary: usage,
            usageByProvider: mapProviderUsage(usage),
          });
        }
        return usage;
      })
      .catch((err: unknown) => {
        // Usage is auxiliary and stale data remains valid. A failed refresh
        // publishes nothing, so a capable client keeps seeing the incomplete
        // marker and reports it once its retry budget is spent.
        log.debug(
          `usage refresh failed: providers=${params.providerIds.join(",")} error=${formatForLog(err)}`,
        );
        throw err;
      })
      .finally(() => {
        if (usageRefreshByCredential.get(cacheKey) === refresh) {
          usageRefreshByCredential.delete(cacheKey);
        }
      }),
  );
  const refresh: ProviderUsageRefresh = {
    agentDir: params.agentDir,
    configRef: params.configRef,
    credentialKey: params.credentialKey,
    providerKey: params.providerKey,
    cacheScopeKey: params.cacheScopeKey,
    promise,
  };
  usageRefreshByCredential.set(cacheKey, refresh);
  return promise;
}

type ProviderUsageCacheParams = {
  agentId: string;
  agentDir: string;
  authStore?: AuthProfileStore;
  exactAuth?: ProviderAuth;
  configRef: OpenClawConfig;
  credentialKey: string;
  cacheScopeKey?: string;
  coldRead?: "refresh-marker";
  forceRefresh?: boolean;
  providerIds: UsageProviderId[];
  now: number;
  resultCredentialFingerprint?: string;
  resultAccountBindingId?: string;
  resultRequestedSessionKey?: string;
  resultEffectiveSessionKey?: string;
  authScope?: "personal" | "shared";
  assertCurrent?: () => void;
};

function resolveProviderUsageCacheRead(params: ProviderUsageCacheParams) {
  const providerIds = params.providerIds.toSorted();
  const providerKey = providerIds.join("\0");
  const credentialKey = scopeProviderUsageCredentialKey(params.credentialKey, providerIds);
  const cacheKey = JSON.stringify([
    params.agentId,
    params.cacheScopeKey ?? null,
    credentialKey,
    providerKey,
  ]);
  const cached = usageCacheByCredential.get(cacheKey);
  const matching =
    cached?.agentDir === params.agentDir &&
    cached.configRef === params.configRef &&
    cached.credentialKey === credentialKey &&
    cached.providerKey === providerKey &&
    cached.cacheScopeKey === params.cacheScopeKey
      ? cached
      : undefined;
  const needsRefresh =
    params.forceRefresh === true ||
    !matching ||
    params.now - matching.refreshedAt >= USAGE_CACHE_TTL_MS;
  return {
    matching,
    needsRefresh,
    refreshParams: {
      agentId: params.agentId,
      agentDir: params.agentDir,
      authStore: params.authStore,
      exactAuth: params.exactAuth,
      configRef: params.configRef,
      credentialKey,
      cacheScopeKey: params.cacheScopeKey,
      providerIds,
      providerKey,
      lastGood: matching?.summary,
      resultCredentialFingerprint: params.resultCredentialFingerprint,
      resultAccountBindingId: params.resultAccountBindingId,
      resultRequestedSessionKey: params.resultRequestedSessionKey,
      resultEffectiveSessionKey: params.resultEffectiveSessionKey,
      authScope: params.authScope,
      assertCurrent: params.assertCurrent,
    },
  };
}

function projectSessionCacheMetadata(params: {
  summary: UsageSummary;
  now: number;
  status: "fresh" | "stale";
  refreshing?: boolean;
}): UsageSummary {
  const sampledAt = params.summary.updatedAt;
  return {
    ...params.summary,
    sampledAt,
    cache: {
      status: params.status,
      sampledAt,
      ageMs: Math.max(0, params.now - sampledAt),
      ttlMs: USAGE_CACHE_TTL_MS,
      ...(params.refreshing ? { refreshing: true } : {}),
    },
  };
}

export function readProviderUsageStaleWhileRevalidate(
  params: ProviderUsageCacheParams,
): Map<string, ProviderUsageStatus> {
  if (params.providerIds.length === 0) {
    return new Map();
  }
  const { matching, needsRefresh, refreshParams } = resolveProviderUsageCacheRead(params);
  if (needsRefresh) {
    // Never couple the RPC deadline to provider HTTP. A cold call returns auth
    // without usage; stale calls return the last snapshot while one refresh runs.
    void scheduleProviderUsageRefresh(refreshParams).catch(() => {});
  }
  return matching?.usageByProvider ?? new Map();
}

/** Shares the models.authStatus cache contract with the unscoped usage.status RPC. */
export async function loadUsageStatusStaleWhileRevalidate(options: {
  config: OpenClawConfig;
  coldRead?: "refresh-marker";
  now?: number;
}): Promise<UsageSummary> {
  const snapshot = getProviderUsageRuntimeSnapshot({ config: options.config });
  const params: ProviderUsageCacheParams = {
    agentId: snapshot.agentId,
    agentDir: snapshot.agentDir,
    authStore: snapshot.store,
    configRef: snapshot.configRef,
    credentialKey: snapshot.credentialKey,
    providerIds: snapshot.providerIds,
    coldRead: options.coldRead,
    now: options.now ?? Date.now(),
  };
  if (params.providerIds.length === 0) {
    return { updatedAt: params.now, providers: [] };
  }
  const { matching, needsRefresh, refreshParams } = resolveProviderUsageCacheRead(params);
  if (matching && !needsRefresh) {
    return matching.summary;
  }
  const refresh = scheduleProviderUsageRefresh(refreshParams);
  if (matching) {
    void refresh.catch(() => {});
    return matching.summary;
  }
  if (params.coldRead !== "refresh-marker") {
    return await refresh;
  }
  void refresh.catch(() => {});
  return { updatedAt: params.now, providers: [], refreshing: true };
}

/** Load usage for one already-authorized, exact credential without consulting global order. */
export async function loadCredentialUsageStatusStaleWhileRevalidate(options: {
  agentId: string;
  agentDir: string;
  authStore: AuthProfileStore;
  exactAuth: ProviderAuth;
  config: OpenClawConfig;
  credentialFingerprint: string;
  accountBindingId?: string;
  sessionKey: string;
  sessionId: string;
  lifecycleRevision: string;
  providerId: UsageProviderId;
  authScope: "personal" | "shared";
  coldRead?: "refresh-marker";
  now?: number;
  assertCurrent?: () => void;
}): Promise<UsageSummary> {
  const now = options.now ?? Date.now();
  const params: ProviderUsageCacheParams = {
    agentId: options.agentId,
    agentDir: options.agentDir,
    authStore: options.authStore,
    exactAuth: options.exactAuth,
    configRef: options.config,
    cacheScopeKey: JSON.stringify([
      options.sessionKey,
      options.sessionId,
      options.lifecycleRevision,
    ]),
    credentialKey: JSON.stringify({
      profiles: [[options.providerId, options.credentialFingerprint]],
      direct: [],
    }),
    providerIds: [options.providerId],
    coldRead: options.coldRead,
    now,
    resultCredentialFingerprint: options.credentialFingerprint,
    resultAccountBindingId: options.accountBindingId,
    resultRequestedSessionKey: options.sessionKey,
    resultEffectiveSessionKey: options.sessionKey,
    authScope: options.authScope,
    assertCurrent: options.assertCurrent,
  };
  const { matching, needsRefresh, refreshParams } = resolveProviderUsageCacheRead(params);
  if (matching && !needsRefresh) {
    return projectSessionCacheMetadata({
      summary: matching.summary,
      now,
      status: "fresh",
    });
  }
  const refresh = scheduleProviderUsageRefresh(refreshParams);
  if (matching) {
    void refresh.catch(() => {});
    return projectSessionCacheMetadata({
      summary: matching.summary,
      now,
      status: "stale",
      refreshing: true,
    });
  }
  if (options.coldRead !== "refresh-marker") {
    return projectSessionCacheMetadata({
      summary: await refresh,
      now,
      status: "fresh",
    });
  }
  void refresh.catch(() => {});
  return {
    updatedAt: now,
    providers: [],
    refreshing: true,
    authScope: options.authScope,
    credentialFingerprint: options.credentialFingerprint,
    sessionScope: {
      status: "refreshing",
      requestedSessionKey: options.sessionKey,
      effectiveSessionKey: options.sessionKey,
      authScope: options.authScope,
      credential: {
        sessionBindingId: options.credentialFingerprint,
        consistency: "unavailable",
      },
      account: {
        ...(options.accountBindingId ? { sessionBindingId: options.accountBindingId } : {}),
        consistency: "unavailable",
      },
    },
    cache: { status: "refreshing", refreshing: true, ttlMs: USAGE_CACHE_TTL_MS },
  };
}
