/** One quota window reported by a provider usage endpoint. */
export type UsageWindow = {
  label: string;
  groupLabel?: string;
  usedPercent: number;
  resetAt?: number;
};

/** Provider-reported monetary or credit facts. Units may be ISO currencies or provider credits. */
export type ProviderUsageBilling =
  | {
      type: "balance";
      label?: string;
      amount: number;
      unit: string;
    }
  | {
      type: "spend";
      label?: string;
      amount: number;
      unit: string;
      period?: string;
      resetAt?: number;
    }
  | {
      type: "budget";
      label?: string;
      used: number;
      limit: number;
      unit: string;
      period?: string;
      resetAt?: number;
    };

/** Provider-reported daily cost and token totals. Costs are actual provider billing, not estimates. */
export type ProviderUsageCostDaily = {
  date: string;
  amount: number;
  requests?: number;
  inputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  outputTokens: number;
  totalTokens: number;
};

/** Aggregate model activity for the provider history window. */
export type ProviderUsageModelBreakdown = Omit<ProviderUsageCostDaily, "date" | "amount"> & {
  name: string;
};

/** Aggregate provider billing category for the history window. */
export type ProviderUsageCostBreakdown = {
  name: string;
  amount: number;
};

/** Provider-reported cost history and attribution for one bounded UTC window. */
export type ProviderUsageCostHistory = {
  unit: string;
  periodDays: number;
  scope?: string;
  daily: ProviderUsageCostDaily[];
  models: ProviderUsageModelBreakdown[];
  categories: ProviderUsageCostBreakdown[];
};

export type ProviderUsageSnapshot = {
  provider: UsageProviderId;
  displayName: string;
  windows: UsageWindow[];
  billing?: ProviderUsageBilling[];
  costHistory?: ProviderUsageCostHistory;
  summary?: string;
  plan?: string;
  /** Account identity (email) the usage was fetched under, when known. */
  accountEmail?: string;
  /** Process-local, non-reversible identity of the credential used for this snapshot. */
  credentialFingerprint?: string;
  /** Process-local, non-reversible identity of the provider-reported account. */
  accountBindingId?: string;
  error?: string;
};

export type SessionUsageBindingConsistency = "match" | "mismatch" | "unavailable";

export type SessionUsageScope = {
  status: "verified" | "refreshing" | "unavailable";
  /** Canonical session key accepted for this request. */
  requestedSessionKey: string;
  /** Canonical session key whose successful auth binding was sampled. */
  effectiveSessionKey: string;
  authScope?: "personal" | "shared";
  reason?:
    | "binding-missing"
    | "credential-missing"
    | "provider-mismatch"
    | "credential-changed"
    | "auth-unavailable"
    | "account-binding-unavailable"
    | "account-binding-mismatch"
    | "personal-account-authority-required";
  credential: {
    sessionBindingId?: string;
    sampledBindingId?: string;
    consistency: SessionUsageBindingConsistency;
  };
  account: {
    sessionBindingId?: string;
    sampledBindingId?: string;
    consistency: SessionUsageBindingConsistency;
  };
};

export type SessionUsageCacheMetadata = {
  status: "fresh" | "stale" | "refreshing" | "unavailable";
  sampledAt?: number;
  ageMs?: number;
  ttlMs?: number;
  refreshing?: boolean;
};

export type UsageSummary = {
  updatedAt: number;
  providers: ProviderUsageSnapshot[];
  /** A background refresh owns the real values; an empty list is incomplete. */
  refreshing?: boolean;
  /** Credential scope for a session-bound query; absent on the legacy global query. */
  authScope?: "personal" | "shared";
  credentialFingerprint?: string;
  /** Strictly projected metadata for a session-scoped query. Absent on legacy reads. */
  sessionScope?: SessionUsageScope;
  /** Time the provider values were sampled. Absent while unavailable or cold-refreshing. */
  sampledAt?: number;
  /** Cache freshness for a session-scoped query. Absent on legacy reads. */
  cache?: SessionUsageCacheMetadata;
};

/** Normalized provider id. Usage providers are discovered from plugin hooks at runtime. */
export type UsageProviderId = string;
