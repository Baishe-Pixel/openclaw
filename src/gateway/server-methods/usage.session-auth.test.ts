import { expectDefined } from "@openclaw/normalization-core";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AuthProfileCredential, AuthProfileStore } from "../../agents/auth-profiles.js";
import { fingerprintResolvedAuthProfileCredential } from "../../agents/execution-auth-binding.js";
import {
  clearSessionSuccessfulAuthBindingsForTest,
  recordSessionSuccessfulAuthBinding,
} from "../../agents/session-successful-auth-binding.js";
import type { OpenClawConfig } from "../../config/types.openclaw.js";

const mocks = vi.hoisted(() => ({
  authorize: true,
  loadProviderUsageSummary: vi.fn(),
  resolveChatMetadataReadParams: vi.fn(),
  getProviderUsageRuntimeSnapshot: vi.fn(),
  resolveApiKeyForProfile: vi.fn(),
}));

vi.mock("../../agents/auth-profiles.js", async (importActual) => {
  const actual = await importActual<typeof import("../../agents/auth-profiles.js")>();
  return {
    ...actual,
    resolveApiKeyForProfile: mocks.resolveApiKeyForProfile,
  };
});

vi.mock("./chat-metadata-handler.js", () => ({
  resolveChatMetadataReadParams: mocks.resolveChatMetadataReadParams,
}));
vi.mock("./provider-usage-runtime.js", () => ({
  getProviderUsageRuntimeSnapshot: mocks.getProviderUsageRuntimeSnapshot,
  clearProviderUsageRuntimeSnapshot: vi.fn(),
}));
vi.mock("../../infra/provider-usage.load.js", () => ({
  loadProviderUsageSummary: mocks.loadProviderUsageSummary,
}));

import { clearModelAuthStatusUsageCache } from "./models-auth-status-usage-cache.js";
import { usageHandlers } from "./usage.js";

const config = { agents: { list: [{ id: "main", default: true }] } } as OpenClawConfig;
const sharedCredential: AuthProfileCredential = {
  type: "oauth",
  provider: "openai",
  access: "shared-access",
  refresh: "shared-refresh",
  expires: Date.now() + 3_600_000,
};
const sharedStore: AuthProfileStore = {
  version: 1,
  profiles: { "openai:shared-winner": sharedCredential },
};
const sessionEntry = {
  sessionId: "session-one",
  lifecycleRevision: 7,
  authProfileOverride: "personal:owner:pinned-plus",
  authProfileOverrideSource: "user" as const,
  modelProvider: "openai",
  model: "gpt-test",
};

async function runScoped() {
  const respond = vi.fn();
  await expectDefined(
    usageHandlers["usage.status"],
    "usage.status handler",
  )({
    respond,
    params: { sessionKey: "agent:main:main" },
    context: { getRuntimeConfig: () => config },
    client: { connect: { caps: [] } },
  } as never);
  return { respond, call: respond.mock.calls[0] };
}

beforeEach(() => {
  clearSessionSuccessfulAuthBindingsForTest();
  clearModelAuthStatusUsageCache();
  vi.clearAllMocks();
  mocks.resolveChatMetadataReadParams.mockImplementation((options) => {
    if (!mocks.authorize) {
      options.respond(false, undefined, { code: "NOT_FOUND", message: "session not found" });
      return undefined;
    }
    return {
      agentId: "main",
      sessionKey: "agent:main:main",
      sessionEntry,
      assertCurrent: vi.fn(),
      release: vi.fn(),
    };
  });
  mocks.resolveApiKeyForProfile.mockResolvedValue({
    apiKey: sharedCredential.access,
    provider: "openai",
    profileId: "openai:shared-winner",
  });
  mocks.getProviderUsageRuntimeSnapshot.mockReturnValue({
    agentId: "main",
    agentDir: "agent-dir",
    configRef: config,
    credentialKey: "unused",
    descriptors: [],
    directApiKeys: new Map(),
    providerIds: ["openai"],
    store: sharedStore,
  });
  mocks.loadProviderUsageSummary.mockResolvedValue({
    updatedAt: 1,
    providers: [
      {
        provider: "openai",
        displayName: "OpenAI",
        windows: [{ label: "5h", usedPercent: 12 }],
        accountEmail: "private@example.test",
      },
    ],
  });
  mocks.authorize = true;
});

describe("usage.status session credential scope", () => {
  it("uses the successful shared fallback instead of the personal requested pin", async () => {
    const authFingerprint = expectDefined(
      fingerprintResolvedAuthProfileCredential({
        profileId: "openai:shared-winner",
        credential: sharedCredential,
        resolvedAuth: undefined,
      }),
      "shared credential fingerprint",
    );
    recordSessionSuccessfulAuthBinding({
      sessionKey: "agent:main:main",
      sessionId: sessionEntry.sessionId,
      lifecycleRevision: sessionEntry.lifecycleRevision,
      provider: sessionEntry.modelProvider,
      model: sessionEntry.model,
      binding: {
        authProfileId: "openai:shared-winner",
        authFingerprint,
        modelId: sessionEntry.model,
      },
    });

    const { call } = await runScoped();
    expect(call?.[0]).toBe(true);
    expect(mocks.loadProviderUsageSummary).toHaveBeenCalledWith(
      expect.objectContaining({
        authStore: expect.objectContaining({
          profiles: { "openai:shared-winner": sharedCredential },
        }),
        providers: ["openai"],
      }),
    );
    expect(call?.[1]).toMatchObject({
      authScope: "shared",
      credentialFingerprint: authFingerprint,
      providers: [{ credentialFingerprint: authFingerprint }],
    });
    expect(call?.[1].providers[0].accountEmail).toBeUndefined();
  });

  it("returns an empty unverified result without a successful binding", async () => {
    const { call } = await runScoped();
    expect(call?.[0]).toBe(true);
    expect(call?.[1]).toMatchObject({ providers: [] });
    expect(call?.[1].credentialFingerprint).toBeUndefined();
    expect(mocks.loadProviderUsageSummary).not.toHaveBeenCalled();
  });

  it("does not bypass session visibility authorization", async () => {
    mocks.authorize = false;
    const { call } = await runScoped();
    expect(call?.[0]).toBe(false);
    expect(call?.[2]).toMatchObject({ code: "NOT_FOUND" });
    expect(mocks.loadProviderUsageSummary).not.toHaveBeenCalled();
  });
});
