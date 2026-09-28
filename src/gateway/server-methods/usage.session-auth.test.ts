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
  readUserModelAuthProfileAsync: vi.fn(),
  preparePersonalModelAccountRead: vi.fn(),
}));

vi.mock("../../agents/auth-profiles.js", async (importActual) => {
  const actual = await importActual<typeof import("../../agents/auth-profiles.js")>();
  return {
    ...actual,
    resolveApiKeyForProfile: mocks.resolveApiKeyForProfile,
  };
});

vi.mock("../../agents/auth-profiles/sqlite-read.js", () => ({
  readUserModelAuthProfileAsync: mocks.readUserModelAuthProfileAsync,
}));
vi.mock("./users-model-account-access.js", () => ({
  preparePersonalModelAccountRead: mocks.preparePersonalModelAccountRead,
}));

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
  email: "private@example.test",
};
const decoyCredential: AuthProfileCredential = {
  type: "oauth",
  provider: "openai",
  access: "decoy-access",
  refresh: "decoy-refresh",
  expires: Date.now() + 3_600_000,
};
const sharedStore: AuthProfileStore = {
  version: 1,
  profiles: {
    "openai:shared-winner": sharedCredential,
    "openai:global-order-first": decoyCredential,
  },
  order: { openai: ["openai:global-order-first", "openai:shared-winner"] },
};
const personalProfileId =
  "personal:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const personalCredential: AuthProfileCredential = {
  type: "oauth",
  provider: "openai",
  access: "personal-access",
  refresh: "personal-refresh",
  expires: Date.now() + 3_600_000,
};

const sessionEntry = {
  sessionId: "session-one",
  lifecycleRevision: 7,
  authProfileOverride: "personal:owner:pinned-plus",
  authProfileOverrideSource: "user" as const,
  modelProvider: "openai",
  model: "gpt-test",
};

async function runScoped(sessionKey = "agent:main:main") {
  const respond = vi.fn();
  await expectDefined(
    usageHandlers["usage.status"],
    "usage.status handler",
  )({
    respond,
    params: { sessionKey },
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
    const requestedSessionKey = options.params.sessionKey as string;
    return {
      agentId: "main",
      sessionKey: requestedSessionKey,
      sessionEntry:
        requestedSessionKey === "agent:main:secondary"
          ? { ...sessionEntry, sessionId: "session-two" }
          : sessionEntry,
      assertCurrent: vi.fn(),
      release: vi.fn(),
    };
  });
  mocks.preparePersonalModelAccountRead.mockResolvedValue({
    owner: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    authProfileId: personalProfileId,
    assertCurrent: vi.fn(),
  });
  mocks.readUserModelAuthProfileAsync.mockResolvedValue({ credential: personalCredential });
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
        auth: [
          expect.objectContaining({
            provider: "openai",
            token: "shared-access",
            authProfileId: "openai:shared-winner",
          }),
        ],
      }),
    );
    expect(call?.[1]).toMatchObject({
      authScope: "shared",
      credentialFingerprint: authFingerprint,
      sampledAt: 1,
      providers: [{ credentialFingerprint: authFingerprint }],
      sessionScope: {
        status: "verified",
        requestedSessionKey: "agent:main:main",
        effectiveSessionKey: "agent:main:main",
        credential: { consistency: "match" },
        account: { consistency: "match" },
      },
      cache: { status: "fresh" },
    });
    expect(call?.[1].providers[0].accountEmail).toBeUndefined();
    expect(call?.[1].sessionScope.account.sessionBindingId).not.toContain("private@example");
    expect(call?.[1].sessionScope.account.sampledBindingId).toBe(
      call?.[1].sessionScope.account.sessionBindingId,
    );
  });

  it("does not let an ambient admin key substitute for the verified session credential", async () => {
    vi.stubEnv("OPENAI_ADMIN_KEY", "ambient-admin-key");
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

    await runScoped();
    expect(mocks.loadProviderUsageSummary).toHaveBeenCalledWith(
      expect.objectContaining({ auth: [expect.objectContaining({ token: "shared-access" })] }),
    );
    expect(mocks.loadProviderUsageSummary.mock.calls[0]?.[0].auth[0].token).not.toBe(
      process.env.OPENAI_ADMIN_KEY,
    );
    vi.unstubAllEnvs();
  });

  it("rejects a shared-session viewer before personal-account provider I/O", async () => {
    const authFingerprint = expectDefined(
      fingerprintResolvedAuthProfileCredential({
        profileId: personalProfileId,
        credential: personalCredential,
        resolvedAuth: undefined,
      }),
      "personal credential fingerprint",
    );
    recordSessionSuccessfulAuthBinding({
      sessionKey: "agent:main:main",
      sessionId: sessionEntry.sessionId,
      lifecycleRevision: sessionEntry.lifecycleRevision,
      provider: sessionEntry.modelProvider,
      model: sessionEntry.model,
      binding: { authProfileId: personalProfileId, authFingerprint, modelId: sessionEntry.model },
    });
    const { ModelAccountConnectAuthorityError } = await import("../model-account-connect.js");
    mocks.preparePersonalModelAccountRead.mockRejectedValue(
      new ModelAccountConnectAuthorityError(),
    );

    const { call } = await runScoped();
    expect(call?.[0]).toBe(false);
    expect(call?.[2]).toMatchObject({ code: "FORBIDDEN" });
    expect(mocks.readUserModelAuthProfileAsync).not.toHaveBeenCalled();
    expect(mocks.loadProviderUsageSummary).not.toHaveBeenCalled();
  });

  it("revalidates personal-account ownership after provider I/O before responding", async () => {
    const authFingerprint = expectDefined(
      fingerprintResolvedAuthProfileCredential({
        profileId: personalProfileId,
        credential: personalCredential,
        resolvedAuth: undefined,
      }),
      "personal credential fingerprint",
    );
    recordSessionSuccessfulAuthBinding({
      sessionKey: "agent:main:main",
      sessionId: sessionEntry.sessionId,
      lifecycleRevision: sessionEntry.lifecycleRevision,
      provider: sessionEntry.modelProvider,
      model: sessionEntry.model,
      binding: { authProfileId: personalProfileId, authFingerprint, modelId: sessionEntry.model },
    });
    const { ModelAccountConnectAuthorityError } = await import("../model-account-connect.js");
    let checks = 0;
    mocks.preparePersonalModelAccountRead.mockResolvedValue({
      owner: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      authProfileId: personalProfileId,
      assertCurrent: vi.fn(() => {
        if (++checks === 3) throw new ModelAccountConnectAuthorityError();
      }),
    });
    mocks.resolveApiKeyForProfile.mockResolvedValue({
      apiKey: "personal-access",
      provider: "openai",
      profileId: personalProfileId,
    });

    const { call } = await runScoped();
    expect(mocks.loadProviderUsageSummary).toHaveBeenCalledOnce();
    expect(call?.[0]).toBe(false);
    expect(call?.[2]).toMatchObject({ code: "FORBIDDEN" });
  });

  it("allows the current personal-account owner and uses that exact credential", async () => {
    const authFingerprint = expectDefined(
      fingerprintResolvedAuthProfileCredential({
        profileId: personalProfileId,
        credential: personalCredential,
        resolvedAuth: undefined,
      }),
      "personal credential fingerprint",
    );
    recordSessionSuccessfulAuthBinding({
      sessionKey: "agent:main:main",
      sessionId: sessionEntry.sessionId,
      lifecycleRevision: sessionEntry.lifecycleRevision,
      provider: sessionEntry.modelProvider,
      model: sessionEntry.model,
      binding: { authProfileId: personalProfileId, authFingerprint, modelId: sessionEntry.model },
    });
    mocks.resolveApiKeyForProfile.mockResolvedValue({
      apiKey: "personal-access",
      provider: "openai",
      profileId: personalProfileId,
    });

    const { call } = await runScoped();
    expect(call?.[0]).toBe(true);
    expect(call?.[1]).toMatchObject({
      authScope: "personal",
      credentialFingerprint: authFingerprint,
    });
    expect(mocks.loadProviderUsageSummary).toHaveBeenCalledWith(
      expect.objectContaining({
        auth: [
          expect.objectContaining({ token: "personal-access", authProfileId: personalProfileId }),
        ],
      }),
    );
  });

  it("isolates identical credentials across session and lifecycle cache owners", async () => {
    const authFingerprint = expectDefined(
      fingerprintResolvedAuthProfileCredential({
        profileId: "openai:shared-winner",
        credential: sharedCredential,
        resolvedAuth: undefined,
      }),
      "shared credential fingerprint",
    );
    for (const binding of [
      { sessionKey: "agent:main:main", sessionId: sessionEntry.sessionId },
      { sessionKey: "agent:main:secondary", sessionId: "session-two" },
    ]) {
      recordSessionSuccessfulAuthBinding({
        ...binding,
        lifecycleRevision: sessionEntry.lifecycleRevision,
        provider: sessionEntry.modelProvider,
        model: sessionEntry.model,
        binding: {
          authProfileId: "openai:shared-winner",
          authFingerprint,
          modelId: sessionEntry.model,
        },
      });
    }
    mocks.loadProviderUsageSummary.mockImplementation(async () => ({
      updatedAt: Date.now(),
      providers: [
        {
          provider: "openai",
          displayName: "OpenAI",
          windows: [
            {
              label: "5h",
              usedPercent: mocks.loadProviderUsageSummary.mock.calls.length * 10,
            },
          ],
        },
      ],
    }));

    const first = await runScoped("agent:main:main");
    const second = await runScoped("agent:main:secondary");

    expect(first.call?.[1].providers[0].windows[0].usedPercent).toBe(10);
    expect(second.call?.[1].providers[0].windows[0].usedPercent).toBe(20);
    expect(first.call?.[1].sessionScope).toMatchObject({
      requestedSessionKey: "agent:main:main",
      effectiveSessionKey: "agent:main:main",
    });
    expect(second.call?.[1].sessionScope).toMatchObject({
      requestedSessionKey: "agent:main:secondary",
      effectiveSessionKey: "agent:main:secondary",
    });
    expect(mocks.loadProviderUsageSummary).toHaveBeenCalledTimes(2);
  });

  it("fails closed when the stored credential no longer matches the successful binding", async () => {
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
    const changedCredential: AuthProfileCredential = {
      ...sharedCredential,
      access: "changed-access",
      refresh: "changed-refresh",
      email: "changed@example.test",
    };
    mocks.getProviderUsageRuntimeSnapshot.mockReturnValue({
      agentId: "main",
      agentDir: "agent-dir",
      configRef: config,
      credentialKey: "unused",
      descriptors: [],
      directApiKeys: new Map(),
      providerIds: ["openai"],
      store: { version: 1, profiles: { "openai:shared-winner": changedCredential } },
    });
    mocks.resolveApiKeyForProfile.mockResolvedValue({
      apiKey: "changed-access",
      provider: "openai",
      profileId: "openai:shared-winner",
    });

    const { call } = await runScoped();
    expect(call?.[1]).toMatchObject({
      providers: [],
      sessionScope: { status: "unavailable", reason: "credential-changed" },
    });
    expect(mocks.loadProviderUsageSummary).not.toHaveBeenCalled();
  });

  it("preserves the exact OAuth grant across an access-token refresh", async () => {
    const rotatingCredential: AuthProfileCredential = {
      type: "oauth",
      provider: "openai",
      access: "old-access",
      refresh: "old-refresh",
      expires: 1,
    };
    const refreshedCredential: AuthProfileCredential = {
      ...rotatingCredential,
      access: "new-access",
      refresh: "new-refresh",
      expires: Date.now() + 3_600_000,
    };
    const oldFingerprint = expectDefined(
      fingerprintResolvedAuthProfileCredential({
        profileId: "openai:shared-winner",
        credential: rotatingCredential,
        resolvedAuth: undefined,
      }),
      "old OAuth fingerprint",
    );
    recordSessionSuccessfulAuthBinding({
      sessionKey: "agent:main:main",
      sessionId: sessionEntry.sessionId,
      lifecycleRevision: sessionEntry.lifecycleRevision,
      provider: sessionEntry.modelProvider,
      model: sessionEntry.model,
      binding: {
        authProfileId: "openai:shared-winner",
        authFingerprint: oldFingerprint,
        modelId: sessionEntry.model,
      },
    });
    const runtimeSnapshot = (credential: AuthProfileCredential) => ({
      agentId: "main",
      agentDir: "agent-dir",
      configRef: config,
      credentialKey: "unused",
      descriptors: [],
      directApiKeys: new Map(),
      providerIds: ["openai"],
      store: { version: 1, profiles: { "openai:shared-winner": credential } },
    });
    mocks.getProviderUsageRuntimeSnapshot.mockReturnValue(runtimeSnapshot(rotatingCredential));
    mocks.resolveApiKeyForProfile.mockResolvedValue({
      apiKey: "new-access",
      provider: "openai",
      profileId: "openai:shared-winner",
      credential: refreshedCredential,
    });

    const first = await runScoped();
    const refreshedFingerprint = first.call?.[1].credentialFingerprint;
    expect(refreshedFingerprint).not.toBe(oldFingerprint);
    expect(first.call?.[1].sessionScope.credential).toMatchObject({
      sessionBindingId: refreshedFingerprint,
      sampledBindingId: refreshedFingerprint,
      consistency: "match",
    });

    mocks.getProviderUsageRuntimeSnapshot.mockReturnValue(runtimeSnapshot(refreshedCredential));
    const second = await runScoped();
    expect(second.call?.[1].credentialFingerprint).toBe(refreshedFingerprint);
    expect(second.call?.[1].cache.status).toBe("fresh");
    expect(mocks.loadProviderUsageSummary).toHaveBeenCalledTimes(1);
  });

  it("returns an empty unverified result without a successful binding", async () => {
    const { call } = await runScoped();
    expect(call?.[0]).toBe(true);
    expect(call?.[1]).toMatchObject({
      providers: [],
      sessionScope: { status: "unavailable", reason: "binding-missing" },
      cache: { status: "unavailable" },
    });
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
