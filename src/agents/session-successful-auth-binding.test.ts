import { beforeEach, describe, expect, it } from "vitest";
import {
  clearSessionSuccessfulAuthBindingsForTest,
  invalidateSessionSuccessfulAuthBinding,
  readSessionSuccessfulAuthBinding,
  recordSessionSuccessfulAuthBinding,
} from "./session-successful-auth-binding.js";

const identity = {
  sessionKey: "agent:main:main",
  sessionId: "session-one",
  lifecycleRevision: "3",
  provider: "openai",
  model: "gpt-test",
};

beforeEach(clearSessionSuccessfulAuthBindingsForTest);

describe("session successful auth binding", () => {
  it("records only a successful credential fingerprint", () => {
    recordSessionSuccessfulAuthBinding({
      ...identity,
      binding: {
        authProfileId: "openai:shared-winner",
        authFingerprint: "winner-fingerprint",
        modelId: identity.model,
      },
    });
    expect(readSessionSuccessfulAuthBinding(identity)).toMatchObject({
      authProfileId: "openai:shared-winner",
      authFingerprint: "winner-fingerprint",
    });
  });

  it("fails closed without a successful binding or after identity and route changes", () => {
    recordSessionSuccessfulAuthBinding({ ...identity, binding: undefined });
    expect(readSessionSuccessfulAuthBinding(identity)).toBeUndefined();

    recordSessionSuccessfulAuthBinding({
      ...identity,
      binding: {
        authProfileId: "openai:shared-winner",
        authFingerprint: "winner-fingerprint",
      },
    });
    expect(
      readSessionSuccessfulAuthBinding({ ...identity, sessionId: "session-reset" }),
    ).toBeUndefined();
    expect(
      readSessionSuccessfulAuthBinding({ ...identity, lifecycleRevision: "4" }),
    ).toBeUndefined();
    expect(readSessionSuccessfulAuthBinding({ ...identity, model: "other-model" })).toBeUndefined();
    expect(
      readSessionSuccessfulAuthBinding({ ...identity, provider: "other-provider" }),
    ).toBeUndefined();
  });

  it("invalidates the prior generation on reset", () => {
    recordSessionSuccessfulAuthBinding({
      ...identity,
      binding: {
        authProfileId: "openai:shared-winner",
        authFingerprint: "winner-fingerprint",
      },
    });
    invalidateSessionSuccessfulAuthBinding(identity.sessionKey);
    expect(readSessionSuccessfulAuthBinding(identity)).toBeUndefined();
  });
});
