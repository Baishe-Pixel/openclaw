import { expect, test } from "vitest";
import { validateSessionsUsageParams, validateUsageStatusParams } from "./index.js";

test("sessions.usage accepts time zones and opaque creator selectors", () => {
  for (const params of [
    { mode: "specific", timeZone: "Europe/Vienna" },
    { mode: "specific", utcOffset: "UTC+2" },
    { creatorKey: '["profile","person"]' },
  ]) {
    expect(validateSessionsUsageParams(params)).toBe(true);
  }
  for (const params of [
    { mode: "specific", timeZone: "" },
    { mode: "specific", timeZone: 2 },
    { creatorKey: "" },
    { creatorKey: 2 },
  ]) {
    expect(validateSessionsUsageParams(params)).toBe(false);
  }
});

test("usage.status accepts only legacy empty params or a session key", () => {
  expect(validateUsageStatusParams({})).toBe(true);
  expect(validateUsageStatusParams({ sessionKey: "agent:main:main" })).toBe(true);
  expect(validateUsageStatusParams({ sessionKey: "" })).toBe(false);
  expect(validateUsageStatusParams({ authProfileId: "private" })).toBe(false);
});
