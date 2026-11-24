import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { claimMammothMailSetupCode, mammothMailSetupAdapter, parseSetupCode } from "../src/setup.js";

test("manifest accepts required credentials at the root or per named account", () => {
  const manifest = JSON.parse(
    readFileSync(new URL("../../openclaw.plugin.json", import.meta.url), "utf8"),
  );
  const schema = manifest.channelConfigs.mammothmail.schema;
  assert.deepEqual(schema.anyOf, [
    { required: ["baseUrl", "gatewayId", "secret"] },
    { required: ["accounts"] },
  ]);
  assert.deepEqual(schema.allOf[0], {
    if: {
      anyOf: [
        { required: ["baseUrl"] },
        { required: ["gatewayId"] },
        { required: ["secret"] },
      ],
    },
    then: { required: ["baseUrl", "gatewayId", "secret"] },
  });
  assert.deepEqual(schema.properties.accounts.additionalProperties.required, [
    "baseUrl",
    "gatewayId",
    "secret",
  ]);
  assert.equal(schema.properties.accounts.minProperties, 1);
});

test("named-account setup writes credentials under accounts", () => {
  const patched = mammothMailSetupAdapter.applyAccountConfig({
    cfg: {},
    accountId: "uat-pr25",
    input: {
      baseUrl: "http://mail.example.com",
      gatewayId: "gw-test",
      secret: "secret-test",
    },
  });
  assert.deepEqual(patched.channels?.mammothmail, {
    enabled: true,
    accounts: {
      "uat-pr25": {
        enabled: true,
        baseUrl: "http://mail.example.com",
        gatewayId: "gw-test",
        secret: "secret-test",
      },
    },
  });
});

test("parseSetupCode reads the base URL from a setup URL fragment", () => {
  const parsed = parseSetupCode({ code: "http://mail.example.com/#abc123" });
  assert.equal(parsed.baseUrl, "http://mail.example.com");
  assert.equal(parsed.code, "abc123");
});

test("parseSetupCode requires a base URL for a bare code", () => {
  assert.throws(() => parseSetupCode({ code: "abc123" }));
  const parsed = parseSetupCode({ code: "abc123", baseUrl: "https://mail.example.com/" });
  assert.equal(parsed.baseUrl, "https://mail.example.com");
  assert.equal(parsed.code, "abc123");
});

test("claimMammothMailSetupCode posts the code and returns credentials", async () => {
  const calls: Array<{ url: string; body: string }> = [];
  const fetchImpl = (async (url: string, init: { body: string }) => {
    calls.push({ url: String(url), body: init.body });
    return new Response(JSON.stringify({ secret: "sec", gatewayId: "gw-x", kind: "openclaw" }), {
      status: 200,
    });
  }) as unknown as typeof fetch;
  const result = await claimMammothMailSetupCode({
    baseUrl: "http://mail.example.com/",
    code: "abc",
    gatewayId: "gw-x",
    fetchImpl,
  });
  assert.equal(calls[0].url, "http://mail.example.com/relay/enroll");
  assert.deepEqual(JSON.parse(calls[0].body), { enrollmentToken: "abc", gatewayId: "gw-x" });
  assert.equal(result.secret, "sec");
});

test("claimMammothMailSetupCode surfaces an expired code", async () => {
  const fetchImpl = (async () => new Response("no", { status: 403 })) as unknown as typeof fetch;
  await assert.rejects(
    () => claimMammothMailSetupCode({ baseUrl: "http://mail.example.com", code: "x", fetchImpl }),
    /invalid, expired or already used/,
  );
});
