import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import test from "node:test";
import {
  isKnownPermission,
  validateCommunityList,
  validateEntry,
} from "./validate.mjs";
import { buildBumpedEntry } from "./bump-versions.mjs";

// Behavioral inputs mirrored from plugin-sdk/spec/permissions.json (SDK 0.3.20).
// Exercise the real registration/bump validators, not a second implementation.
const knownPermissions = [
  "storage", "ui:settings-section", "ui:add-menu", "ui:composer-status",
  "ui:panel-tab", "ui:status-bar", "ui:overlay", "ui:command", "ui:markdown",
  "ui:page", "ui:timeline-row", "ui:workspace-menu", "ui:session-menu",
  "ui:sidebar-entry", "ui:center-tab", "ui:conversation-mode", "agent", "theme",
  "i18n", "events", "network:none", "composer:draft", "host:session",
  "host:workspace", "host:workspace:remote", "host:worktree", "host:window",
  "host:models", "session.lifecycle.read", "runtime.events.read",
  "runtime.switch.observe", "prompt.contribute.internal", "workspace.metadata.read",
  "plugin.storage", "assets:bundle", "assets:directory",
];
const ccbPermissions = [
  "storage", "ui:settings-section", "ui:workspace-menu", "i18n", "events",
  "network:none", "session.lifecycle.read", "runtime.events.read",
  "runtime.switch.observe", "prompt.contribute.internal", "workspace.metadata.read",
  "host:workspace", "plugin.storage",
];
const validIds = [
  "ab", "a-", "a.b", "a1-2.b3", "ccgui.client-context-bridge",
  "vendor.plugin2.feature-x", "a".repeat(64), "0a", "0.1", "a-.b-",
  "a." + "b".repeat(62),
];
const invalidIds = [
  "", "a", ".", "..", ".plugin", "plugin.", "a..b", "../plugin", "a/b",
  "a\\b", "Plugin", "-a", "a+b", "a".repeat(65), "a.-b", "a._b", "a.B",
  "a_", "a:b", "a b", " ab", "ab ", "a/../b", "a.%2e%2e.b", "a．b",
  "插件", "éa", "a.é", "a💡", "ab\u2028", "ab\u2029",
  "a." + "b".repeat(63),
  ...Array.from({ length: 33 }, (_, i) => String.fromCharCode(i === 32 ? 127 : i))
    .flatMap((char) => [`${char}ab`, `a${char}b`, `ab${char}`]),
];
const validGrants = [
  "network:127.0.0.1", "network:api.example.com", "network:EXAMPLE.com",
  "network:api.example.com:8443", "network:127.0.0.1:7680-7690",
  "network:host:1-65535", "network:host:1", "network:host:65535",
  "exec:git", "exec:node", "exec:my-cli.v2", "exec:my_cli",
];
const invalidPermissions = [
  "unknown", "ui:unknown", "session.lifecycle.write", "runtime.events.write",
  "runtime.switch.write", "prompt.contribute.external", "workspace.metadata.write",
  "plugin.storage.admin", "assets:unknown", "network:", "network:bad host",
  "network:*.example.com", "network:host:abc", "network:host:99999",
  "network:host:65536", "network:host:0", "network:host:0-80",
  "network:host:90-80", "network:host:1-2-3", "network:host:",
  "network:NONE", "network:none:80", "network:NoNe:1-65535",
  "network:https://example.com", "network:host/path", "network:host\\path",
  "network:host\n", "network:host:80\r", "network:host\0",
  "exec:", "exec:a/b", "exec:../x", "exec:x y", "exec:a\\b",
  "exec:git\n", "exec:git\r", "exec:git\0", "storage\n",
];

function entry(overrides = {}) {
  return {
    id: "sample-plugin",
    repo: "example/sample-plugin",
    tier: "js",
    version: "1.0.2",
    minAppVersion: "1.0.0",
    sdkVersion: ">=0.3.20",
    permissions: ["storage"],
    sha256: { "manifest.json": "a".repeat(64), "main.js": "b".repeat(64) },
    ...overrides,
  };
}

function entryErrors(value, fileName = `${value.id}.json`) {
  const errors = [];
  validateEntry(value, fileName, errors, []);
  return errors;
}

function communityErrors(id) {
  const errors = [];
  validateCommunityList([{
    id, repo: "example/sample-plugin", name: "Sample", description: "Sample plugin",
    author: "Example",
  }], errors, []);
  return errors;
}

function releaseFetch(t, candidate, main = "export function activate() {}") {
  const files = {
    "manifest.json": Buffer.from(JSON.stringify(candidate)),
    "main.js": Buffer.from(main),
  };
  const fetchMock = t.mock.method(globalThis, "fetch", async (url) => {
    const prefix = `https://github.com/${candidate.repo}/releases/download/${candidate.version}/`;
    assert.ok(url.startsWith(prefix), `Unexpected release URL: ${url}`);
    const file = url.slice(prefix.length);
    assert.ok(Object.hasOwn(files, file), `Unexpected release asset: ${file}`);
    return new Response(files[file], { status: 200 });
  });
  return { files, fetchMock };
}

function denyFetch(t) {
  return t.mock.method(globalThis, "fetch", async () => {
    throw new Error("Invalid input must be rejected before downloading");
  });
}

test("registration accepts ordinary and namespaced IDs at byte-length boundaries", () => {
  for (const id of validIds) {
    assert.deepEqual(communityErrors(id), [], JSON.stringify(id));
    assert.deepEqual(entryErrors(entry({ id })), [], JSON.stringify(id));
  }
});

test("registration rejects unsafe IDs in both index and entry validation", () => {
  for (const id of [...invalidIds, null, 12, {}, []]) {
    assert.ok(communityErrors(id).some((error) => error.includes(".id")), JSON.stringify(id));
    assert.ok(entryErrors(entry({ id })).some((error) => error.includes(".id")), JSON.stringify(id));
  }
});

test("namespaced IDs still have to match the registry filename", () => {
  const errors = entryErrors(entry({ id: "vendor.plugin" }), "other.plugin.json");
  assert.ok(errors.some((error) => error.includes("与文件名")));
});

test("CCB registers its unchanged ID and all 13 declared permissions", () => {
  const id = "ccgui.client-context-bridge";
  assert.deepEqual(communityErrors(id), []);
  assert.deepEqual(entryErrors(entry({ id, permissions: ccbPermissions })), []);
});

test("all SDK base permissions and valid network/exec grants are accepted", () => {
  for (const permission of [...knownPermissions, ...validGrants]) {
    assert.equal(isKnownPermission(permission), true, permission);
    assert.deepEqual(entryErrors(entry({ permissions: [permission] })), [], permission);
  }
});

test("unknown permissions and malformed network/exec grants remain rejected", () => {
  for (const permission of invalidPermissions) {
    assert.equal(isKnownPermission(permission), false, JSON.stringify(permission));
    assert.ok(entryErrors(entry({ permissions: [permission] }))
      .some((error) => error.includes("permissions")), JSON.stringify(permission));
  }
});

test("permissions must remain an array of strings", () => {
  for (const permissions of ["storage", {}, [null], [12], [{}]]) {
    assert.ok(entryErrors(entry({ permissions })).some((error) => error.includes("permissions")));
  }
});

test("current registry entries retain schema validity", () => {
  const errors = [];
  const warnings = [];
  const community = JSON.parse(readFileSync(new URL("../community-plugins.json", import.meta.url), "utf8"));
  validateCommunityList(community, errors, warnings);
  const directory = new URL("../plugins/", import.meta.url);
  for (const file of readdirSync(directory).filter((file) => file.endsWith(".json"))) {
    const value = JSON.parse(readFileSync(new URL(file, directory), "utf8"));
    validateEntry(value, file, errors, warnings);
  }
  assert.deepEqual(errors, []);
});

test("bump preflight accepts CCB permissions and produces a valid registration", async (t) => {
  const old = entry({ id: "ccgui.client-context-bridge", version: "1.0.1", permissions: ccbPermissions });
  const candidate = { ...old, version: "1.0.2" };
  const { files, fetchMock } = releaseFetch(t, candidate);
  const result = await buildBumpedEntry(old.id, old, candidate.version, candidate, Object.keys(files));
  assert.equal(result.skip, undefined);
  assert.deepEqual(result.notes, []);
  assert.equal(result.entry.id, old.id);
  assert.equal(result.entry.version, candidate.version);
  assert.deepEqual(result.entry.permissions, ccbPermissions);
  assert.deepEqual(entryErrors(result.entry), []);
  for (const [file, data] of Object.entries(files)) {
    assert.equal(result.entry.sha256[file], createHash("sha256").update(data).digest("hex"));
  }
  assert.equal(fetchMock.mock.calls.length, 2);
});

test("bump preflight shares the complete permission and ID acceptance contract", async (t) => {
  for (const id of validIds) {
    await t.test(id, async (t) => {
      const old = entry({ id, version: "1.0.1" });
      const candidate = entry({ id, permissions: [...knownPermissions, ...validGrants] });
      const { files } = releaseFetch(t, candidate);
      const result = await buildBumpedEntry(id, old, candidate.version, candidate, Object.keys(files));
      assert.equal(result.skip, undefined);
      assert.deepEqual(result.entry.permissions, candidate.permissions);
      assert.deepEqual(entryErrors(result.entry), []);
    });
  }
});

test("bump preflight rejects unsafe IDs before fetching artifacts", async (t) => {
  const fetchMock = denyFetch(t);
  for (const id of [...invalidIds, null, 12]) {
    const old = entry({ id, version: "1.0.1" });
    const candidate = entry({ id });
    const result = await buildBumpedEntry(id, old, candidate.version, candidate, []);
    assert.equal(result.entry, undefined, JSON.stringify(id));
    assert.equal(typeof result.skip, "string", JSON.stringify(id));
  }
  assert.equal(fetchMock.mock.calls.length, 0);
});

test("bump preflight rejects unknown and malformed permissions before fetching", async (t) => {
  const fetchMock = denyFetch(t);
  for (const permissions of [
    ...invalidPermissions.map((permission) => [permission]),
    "storage", {}, [null], [12], [{}],
  ]) {
    const old = entry({ version: "1.0.1" });
    const candidate = entry({ permissions });
    const result = await buildBumpedEntry(old.id, old, candidate.version, candidate, []);
    assert.equal(result.entry, undefined, JSON.stringify(permissions));
    assert.equal(typeof result.skip, "string", JSON.stringify(permissions));
  }
  assert.equal(fetchMock.mock.calls.length, 0);
});

test("bump preflight retains manifest identity, version and tier checks", async (t) => {
  const fetchMock = denyFetch(t);
  const old = entry({ id: "vendor.plugin", version: "1.0.1" });
  for (const overrides of [{ id: "other.plugin" }, { version: "1.0.3" }, { tier: "declarative" }]) {
    const candidate = entry({ id: old.id, ...overrides });
    const result = await buildBumpedEntry(old.id, old, "1.0.2", candidate, []);
    assert.equal(result.entry, undefined);
    assert.equal(typeof result.skip, "string");
  }
  assert.equal(fetchMock.mock.calls.length, 0);
});

test("namespaced IDs and new permissions do not bypass the bundle blacklist", async (t) => {
  const old = entry({ id: "ccgui.client-context-bridge", version: "1.0.1" });
  const candidate = entry({ id: old.id, permissions: ccbPermissions });
  const { files } = releaseFetch(t, candidate, "eval('unsafe')");
  const result = await buildBumpedEntry(old.id, old, candidate.version, candidate, Object.keys(files));
  assert.equal(result.entry, undefined);
  assert.equal(typeof result.skip, "string");
});
