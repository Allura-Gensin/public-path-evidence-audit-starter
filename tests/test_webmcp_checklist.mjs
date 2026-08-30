import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const source = await readFile(new URL("../webmcp-checklist.js", import.meta.url), "utf8");

async function load({ withModelContext = true } = {}) {
  const registered = [];
  const document = {};
  if (withModelContext) {
    document.modelContext = {
      async registerTool(tool, options) {
        registered.push({ tool, options });
      },
    };
  }

  const context = vm.createContext({ AbortController, document, URL });
  vm.runInContext(source, context, { filename: "webmcp-checklist.js" });
  await new Promise((resolve) => setImmediate(resolve));
  return { api: context.__allureWebMCPChecklist, registered };
}

test("no-ops in unsupported browsers while preserving the normal page", async () => {
  const { api, registered } = await load({ withModelContext: false });
  assert.ok(api);
  assert.equal(registered.length, 0);
  assert.equal(await api.register(), false);
});

test("registers exactly two current-shape read-only WebMCP tools", async () => {
  const { registered } = await load();
  assert.deepEqual(
    registered.map(({ tool }) => tool.name),
    ["list_public_path_checks", "prepare_public_path_check"],
  );
  for (const { tool, options } of registered) {
    assert.equal(tool.annotations.readOnlyHint, true);
    assert.equal(tool.inputSchema.additionalProperties, false);
    assert.equal(typeof tool.execute, "function");
    assert.equal(options.signal.aborted, false);
  }
});

test("returns the authoritative checklist without executing a review", async () => {
  const { api } = await load();
  const output = api.listPublicPathChecks({ include_stop_conditions: true });
  assert.equal(output.source, "/public-path-checklist/");
  assert.equal(output.executes_review, false);
  assert.equal(output.checks.length, 8);
  assert.equal(output.stop_conditions.length, 4);
  assert.throws(() => api.listPublicPathChecks({ extra: true }), /Unsupported input field/);
});

test("builds a deterministic five-route register without fetching or storing", async () => {
  const { api } = await load();
  const input = {
    target_action: "Request a product demo",
    routes: [
      "https://allurelabs.ai/",
      "https://allurelabs.ai/pricing",
      "https://allurelabs.ai/product",
      "https://allurelabs.ai/contact",
      "https://allurelabs.ai/terms",
    ],
    viewport: "both",
  };
  const first = api.preparePublicPathCheck(input);
  const second = api.preparePublicPathCheck(input);
  assert.equal(JSON.stringify(first), JSON.stringify(second));
  assert.equal(first.executes_review, false);
  assert.equal(first.fetches_routes, false);
  assert.equal(first.stores_input, false);
  assert.equal(first.route_register.length, 5);
  assert.deepEqual(Array.from(first.route_register_columns), [
    "route_id",
    "public_start_url",
    "visitor_action",
    "desktop_checked_at_utc",
    "mobile_checked_at_utc",
    "owner_notes",
  ]);
  assert.equal(first.route_register[0].route_id, "route-01");
  assert.equal(first.route_register[4].route_id, "route-05");
  assert.equal(first.review_sequence.length, 8);
});

test("fails closed on private, credentialed, or mutation-shaped requests", async () => {
  const { api } = await load();
  const valid = { target_action: "Review the public demo request path", routes: ["https://allurelabs.ai/"] };
  const invalidRoutes = [
    "http://allurelabs.ai/",
    "https://user:secret@allurelabs.ai/",
    "https://allurelabs.ai/?token=secret",
    "https://allurelabs.ai/#private",
    "https://127.0.0.1/",
    "https://localhost/",
    "https://service.internal/",
    "https://example.test/",
    "https://allurelabs.ai:8443/",
  ];
  for (const route of invalidRoutes) {
    assert.throws(() => api.preparePublicPathCheck({ ...valid, routes: [route] }), undefined, route);
  }
  for (const target_action of ["Log in as a customer", "Submit payment", "Inspect private data", "Use an API key"]) {
    assert.throws(() => api.preparePublicPathCheck({ ...valid, target_action }), /public-only review boundary/);
  }
  assert.throws(() => api.preparePublicPathCheck({ ...valid, extra: true }), /Unsupported input field/);
  assert.throws(() => api.preparePublicPathCheck({ ...valid, routes: Array(6).fill("https://allurelabs.ai/") }), /1 to 5/);
  assert.throws(() => api.preparePublicPathCheck({ ...valid, routes: ["https://allurelabs.ai/", "https://allurelabs.ai/"] }), /Duplicate/);
});

test("honors cancellation before producing output", async () => {
  const { api } = await load();
  const lifecycle = new AbortController();
  lifecycle.abort(new Error("cancelled"));
  assert.throws(
    () => api.listPublicPathChecks({}, { signal: lifecycle.signal }),
    /cancelled/,
  );
});

test("proof source contains no network, navigation, storage, form, or email action", () => {
  assert.doesNotMatch(source, /\bfetch\s*\(|XMLHttpRequest|sendBeacon|localStorage|sessionStorage|indexedDB/i);
  assert.doesNotMatch(source, /location\s*=|\.submit\s*\(|mailto:|window\.open/i);
  assert.match(source, /document\.modelContext/);
  assert.match(source, /registerTool/);
});
