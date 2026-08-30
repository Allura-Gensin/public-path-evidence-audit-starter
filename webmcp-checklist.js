(function initializeAllureChecklistWebMCP(global) {
  "use strict";

  const SOURCE_PATH = "/public-path-checklist/";
  const MAX_TARGET_ACTION_LENGTH = 120;
  const MAX_ROUTES = 5;
  const ALLOWED_VIEWPORTS = new Set(["desktop", "mobile", "both"]);
  const SAFE_INPUT_KEYS = new Set(["target_action", "routes", "viewport"]);
  const PRIVATE_HOST_SUFFIXES = [
    ".internal",
    ".invalid",
    ".local",
    ".localhost",
    ".test",
  ];
  const PROHIBITED_SCOPE = /\b(?:api[ -]?key|card(?:holder)?|checkout|credential|customer[ -]?data|health|log[ -]?in|medical|password|patient|payment|private[ -]?data|purchase|sign[ -]?in)\b/i;

  const checks = Object.freeze([
    Object.freeze({ id: "01", title: "Name the first promise", detail: "Write the one claim, offer, or outcome a visitor sees before the first call to action." }),
    Object.freeze({ id: "02", title: "Follow the primary click", detail: "Record every public page, redirect, decision, and dead end on the primary visitor path." }),
    Object.freeze({ id: "03", title: "Match the destination", detail: "Confirm the destination still delivers the promise that prompted the click." }),
    Object.freeze({ id: "04", title: "Check the return path", detail: "Confirm labels and navigation help a visitor recover from a wrong turn." }),
    Object.freeze({ id: "05", title: "Read the trust pages", detail: "Review visible pricing, privacy, terms, and contact links only for consistency with the offer." }),
    Object.freeze({ id: "06", title: "Repeat at a narrow viewport", detail: "Check the same route for hidden calls to action, overflow, stacked controls, or changed meaning." }),
    Object.freeze({ id: "07", title: "Separate observation from preference", detail: "Record reproducible observations separately from subjective design questions." }),
    Object.freeze({ id: "08", title: "Choose one next change", detail: "Prioritize the smallest change that removes an observed public-route break." }),
  ]);

  const stopConditions = Object.freeze([
    "A route requires a login or credentials.",
    "The review requires data entry, form submission, email confirmation, or a purchase.",
    "The review would expose customer, payment, health, or other private data.",
    "The work would require security testing or a production change.",
  ]);

  function abortIfRequested(context) {
    if (context && context.signal && typeof context.signal.throwIfAborted === "function") {
      context.signal.throwIfAborted();
    }
  }

  function assertPlainObject(value, label) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new TypeError(`${label} must be an object.`);
    }
  }

  function normalizeTargetAction(value) {
    if (typeof value !== "string") {
      throw new TypeError("target_action must be a string.");
    }
    const normalized = value.replace(/\s+/g, " ").trim();
    if (!normalized || normalized.length > MAX_TARGET_ACTION_LENGTH) {
      throw new TypeError(`target_action must contain 1 to ${MAX_TARGET_ACTION_LENGTH} characters.`);
    }
    if (PROHIBITED_SCOPE.test(normalized)) {
      throw new TypeError("target_action crosses the public-only review boundary.");
    }
    return normalized;
  }

  function isIpLiteral(hostname) {
    if (hostname.includes(":")) return true;
    const parts = hostname.split(".");
    return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part));
  }

  function normalizePublicRoute(value) {
    if (typeof value !== "string" || !value || value.length > 2048) {
      throw new TypeError("Each route must be a non-empty URL of at most 2048 characters.");
    }
    if (/\\|\s|[\u0000-\u001f\u007f-\u009f]/.test(value)) {
      throw new TypeError("Routes may not contain whitespace, backslashes, or control characters.");
    }

    let route;
    try {
      route = new URL(value);
    } catch {
      throw new TypeError("Each route must be a valid public HTTPS URL.");
    }

    if (route.protocol !== "https:" || !route.hostname) {
      throw new TypeError("Each route must use HTTPS and include a hostname.");
    }
    if (route.username || route.password) {
      throw new TypeError("Credential-bearing routes are not allowed.");
    }
    if (route.search || route.hash) {
      throw new TypeError("Query strings and fragments are not allowed.");
    }
    if (route.port && route.port !== "443") {
      throw new TypeError("Only HTTPS port 443 is allowed.");
    }

    const hostname = route.hostname.toLowerCase().replace(/\.$/, "");
    if (
      !hostname.includes(".") ||
      hostname === "localhost" ||
      isIpLiteral(hostname) ||
      PRIVATE_HOST_SUFFIXES.some((suffix) => hostname.endsWith(suffix))
    ) {
      throw new TypeError("Each route must use a public hostname, not a local, private, test, or IP-literal host.");
    }
    if (route.pathname.startsWith("//")) {
      throw new TypeError("Network-path-style route paths are not allowed.");
    }

    route.hostname = hostname;
    route.port = "";
    return route.href;
  }

  function listPublicPathChecks(input = {}, context = {}) {
    abortIfRequested(context);
    assertPlainObject(input, "input");
    const allowed = new Set(["include_stop_conditions"]);
    for (const key of Object.keys(input)) {
      if (!allowed.has(key)) throw new TypeError(`Unsupported input field: ${key}.`);
    }
    if (input.include_stop_conditions !== undefined && typeof input.include_stop_conditions !== "boolean") {
      throw new TypeError("include_stop_conditions must be a boolean.");
    }

    return {
      source: SOURCE_PATH,
      scope: "public observation only",
      executes_review: false,
      checks: checks.map((check) => ({ ...check })),
      stop_conditions: input.include_stop_conditions === false ? [] : [...stopConditions],
    };
  }

  function preparePublicPathCheck(input, context = {}) {
    abortIfRequested(context);
    assertPlainObject(input, "input");
    for (const key of Object.keys(input)) {
      if (!SAFE_INPUT_KEYS.has(key)) throw new TypeError(`Unsupported input field: ${key}.`);
    }

    const targetAction = normalizeTargetAction(input.target_action);
    if (!Array.isArray(input.routes) || input.routes.length < 1 || input.routes.length > MAX_ROUTES) {
      throw new TypeError(`routes must contain 1 to ${MAX_ROUTES} public HTTPS URLs.`);
    }
    const routes = input.routes.map(normalizePublicRoute);
    if (new Set(routes).size !== routes.length) {
      throw new TypeError("Duplicate routes are not allowed.");
    }

    const viewport = input.viewport === undefined ? "both" : input.viewport;
    if (typeof viewport !== "string" || !ALLOWED_VIEWPORTS.has(viewport)) {
      throw new TypeError("viewport must be desktop, mobile, or both.");
    }

    return {
      source: SOURCE_PATH,
      scope: "synthetic plan for public observation only",
      executes_review: false,
      fetches_routes: false,
      stores_input: false,
      target_action: targetAction,
      viewport,
      route_register_columns: [
        "route_id",
        "public_start_url",
        "visitor_action",
        "desktop_checked_at_utc",
        "mobile_checked_at_utc",
        "owner_notes",
      ],
      route_register: routes.map((publicStartUrl, index) => ({
        route_id: `route-${String(index + 1).padStart(2, "0")}`,
        public_start_url: publicStartUrl,
        visitor_action: targetAction,
        desktop_checked_at_utc: "",
        mobile_checked_at_utc: "",
        owner_notes: "",
      })),
      review_sequence: checks.map(({ id, title }) => ({ id, title })),
      stop_conditions: [...stopConditions],
    };
  }

  const toolDefinitions = Object.freeze([
    Object.freeze({
      name: "list_public_path_checks",
      title: "List public-path checks",
      description: "Return Allure Labs' eight public-only launch-path checks and stop conditions. This tool does not visit a URL or modify anything.",
      inputSchema: {
        type: "object",
        properties: {
          include_stop_conditions: { type: "boolean", default: true },
        },
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, untrustedContentHint: false },
      execute: listPublicPathChecks,
    }),
    Object.freeze({
      name: "prepare_public_path_check",
      title: "Prepare a public-path check",
      description: "Validate one to five credential-free public HTTPS routes and return a non-executing route register plus review sequence. This tool does not fetch, submit, store, or modify anything.",
      inputSchema: {
        type: "object",
        properties: {
          target_action: { type: "string", minLength: 1, maxLength: MAX_TARGET_ACTION_LENGTH },
          routes: {
            type: "array",
            minItems: 1,
            maxItems: MAX_ROUTES,
            uniqueItems: true,
            items: { type: "string", format: "uri", maxLength: 2048 },
          },
          viewport: { type: "string", enum: ["desktop", "mobile", "both"], default: "both" },
        },
        required: ["target_action", "routes"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, untrustedContentHint: true },
      execute: preparePublicPathCheck,
    }),
  ]);

  async function register(modelContext = global.document && global.document.modelContext) {
    if (!modelContext || typeof modelContext.registerTool !== "function") return false;
    const lifecycle = new AbortController();
    for (const tool of toolDefinitions) {
      await modelContext.registerTool(tool, { signal: lifecycle.signal });
    }
    return { lifecycle, names: toolDefinitions.map((tool) => tool.name) };
  }

  const api = Object.freeze({
    checks,
    stopConditions,
    toolDefinitions,
    listPublicPathChecks,
    preparePublicPathCheck,
    register,
  });
  global.__allureWebMCPChecklist = api;
  void register();
})(globalThis);
