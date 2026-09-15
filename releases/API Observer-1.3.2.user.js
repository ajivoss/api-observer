// ==UserScript==
// @name         API Observer
// @namespace    local.api.observer
// @version      1.3.2
// @description  Passively observes same-origin API traffic and exports Discovery JSON, Postman 2.1, and OpenAPI 3.1.
// @match        https://github.com/*
// @run-at       document-start
// @grant        none
// ==/UserScript==

/*
 * USER CONFIGURATION
 *
 * 1. REQUIRED: Change @match above to the website where this script may run.
 *    Tampermonkey controls site access through @match. API Observer then uses
 *    location.origin automatically, so the origin is configured only once.
 *
 * 2. REQUIRED: Set prefixes to the same-origin API path prefixes to capture.
 *    Use ["/"] to observe every same-origin request path on the matched site.
 *
 * Examples:
 *   prefixes: ["/api/"]
 *   prefixes: ["/api/", "/rest/", "/graphql"]
 *   prefixes: ["/"]
 *
 * Only observe applications and traffic you are authorized to inspect.
 */
(() => {
  "use strict";
  const CFG = {
    prefixes: ["/"],
    db: "api-observer",
    store: "observations",
    maxBody: 5000000,
    postmanMaxResponse: 250000,
    maxVariants: 5,
    version: "1.3.2",
  };
  const ST = {
    on: sessionStorage.getItem("ObserverEnabled") !== "false",
    db: null,
    errors: 0,
    ui: null,
  };
  const iso = () => new Date().toISOString();
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const clone = (v) => JSON.parse(JSON.stringify(v));
  const stable = (v) =>
    v === null || typeof v !== "object"
      ? JSON.stringify(v)
      : Array.isArray(v)
        ? `[${v.map(stable)}]`
        : `{${Object.keys(v)
            .sort()
            .map((k) => JSON.stringify(k) + ":" + stable(v[k]))
            .join(",")}}`;
  const parse = (v) => {
    if (typeof v !== "string") return v;
    const t = v.trim();
    if (!t || !"{[".includes(t[0])) return v;
    try {
      return JSON.parse(t);
    } catch {
      return v;
    }
  };
  const clip = (v) => {
    if (v == null) return null;
    const s = String(v);
    return s.length <= CFG.maxBody
      ? s
      : s.slice(0, CFG.maxBody) +
          `\n...[TRUNCATED ${s.length - CFG.maxBody} CHARACTERS]`;
  };
  const route = () => ({
    href: location.href,
    pathname: location.pathname,
    hash: location.hash || "",
  });
  const shouldCapture = (u) => {
    try {
      const x = new URL(u, location.href);
      return (
        x.origin === location.origin &&
        CFG.prefixes.some((prefix) => x.pathname.startsWith(prefix))
      );
    } catch {
      return false;
    }
  };
  const headersObject = (h) => {
    const o = {};
    try {
      if (h instanceof Headers) h.forEach((v, k) => (o[k] = v));
      else if (Array.isArray(h)) h.forEach(([k, v]) => (o[k] = String(v)));
      else Object.assign(o, h || {});
    } catch (e) {
      o.__captureError = String(e);
    }
    return o;
  };
  const rawHeaders = (s) => {
    const o = {};
    for (const line of (s || "").trim().split(/[\r\n]+/)) {
      const i = line.indexOf(":");
      if (i > 0) o[line.slice(0, i).trim()] = line.slice(i + 1).trim();
    }
    return o;
  };
  const header = (h, n) =>
    Object.entries(h || {}).find(
      ([k]) => k.toLowerCase() === n.toLowerCase(),
    )?.[1] || null;

  const sensitiveKey = (k) =>
    /^(user(name)?|login|email|password|passwd|pwd|passcode|secret|credential|authorization|cookie|access.?token|refresh.?token)$/i.test(
      String(k).replace(/[^a-z0-9]/gi, ""),
    );
  function redact(value, key = "") {
    if (sensitiveKey(key)) return "<REDACTED>";
    if (Array.isArray(value)) return value.map((v) => redact(v, key));
    if (value && typeof value === "object")
      return Object.fromEntries(
        Object.entries(value).map(([k, v]) => [k, redact(v, k)]),
      );
    return value;
  }
  function redactBody(value, url) {
    const parsed = parse(value);
    const path = new URL(url, location.href).pathname.toLowerCase();
    if (path === "/api/session" || /\/(auth|login|token)(\/|$)/.test(path))
      return redact(parsed);
    return redact(parsed);
  }
  function redactHeaders(h) {
    return Object.fromEntries(
      Object.entries(h || {}).map(([k, v]) => [
        k,
        /authorization|cookie|token|secret|password/i.test(k)
          ? "<REDACTED>"
          : v,
      ]),
    );
  }

  async function captureBody(v, url) {
    try {
      if (v == null) return null;
      if (typeof v === "string") return redactBody(clip(v), url);
      if (v instanceof URLSearchParams) return redactBody(v.toString(), url);
      if (v instanceof FormData) {
        const fields = [];
        for (const [name, x] of v)
          fields.push(
            x instanceof File
              ? {
                  name,
                  kind: "file",
                  fileName: x.name,
                  type: x.type,
                  size: x.size,
                }
              : {
                  name,
                  kind: "field",
                  value: sensitiveKey(name) ? "<REDACTED>" : clip(x),
                },
          );
        return { __kind: "FormData", fields };
      }
      if (v instanceof Blob)
        return v.size > CFG.maxBody
          ? { __kind: "Blob", type: v.type, size: v.size, captured: false }
          : {
              __kind: "Blob",
              type: v.type,
              size: v.size,
              text: redactBody(clip(await v.text()), url),
            };
      if (v instanceof ArrayBuffer || ArrayBuffer.isView(v))
        return { __kind: "Binary", byteLength: v.byteLength, captured: false };
      return redact(clone(v));
    } catch (e) {
      return { __captureError: String(e) };
    }
  }

  function mergeSchemas(xs) {
    xs = xs.filter(Boolean).flatMap((x) => x.anyOf || [x]);
    if (!xs.length) return {};
    const types = [...new Set(xs.map((x) => x.type))];
    if (types.length !== 1) {
      const u = new Map(xs.map((x) => [stable(x), x]));
      return u.size === 1
        ? [...u.values()][0]
        : { anyOf: [...u.values()].slice(0, 25) };
    }
    const type = types[0];
    if (["string", "number", "boolean", "null"].includes(type)) {
      const examples = [];
      xs.flatMap((x) => x.examples || []).forEach((x) => {
        if (
          !examples.some((y) => stable(y) === stable(x)) &&
          examples.length < 20
        )
          examples.push(x);
      });
      return { type, ...(examples.length ? { examples } : {}) };
    }
    if (type === "array")
      return {
        type: "array",
        items: mergeSchemas(xs.map((x) => x.items)),
        "x-observed-lengths": [
          ...new Set(
            xs
              .flatMap((x) => x["x-observed-lengths"] || [x.observedLength])
              .filter(Number.isFinite),
          ),
        ].sort((a, b) => a - b),
      };
    if (type === "object") {
      const keys = [
          ...new Set(xs.flatMap((x) => Object.keys(x.properties || {}))),
        ].sort(),
        properties = {};
      keys.forEach(
        (k) =>
          (properties[k] = mergeSchemas(
            xs.map((x) => x.properties?.[k]).filter(Boolean),
          )),
      );
      const required = keys.filter((k) =>
        xs.every((x) => k in (x.properties || {})),
      );
      return {
        type: "object",
        properties,
        ...(required.length ? { required } : {}),
      };
    }
    return xs[0];
  }
  function schema(v, d = 0) {
    if (d > 20) return {};
    if (v === null) return { type: "null" };
    if (Array.isArray(v))
      return {
        type: "array",
        observedLength: v.length,
        items: mergeSchemas(v.slice(0, 100).map((x) => schema(x, d + 1))),
      };
    if (typeof v === "object") {
      const properties = {};
      Object.entries(v).forEach(([k, x]) => (properties[k] = schema(x, d + 1)));
      return { type: "object", properties, required: Object.keys(v) };
    }
    return { type: typeof v, examples: [v] };
  }

  const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const OBJECT_ID_RE = /^[0-9a-f]{24}$/i;
  const INTEGER_RE = /^\d+$/;
  const CONTEXT_KEY_RE = /^(tenant|organization|org|site|workspace|account|project|environment|env)(id)?$/i;
  const VOLATILE_HEADER_RE = /nonce|csrf|xsrf|anti[-_]?forgery|request[-_]?verification|^(x-)?request-id$|^(x-)?correlation-id$|^client-request-id$|^activity-id$|^query-id$/i;

  function variableName(value, fallback = "value") {
    const cleaned = String(value || fallback)
      .replace(/[^A-Za-z0-9]+(.)/g, (_, x) => x.toUpperCase())
      .replace(/^[^A-Za-z_]+/, "")
      .replace(/^./, (x) => x.toLowerCase());
    return cleaned || fallback;
  }

  function singular(value) {
    const x = variableName(value, "record");
    if (/ies$/i.test(x)) return x.slice(0, -3) + "y";
    if (/ses$/i.test(x)) return x.slice(0, -2);
    if (/s$/i.test(x) && !/ss$/i.test(x)) return x.slice(0, -1);
    return x;
  }

  function looksLikeIdentifier(value) {
    return GUID_RE.test(value) || OBJECT_ID_RE.test(value) || INTEGER_RE.test(value);
  }

  function pathParameterName(segments, index) {
    const previous = segments[index - 1] || "record";
    const base = singular(previous);
    return /id$/i.test(base) ? base : `${base}Id`;
  }

  function normalizePath(path) {
    const segments = path.split("/").filter(Boolean);
    return "/" + segments
      .map((segment, index) =>
        looksLikeIdentifier(segment)
          ? `{${pathParameterName(segments, index)}}`
          : segment,
      )
      .join("/");
  }

  function requestContext(url) {
    const x = new URL(url, location.href);
    return {
      origin: x.origin,
      pathname: x.pathname,
      query: Object.fromEntries(
        [...x.searchParams].map(([key, value]) => [
          key,
          sensitiveKey(key) ? "<REDACTED>" : value,
        ]),
      ),
    };
  }

  const endpointPath = (item) =>
    normalizePath(item.requestContext?.pathname || new URL(item.url).pathname);

  function classify(item) {
    const path = endpointPath(item).toLowerCase();
    if (/\/(auth|login|logout|session|token|oauth)(\/|$)/.test(path))
      return "Authentication API";
    if (/\/(search|query|lookup)([-_/]|$)/.test(path)) return "Search API";
    if (/\/(files?|documents?|blobs?|attachments?)(\/|$)/.test(path))
      return "File API";
    if (/\/(reports?|exports?)(\/|$)/.test(path)) return "Reporting API";
    if (/\/(admin|configuration|settings)(\/|$)/.test(path))
      return "Administration API";
    if (/\/(events?|comments?|activities|history)(\/|$)/.test(path))
      return "Activity API";
    if (/\/(metadata|schema|definitions?)(\/|$)/.test(path))
      return "Metadata API";
    return "Application API";
  }

  function mutation(item) {
    const m = item.method.toUpperCase(),
      p = endpointPath(item).toLowerCase();
    if (
      ["GET", "HEAD", "OPTIONS"].includes(m) ||
      /\/(search|search-paged|lookup-search-paged|actions)$/.test(p)
    )
      return "Read and Query";
    if (
      /\/(create|update|delete|restore|close|complete|approve|reject|trigger|sign|importcsv)(\/|$)/.test(
        p,
      )
    )
      return "Known Mutating";
    if (["POST", "PUT", "PATCH", "DELETE"].includes(m))
      return "Potentially Mutating";
    return "Metadata and Configuration";
  }

  async function openDb() {
    if (ST.db) return ST.db;
    ST.db = await new Promise((resolve, reject) => {
      const q = indexedDB.open(CFG.db, 1);
      q.onupgradeneeded = () => {
        const d = q.result;
        if (!d.objectStoreNames.contains(CFG.store))
          d.createObjectStore(CFG.store, {
            keyPath: "id",
            autoIncrement: true,
          });
      };
      q.onsuccess = () => resolve(q.result);
      q.onerror = () => reject(q.error);
    });
    return ST.db;
  }
  async function add(x) {
    try {
      const d = await openDb();
      await new Promise((r, j) => {
        const t = d.transaction(CFG.store, "readwrite");
        t.objectStore(CFG.store).add(x);
        t.oncomplete = r;
        t.onerror = () => j(t.error);
      });
      updateUi();
    } catch (e) {
      ST.errors++;
      console.error("[API Observer]", e);
    }
  }
  async function all() {
    const d = await openDb();
    return new Promise((r, j) => {
      const q = d.transaction(CFG.store).objectStore(CFG.store).getAll();
      q.onsuccess = () => r(q.result || []);
      q.onerror = () => j(q.error);
    });
  }
  async function count() {
    const d = await openDb();
    return new Promise((r, j) => {
      const q = d.transaction(CFG.store).objectStore(CFG.store).count();
      q.onsuccess = () => r(q.result);
      q.onerror = () => j(q.error);
    });
  }
  async function clear() {
    const d = await openDb();
    return new Promise((r, j) => {
      const t = d.transaction(CFG.store, "readwrite");
      t.objectStore(CFG.store).clear();
      t.oncomplete = r;
      t.onerror = () => j(t.error);
    });
  }
  function base(transport, method, url, headers, requestBody) {
    const ctx = requestContext(url);
    return {
      scriptVersion: CFG.version,
      transport,
      startedAt: iso(),
      endedAt: null,
      durationMs: null,
      pageContext: route(),
      method: (method || "GET").toUpperCase(),
      url: new URL(url, location.href).href,
      requestContext: ctx,
      normalizedPath: normalizePath(ctx.pathname),
      classification: null,
      requestHeaders: redactHeaders(headers),
      requestBody: redact(requestBody),
      requestSchema: schema(redact(parse(requestBody))),
      response: null,
      error: null,
    };
  }
  function finish(o, r) {
    o.endedAt = iso();
    o.classification = classify(o);
    if (r && "body" in r) {
      r.body = redact(r.body);
      r.schema = schema(parse(r.body));
    }
    o.response = r;
    return o;
  }

  const nativeFetch = window.fetch;
  if (nativeFetch)
    window.fetch = async function (input, init = {}) {
      const req = input instanceof Request ? input : null,
        url = req?.url || String(input);
      if (!ST.on || !shouldCapture(url))
        return nativeFetch.apply(this, arguments);
      const method = init.method || req?.method || "GET",
        hs = { ...headersObject(req?.headers), ...headersObject(init.headers) },
        b =
          "body" in init
            ? await captureBody(init.body, url)
            : req && !["GET", "HEAD"].includes(method.toUpperCase())
              ? redactBody(clip(await req.clone().text()), url)
              : null,
        o = base("fetch", method, url, hs, b),
        start = performance.now();
      try {
        const res = await nativeFetch.apply(this, arguments);
        let rb = null;
        try {
          rb = redactBody(clip(await res.clone().text()), url);
        } catch (e) {
          rb = { __captureError: String(e) };
        }
        o.durationMs = performance.now() - start;
        finish(o, {
          status: res.status,
          statusText: res.statusText,
          ok: res.ok,
          url: res.url,
          headers: redactHeaders(headersObject(res.headers)),
          body: rb,
        });
        void add(o);
        return res;
      } catch (e) {
        o.endedAt = iso();
        o.durationMs = performance.now() - start;
        o.error = { name: e.name, message: e.message };
        void add(o);
        throw e;
      }
    };
  const xo = XMLHttpRequest.prototype.open,
    xs = XMLHttpRequest.prototype.send,
    xh = XMLHttpRequest.prototype.setRequestHeader;
  XMLHttpRequest.prototype.open = function (m, u) {
    this.__apiObs = {
      method: m,
      url: new URL(String(u), location.href).href,
      headers: {},
    };
    return xo.apply(this, arguments);
  };
  XMLHttpRequest.prototype.setRequestHeader = function (k, v) {
    if (this.__apiObs)
      this.__apiObs.headers[k] = this.__apiObs.headers[k]
        ? this.__apiObs.headers[k] + ", " + v
        : String(v);
    return xh.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function (b) {
    const meta = this.__apiObs;
    if (!meta || !ST.on || !shouldCapture(meta.url))
      return xs.apply(this, arguments);
    meta.start = performance.now();
    captureBody(b, meta.url).then(
      (x) => (meta.obs = base("xhr", meta.method, meta.url, meta.headers, x)),
    );
    this.addEventListener(
      "loadend",
      async () => {
        while (!meta.obs) await sleep(0);
        let rb = null;
        try {
          rb =
            this.responseType === "" || this.responseType === "text"
              ? redactBody(clip(this.responseText), meta.url)
              : this.responseType === "json"
                ? redact(this.response)
                : await captureBody(this.response, meta.url);
        } catch (e) {
          rb = { __captureError: String(e) };
        }
        meta.obs.durationMs = performance.now() - meta.start;
        finish(meta.obs, {
          status: this.status,
          statusText: this.statusText,
          responseType: this.responseType,
          responseURL: this.responseURL,
          headers: redactHeaders(rawHeaders(this.getAllResponseHeaders())),
          body: rb,
        });
        if (!this.status)
          meta.obs.error = {
            name: "XHRNetworkError",
            message: "XHR completed with status 0 or was aborted.",
          };
        void add(meta.obs);
      },
      { once: true },
    );
    return xs.apply(this, arguments);
  };

  function groups(obs) {
    const g = new Map();
    for (const item of obs) {
      const path = endpointPath(item),
        key = `${item.method} ${path}`;
      if (!g.has(key))
        g.set(key, {
          key,
          method: item.method,
          pathTemplate: path,
          classification: classify(item),
          mutationClass: mutation(item),
          observations: [],
          requestSchemas: [],
          responseSchemas: {},
          pagePaths: new Set(),
          routes: new Set(),
          statuses: new Set(),
        });
      const x = g.get(key);
      x.observations.push(item);
      x.requestSchemas.push(item.requestSchema);
      if (item.response?.schema && item.response.status)
        (x.responseSchemas[item.response.status] ??= []).push(
          item.response.schema,
        );
      if (item.pageContext?.pathname) x.pagePaths.add(item.pageContext.pathname);
      if (item.pageContext?.hash) x.routes.add(item.pageContext.hash);
      if (item.response?.status) x.statuses.add(item.response.status);
    }
    return g;
  }
  function scoreGroup(g, maxCount) {
    const count = g.observations.length,
      frequency = maxCount ? count / maxCount : 0,
      routeDiversity = Math.min((g.routes.size + g.pagePaths.size) / 10, 1),
      success =
        g.observations.filter(
          (x) => x.response?.status >= 200 && x.response.status < 400,
        ).length / Math.max(count, 1),
      schemaRichness = Math.min(
        Object.keys(mergeSchemas(g.requestSchemas).properties || {}).length /
          20,
        1,
      );
    const score = Math.round(
      100 *
        (0.5 * frequency +
          0.2 * routeDiversity +
          0.2 * success +
          0.1 * schemaRichness),
    );
    return {
      score,
      components: {
        observationCount: count,
        frequency: Number(frequency.toFixed(3)),
        routeDiversity: Number(routeDiversity.toFixed(3)),
        successRate: Number(success.toFixed(3)),
        schemaRichness: Number(schemaRichness.toFixed(3)),
      },
    };
  }
  function discovery(obs) {
    const gs = groups(obs),
      max = Math.max(1, ...[...gs.values()].map((x) => x.observations.length));
    const endpoints = [...gs.values()]
      .map((g) => {
        const scoring = scoreGroup(g, max);
        return {
          key: g.key,
          method: g.method,
          pathTemplate: g.pathTemplate,
          classification: g.classification,
          mutationClass: g.mutationClass,
          importanceScore: scoring.score,
          scoreComponents: scoring.components,
          observationCount: g.observations.length,
          pagePathsObserved: [...g.pagePaths].sort(),
          routesObserved: [...g.routes].sort(),
          statusCodes: [...g.statuses].sort(),
          requestSchema: mergeSchemas(g.requestSchemas),
          responseSchemas: Object.fromEntries(
            Object.entries(g.responseSchemas).map(([k, v]) => [
              k,
              mergeSchemas(v),
            ]),
          ),
        };
      })
      .sort(
        (a, b) =>
          b.importanceScore - a.importanceScore || a.key.localeCompare(b.key),
      );
    return {
      metadata: {
        scriptVersion: CFG.version,
        exportedAt: iso(),
        baseOrigin: location.origin,
        observationCount: obs.length,
        uniqueEndpointCount: endpoints.length,
        sanitization:
          "usernames, email addresses, passwords, tokens, authorization, cookies, and credential fields redacted",
        scoreFormula:
          "50% relative frequency, 20% page/route diversity, 20% success rate, 10% request-schema richness",
      },
      classifications: Object.fromEntries(
        [...new Set(endpoints.map((x) => x.classification))]
          .sort()
          .map((c) => [
            c,
            endpoints.filter((x) => x.classification === c).length,
          ]),
      ),
      endpoints,
      observations: obs.map((x) => redact(x)),
    };
  }

  function pvar(item, key = "") {
    const pathVar = [...endpointPath(item).matchAll(/\{([^}]+Id)\}/g)].map(
      (x) => x[1],
    )[0];
    if (!key || key === "id") return pathVar || "recordId";
    const n = key
      .replace(/[^A-Za-z0-9]+(.)/g, (_, x) => x.toUpperCase())
      .replace(/^./, (x) => x.toLowerCase());
    return n.endsWith("Id") ? n : n + "Id";
  }
  function parameterize(v, item, key = "") {
    const uuid =
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (typeof v === "string" && uuid.test(v)) return `{{${pvar(item, key)}}}`;
    if (Array.isArray(v)) return v.map((x) => parameterize(x, item, key));
    if (!v || typeof v !== "object") return v;
    const o = {};
    Object.entries(v).forEach(([k, x]) => (o[k] = parameterize(x, item, k)));
    if (
      typeof o.name === "string" &&
      typeof v.value === "string" &&
      uuid.test(v.value)
    )
      o.value = `{{${pvar(item, o.name)}}}`;
    return o;
  }
  function postmanBody(i) {
    const b = redact(i.requestBody);
    if (b == null) return undefined;
    if (b?.__kind === "FormData")
      return {
        mode: "formdata",
        formdata: b.fields.map((f) =>
          f.kind === "file"
            ? { key: f.name, type: "file", src: [] }
            : { key: f.name, type: "text", value: String(f.value ?? "") },
        ),
      };
    const x = parse(b);
    if (x && typeof x === "object")
      return {
        mode: "raw",
        raw: JSON.stringify(parameterize(x, i), null, 2),
        options: { raw: { language: "json" } },
      };
    return {
      mode: "raw",
      raw: String(x),
      options: {
        raw: {
          language: (header(i.requestHeaders, "content-type") || "").includes(
            "json",
          )
            ? "json"
            : "text",
        },
      },
    };
  }
  function normalizedKey(key) {
    return String(key || "").replace(/[^A-Za-z0-9]/g, "");
  }

  function isContextKey(key) {
    return CONTEXT_KEY_RE.test(normalizedKey(key));
  }

  function shouldParameterize(key, value) {
    const text = String(value ?? "");
    return (
      isContextKey(key) ||
      /id$/i.test(normalizedKey(key)) ||
      GUID_RE.test(text) ||
      OBJECT_ID_RE.test(text)
    );
  }

  function parameterizedValue(key, value) {
    if (sensitiveKey(key)) return "<REDACTED>";
    return shouldParameterize(key, value)
      ? `{{${variableName(key)}}}`
      : String(value);
  }

  function safeVariableDefault(key, value) {
    if (sensitiveKey(key) || isContextKey(key)) return "";
    const text = String(value ?? "");
    return GUID_RE.test(text) || OBJECT_ID_RE.test(text) || INTEGER_RE.test(text)
      ? text
      : "";
  }

  function postmanHeaders(i) {
    const blocked = new Set([
      "host", "content-length", "cookie", "origin", "referer", "user-agent",
      "accept-encoding", "connection", "baggage", "traceparent", "tracestate",
    ]);

    return Object.entries(redactHeaders(i.requestHeaders || {}))
      .filter(([key]) =>
        !blocked.has(key.toLowerCase()) &&
        !VOLATILE_HEADER_RE.test(key) &&
        !key.toLowerCase().startsWith("sec-") &&
        !key.toLowerCase().startsWith("x-datadog"),
      )
      .map(([key, value]) => ({
        key,
        value: parameterizedValue(key, value),
        type: "text",
      }));
  }

  function postmanUrl(i) {
    const x = new URL(i.url);
    const path = endpointPath(i)
      .split("/")
      .filter(Boolean)
      .map((segment) => segment.replace(/^\{(.+)\}$/, "{{$1}}"));
    const query = [...x.searchParams].map(([key, value]) => ({
      key,
      value: parameterizedValue(key, value),
    }));
    const queryText = query.length
      ? "?" + query.map(({ key, value }) =>
          `${encodeURIComponent(key)}=${value.startsWith("{{") ? value : encodeURIComponent(value)}`,
        ).join("&")
      : "";
    return {
      raw: `{{baseUrl}}/${path.join("/")}${queryText}`,
      host: ["{{baseUrl}}"],
      path,
      query,
    };
  }

  function postmanResponses(i) {
    if (!i.response || !i.response.status || i.error) return [];
    const keep = new Set([
        "content-type",
        "location",
        "etag",
        "last-modified",
        "content-disposition",
      ]),
      hs = Object.entries(i.response.headers || {})
        .filter(([k]) => keep.has(k.toLowerCase()))
        .map(([key, value]) => ({ key, value: String(value) }));
    let b =
      typeof i.response.body === "string"
        ? i.response.body
        : i.response.body == null
          ? ""
          : JSON.stringify(redact(i.response.body), null, 2);
    if (b.length > CFG.postmanMaxResponse)
      b = JSON.stringify(
        {
          _captureNote:
            "Response omitted because it exceeded the Postman example limit.",
          _capturedCharacterCount: b.length,
          _contentType: header(i.response.headers, "content-type"),
        },
        null,
        2,
      );
    return [
      {
        name: `${i.response.status} ${i.response.statusText || ""}`.trim(),
        originalRequest: {
          method: i.method,
          header: postmanHeaders(i),
          body: postmanBody(i),
          url: postmanUrl(i),
        },
        status: i.response.statusText || "",
        code: i.response.status,
        header: hs,
        cookie: [],
        body: b,
      },
    ];
  }
  function postman(obs) {
    const gs = groups(obs),
      max = Math.max(1, ...[...gs.values()].map((x) => x.observations.length)),
      folders = new Map();
    for (const g of gs.values()) {
      const variants = [],
        seen = new Set();
      for (const i of g.observations) {
        const sig = stable(schema(parse(i.requestBody)));
        if (!seen.has(sig)) {
          seen.add(sig);
          variants.push(i);
        }
        if (variants.length >= CFG.maxVariants) break;
      }
      for (const [n, i] of variants.entries()) {
        const classification = g.classification;
        if (!folders.has(classification))
          folders.set(classification, new Map());
        const segments = endpointPath(i).split("/").filter(Boolean);
        const area = segments.find((segment) => !segment.startsWith("{")) || "Root";
        if (!folders.get(classification).has(area))
          folders.get(classification).set(area, []);
        const sc = scoreGroup(g, max),
          warn = g.mutationClass.includes("Mutating")
            ? "WARNING: This request may change production data. Review it before sending."
            : "";
        folders
          .get(classification)
          .get(area)
          .push({
            name: g.key + (variants.length > 1 ? ` - Variant ${n + 1}` : ""),
            request: {
              method: i.method,
              header: postmanHeaders(i),
              body: postmanBody(i),
              url: postmanUrl(i),
              description: [
                warn,
                `Classification: ${classification}`,
                `Mutation class: ${g.mutationClass}`,
                `Importance score: ${sc.score}/100`,
                `Observations: ${g.observations.length}`,
              ]
                .filter(Boolean)
                .join("\n\n"),
            },
            response: postmanResponses(i),
          });
      }
    }
    const variableDefaults = new Map([["baseUrl", location.origin]]);
    obs.forEach((i) => {
      const originalUrl = new URL(i.url);
      const originalSegments = originalUrl.pathname.split("/").filter(Boolean);
      const templateSegments = endpointPath(i).split("/").filter(Boolean);
      templateSegments.forEach((segment, index) => {
        const match = segment.match(/^\{(.+)\}$/);
        if (!match) return;
        const key = match[1];
        if (!variableDefaults.has(key))
          variableDefaults.set(
            key,
            safeVariableDefault(key, originalSegments[index]),
          );
      });

      for (const [key, value] of originalUrl.searchParams) {
        if (!shouldParameterize(key, value)) continue;
        const name = variableName(key);
        if (!variableDefaults.has(name))
          variableDefaults.set(name, safeVariableDefault(key, value));
      }

      for (const [key, value] of Object.entries(i.requestHeaders || {})) {
        if (VOLATILE_HEADER_RE.test(key)) continue;
        if (!shouldParameterize(key, value)) continue;
        const name = variableName(key);
        if (!variableDefaults.has(name))
          variableDefaults.set(name, safeVariableDefault(key, value));
      }

      const body = postmanBody(i);
      const bodyText =
        typeof body === "string"
          ? body
          : body
            ? JSON.stringify(body)
            : "";

      if (bodyText) {
        for (const match of bodyText.matchAll(/\{\{([^}]+)\}\}/g)) {
          if (!variableDefaults.has(match[1])) {
            variableDefaults.set(match[1], "");
          }
        }
      }
    });
    return {
      info: {
        _postman_id: crypto.randomUUID(),
        name: "Observed API",
        description:
          "Classified and scored from authorized browser activity. Credential fields are redacted.",
        schema:
          "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
      },
      variable: [...variableDefaults]
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, value]) => ({ key, value, type: "string" })),
      item: [...folders]
        .sort()
        .map(([name, areas]) => ({
          name,
          item: [...areas].sort().map(([name, item]) => ({ name, item })),
        })),
    };
  }

  const openapiPath = (p) => p;
  const opId = (m, p) =>
    (
      m.toLowerCase() +
      "_" +
      p.replace(/[{}]/g, "").replace(/[^a-zA-Z0-9]+/g, "_")
    )
      .replace(/_+/g, "_")
      .replace(/^_|_$/g, "");
  function openapi(obs) {
    const gs = groups(obs),
      max = Math.max(1, ...[...gs.values()].map((x) => x.observations.length)),
      paths = {};
    for (const g of gs.values()) {
      const p = openapiPath(g.pathTemplate);
      paths[p] ??= {};
      const representative =
          g.observations.find((x) => x.response?.status) || g.observations[0],
        parameters = [];
      for (const m of p.matchAll(/\{([^}]+)\}/g))
        parameters.push({
          name: m[1],
          in: "path",
          required: true,
          schema: { type: "string" },
        });
      const u = new URL(representative.url);
      for (const [name, value] of u.searchParams)
        if (!parameters.some((x) => x.in === "query" && x.name === name))
          parameters.push({
            name,
            in: "query",
            required: false,
            schema: { type: "string" },
            example: sensitiveKey(name) ? "<REDACTED>" : value,
          });
      const rs = mergeSchemas(g.requestSchemas),
        responses = {};
      for (const [status, schemas] of Object.entries(g.responseSchemas))
        responses[status] = {
          description: `Observed HTTP ${status} response`,
          content: { "application/json": { schema: mergeSchemas(schemas) } },
        };
      if (!Object.keys(responses).length)
        responses.default = { description: "No HTTP response was captured" };
      const sc = scoreGroup(g, max);
      const operation = {
        operationId: opId(g.method, p),
        summary: `${g.method} ${p}`,
        tags: [g.classification],
        description: `Observed ${g.observations.length} time(s). Importance score: ${sc.score}/100. Mutation class: ${g.mutationClass}.`,
        parameters,
        responses,
        "x-observation-count": g.observations.length,
        "x-importance-score": sc.score,
        "x-score-components": sc.components,
        "x-mutation-class": g.mutationClass,
        "x-page-paths-observed": [...g.pagePaths].sort(),
        "x-routes-observed": [...g.routes].sort(),
      };
      if (!["GET", "HEAD"].includes(g.method) && rs && Object.keys(rs).length)
        operation.requestBody = {
          required: false,
          content: {
            "application/json": {
              schema: rs,
              example: parse(redact(representative.requestBody)),
            },
          },
        };
      paths[p][g.method.toLowerCase()] = operation;
    }
    return {
      openapi: "3.1.0",
      info: {
        title: "Observed API",
        version: CFG.version,
        description:
          "Generated from observed authorized browser traffic. This is an empirical API catalog, not vendor-supplied documentation. Credential fields are redacted.",
      },
      servers: [{ url: location.origin }],
      tags: [...new Set([...gs.values()].map((g) => g.classification))]
        .sort()
        .map((name) => ({ name })),
      paths,
      components: {
        schemas: {},
        securitySchemes: {
          browserSession: {
            type: "apiKey",
            in: "cookie",
            name: "browser-session",
            description:
              "Placeholder only. Configure an approved authentication method; credentials are not exported.",
          },
        },
      },
    };
  }

  function download(name, data) {
    const u = URL.createObjectURL(
        new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }),
      ),
      a = document.createElement("a");
    a.href = u;
    a.download = name;
    document.documentElement.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(u), 30000);
  }
  const stamp = () => iso().replace(/[:.]/g, "-");
  const button = (text, fn, danger = false) => {
    const b = document.createElement("button");
    b.textContent = text;
    b.style.cssText = `border:1px solid #475569;border-radius:6px;padding:6px 8px;background:${danger ? "#7f1d1d" : "#1e293b"};color:white;cursor:pointer`;
    b.onclick = async (e) => {
      e.stopPropagation();
      b.disabled = true;
      try {
        await fn();
        await updateUi();
      } catch (x) {
        ST.errors++;
        console.error(x);
        alert(x.message || x);
      } finally {
        b.disabled = false;
      }
    };
    return b;
  };
  async function updateUi() {
    if (!ST.ui) return;
    ST.ui.status.textContent = ST.on ? "CAPTURING" : "PAUSED";
    ST.ui.status.style.color = ST.on ? "#4ade80" : "#fbbf24";
    ST.ui.count.textContent = `${await count().catch(() => 0)} stored | ${ST.errors} errors`;
    ST.ui.toggle.textContent = ST.on ? "Pause" : "Start";
  }
  function installPanel() {
    if (document.getElementById("api-observer-panel")) return;
    const p = document.createElement("div");
    p.id = "api-observer-panel";
    p.style.cssText =
      "position:fixed;right:12px;bottom:12px;z-index:2147483647;width:300px;background:#0f172af5;color:#e2e8f0;border:1px solid #475569;border-radius:10px;padding:10px;font:12px system-ui";
    const title = document.createElement("b");
    title.textContent = `API Observer v${CFG.version}`;
    const line = document.createElement("div"),
      status = document.createElement("strong"),
      countEl = document.createElement("span");
    countEl.style.float = "right";
    line.append(status, countEl);
    const note = document.createElement("div");
    note.textContent =
      "Credentials are redacted. Other restricted payload data is retained.";
    note.style = "color:#fca5a5;margin:7px 0";
    const row = document.createElement("div");
    row.style = "display:flex;flex-wrap:wrap;gap:5px";
    const toggle = button("", async () => {
      ST.on = !ST.on;
      sessionStorage.setItem("ObserverEnabled", String(ST.on));
    });
    row.append(
      toggle,
      button("Discovery JSON", async () => {
        const x = await all();
        download(`api-discovery_${stamp()}.json`, discovery(x));
      }),
      button("Postman", async () => {
        const x = await all();
        download(
          `observed-api_${stamp()}.postman_collection.json`,
          postman(x),
        );
      }),
      button("OpenAPI", async () => {
        const x = await all();
        download(`observed-api_${stamp()}.openapi.json`, openapi(x));
      }),
      button(
        "Clear",
        async () => {
          if (confirm("Delete all stored observations?")) await clear();
        },
        true,
      ),
    );
    p.append(title, line, note, row);
    document.documentElement.append(p);
    ST.ui = { status, count: countEl, toggle };
    updateUi();

    /* -----------------------------
       Draggable panel support
    ----------------------------- */

    let dragging = false;
    let dragOffsetX = 0;
    let dragOffsetY = 0;

    title.style.cursor = 'move';

    title.addEventListener('mousedown', (e) => {
        dragging = true;

        const rect = p.getBoundingClientRect();

        dragOffsetX = e.clientX - rect.left;
        dragOffsetY = e.clientY - rect.top;

        p.style.left = rect.left + 'px';
        p.style.top = rect.top + 'px';

        p.style.right = 'auto';
        p.style.bottom = 'auto';

        e.preventDefault();
    });

    document.addEventListener('mousemove', (e) => {
        if (!dragging) return;

        const left = e.clientX - dragOffsetX;
        const top = e.clientY - dragOffsetY;

        p.style.left = Math.max(0, left) + 'px';
        p.style.top = Math.max(0, top) + 'px';
    });

    document.addEventListener('mouseup', () => {
        dragging = false;
    });
  }
  openDb().catch((e) => {
    ST.errors++;
    console.error(e);
  });
  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", installPanel, { once: true });
  else installPanel();
  console.info(
    "[API Observer] v1.3.2 installed; credential redaction, classification, scoring, and OpenAPI enabled.",
  );
})();
