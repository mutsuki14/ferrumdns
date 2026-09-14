// Local DOM behavior tests only. jsdom does not validate real browser layout.
// External resources are disabled and every API call is served by the fixture.
import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { JSDOM, VirtualConsole } from "jsdom";

const html = await readFile(
  new URL("../web/index.html", import.meta.url),
  "utf8",
);
const script = await readFile(
  new URL("../web/app.js", import.meta.url),
  "utf8",
);

const makeFixture = () => ({
  stats: {
    queries: 100,
    responses: 99,
    cache_hits: 75,
    cache_misses: 25,
    cache_lazy_hits: 3,
    upstream_ok: 24,
    upstream_err: 1,
    dropped: 1,
    avg_latency_us: 1250,
    uptime_secs: 120,
  },
  plugins: {
    executables: ["main", "local_hosts", "cache_local", "forward"],
    domain_sets: ["ads"],
    ip_sets: ["private"],
    caches: [{ tag: "cache_local", size: 12 }],
    entry: "main",
  },
  system: {
    version: "0.2.1",
    runtime_id: "runtime-one",
    entry: "main",
    listeners: [
      {
        protocol: "udp",
        addr: "127.0.0.1:5353",
        entry: "main",
        timeout_secs: 5,
        tls: false,
      },
    ],
    plugins: [
      { tag: "main", type: "sequence" },
      { tag: "local_hosts", type: "hosts" },
      { tag: "cache_local", type: "cache" },
      { tag: "forward", type: "forward" },
      { tag: "ads", type: "domain_set" },
      { tag: "private", type: "ip_set" },
    ],
    upstreams: [{ plugin: "forward", tag: null, addr: "udp://1.1.1.1:53" }],
  },
  result: {
    rcode: "No Error",
    answers: ["router.lan. 60 A(192.0.2.1)"],
    records: [{ name: "router.lan.", ttl: 60, type: "A", data: "192.0.2.1" }],
    elapsed_us: 2100,
    cache_hit: false,
    ecs: "203.0.113.0/24",
    trace: [
      {
        plugin: "local_hosts",
        event: "answer",
        detail: "1 record",
        elapsed_us: 1050,
      },
    ],
  },
});

async function settle() {
  for (let step = 0; step < 12; step += 1) await Promise.resolve();
  await new Promise((resolve) => setImmediate(resolve));
}

async function setup(t, options = {}) {
  const errors = [];
  const virtualConsole = new VirtualConsole();
  virtualConsole.on("jsdomError", (error) => errors.push(error));
  const dom = new JSDOM(html, {
    url: "https://console.test/",
    runScripts: "outside-only",
    pretendToBeVisual: true,
    virtualConsole,
  });
  const { window } = dom;
  const document = window.document;
  const fixture = options.fixture || makeFixture();
  const calls = [];
  const timers = new Map();
  let timerId = 0;
  let offline = false;
  let hidden = false;
  let now = 1_700_000_000_000;
  let handler = null;
  let mobile = Boolean(options.mobile);
  const mediaListeners = new Set();
  const media = {
    media: "(max-width: 720px)",
    get matches() {
      return mobile;
    },
    addEventListener(name, callback) {
      if (name === "change") mediaListeners.add(callback);
    },
    removeEventListener(name, callback) {
      if (name === "change") mediaListeners.delete(callback);
    },
  };
  window.matchMedia = (query) => {
    assert.equal(query, media.media);
    return media;
  };
  Object.defineProperty(document, "hidden", {
    configurable: true,
    get: () => hidden,
  });
  window.Date.now = () => now;
  window.setTimeout = (callback, delay) => {
    const id = ++timerId;
    timers.set(id, { callback, delay });
    return id;
  };
  window.clearTimeout = (id) => timers.delete(id);

  // Only supplement dialog methods that jsdom does not implement.
  const dialogPrototype = window.HTMLDialogElement.prototype;
  if (!dialogPrototype.showModal)
    dialogPrototype.showModal = function () {
      this.open = true;
    };
  if (!dialogPrototype.close)
    dialogPrototype.close = function () {
      this.open = false;
      this.dispatchEvent(new window.Event("close"));
    };

  const response = (data, status = 200) => ({
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get: (name) =>
        name.toLowerCase() === "content-type" ? "application/json" : null,
    },
    json: async () => structuredClone(data),
    text: async () => (typeof data === "string" ? data : JSON.stringify(data)),
  });
  window.fetch = async (path, request = {}) => {
    assert.match(
      path,
      /^\/api\//,
      "all requests must be local API paths handled by the fixture",
    );
    const call = { path, ...request };
    calls.push(call);
    if (offline) throw new TypeError("fixture connection unavailable");
    if (handler) {
      const custom = handler(call);
      if (custom !== undefined) return custom;
    }
    if (path === "/api/stats") return response(fixture.stats);
    if (path === "/api/plugins") return response(fixture.plugins);
    if (path === "/api/system") return response(fixture.system);
    if (path === "/api/query") return response(fixture.result);
    if (path === "/api/cache/flush") {
      const body = JSON.parse(request.body);
      const flushed = [];
      for (const cache of fixture.plugins.caches) {
        if (!body.tag || body.tag === cache.tag) {
          cache.size = 0;
          flushed.push(cache.tag);
        }
      }
      return response({ ok: true, flushed });
    }
    throw new Error(`Unexpected fixture API: ${path}`);
  };
  t.after(() => {
    dom.window.close();
    assert.deepEqual(
      errors.map((error) => error.message),
      [],
      "no unhandled DOM script errors",
    );
  });
  window.eval(script);
  await settle();
  const $ = (id) => document.getElementById(id);
  return {
    window,
    document,
    $,
    fixture,
    calls,
    timers,
    response,
    setHandler(value) {
      handler = value;
    },
    setOffline(value) {
      offline = value;
    },
    advance(ms) {
      now += ms;
    },
    setHidden(value) {
      hidden = value;
      document.dispatchEvent(new window.Event("visibilitychange"));
    },
    setMobile(value) {
      mobile = value;
      for (const callback of mediaListeners)
        callback({ matches: value, media: media.media });
    },
    async refresh() {
      $("refresh-button").click();
      await settle();
    },
    async submit() {
      $("query-form").dispatchEvent(
        new window.Event("submit", { bubbles: true, cancelable: true }),
      );
      await settle();
    },
  };
}

test("initial snapshots render and all five hash navigation pages are reachable", async (t) => {
  const { $, calls, document, window } = await setup(t);
  assert.equal(calls.length, 3);
  assert.equal($("stat-queries").textContent, "100");
  assert.equal($("stat-cache-rate").textContent, "75.0%");
  assert.equal($("stat-latency").textContent, "1.25 ms");
  assert.equal($("stat-qps").textContent, "—");
  assert.equal($("chart-empty").hidden, false);
  assert.equal($("overview-cache-count").textContent, "1");
  assert.equal($("cache-total").textContent, "12");
  assert.equal($("version-label").textContent, "v0.2.1");
  assert.match($("overview-listeners").textContent, /127\.0\.0\.1:5353/);
  assert.match($("settings-upstreams").textContent, /udp:\/\/1\.1\.1\.1:53/);
  for (const page of ["query", "plugins", "cache", "settings", "overview"]) {
    document.querySelector(`.nav-link[data-nav="${page}"]`).click();
    assert.equal(window.location.hash, `#${page}`);
    assert.equal(
      document.querySelectorAll("[data-page]:not([hidden])").length,
      1,
    );
    assert.equal(
      document.querySelector("[data-page]:not([hidden])").dataset.page,
      page,
    );
    assert.equal(
      document.querySelector('.nav-link[aria-current="page"]').dataset.nav,
      page,
    );
  }
  await settle();
});

test("query form posts advanced parameters and renders records, trace, raw JSON and history", async (t) => {
  const app = await setup(t);
  const { $, calls, document, window } = app;
  $("query-name").value = " router.lan ";
  $("query-type").value = "AAAA";
  $("query-entry").value = "main";
  $("query-client-ip").value = "2001:db8::1";
  $("query-ecs").value = "203.0.113.0/24";
  await app.submit();
  const request = calls.find((call) => call.path === "/api/query");
  assert.equal(request.method, "POST");
  assert.equal(request.headers["Content-Type"], "application/json");
  assert.deepEqual(JSON.parse(request.body), {
    name: "router.lan",
    qtype: "AAAA",
    entry: "main",
    client_ip: "2001:db8::1",
    ecs: "203.0.113.0/24",
  });
  assert.equal($("query-result").hidden, false);
  assert.equal($("query-error").hidden, true);
  assert.equal($("result-rcode").textContent, "No Error");
  assert.equal($("result-rcode").dataset.tone, "success");
  assert.equal($("result-time").textContent, "2.10 ms");
  assert.equal($("query-records").rows.length, 1);
  assert.match($("query-records").textContent, /router\.lan\./);
  assert.match($("query-records").textContent, /192\.0\.2\.1/);
  assert.match($("query-trace").textContent, /local_hosts.*answer.*1\.05 ms/s);
  assert.equal(JSON.parse($("query-raw").textContent).rcode, "No Error");
  assert.equal($("query-history").children.length, 1);
  $("query-name").value = "changed.example";
  $("query-type").value = "A";
  document.querySelector('[data-history="0"]').click();
  assert.equal($("query-name").value, "router.lan");
  assert.equal($("query-type").value, "AAAA");
  assert.equal($("query-ecs").value, "203.0.113.0/24");
  assert.equal(window.localStorage.length, 0);
  assert.equal(window.sessionStorage.length, 0);

  $("query-client-ip").value = "invalid-ip";
  document.querySelector(".advanced-options").open = false;
  const before = calls.filter((call) => call.path === "/api/query").length;
  await app.submit();
  assert.equal(
    calls.filter((call) => call.path === "/api/query").length,
    before,
  );
  assert.equal($("query-error").hidden, false);
  assert.match($("query-error").textContent, /有效的 IPv4 或 IPv6/);
  assert.equal(document.querySelector(".advanced-options").open, true);
  assert.equal(document.activeElement, $("query-client-ip"));
});

test("plugin search and type filter intersect, and executable buttons select the query entry", async (t) => {
  const { $, document, window } = await setup(t);
  assert.equal($("plugin-list").rows.length, 6);
  $("plugin-search").value = "local";
  $("plugin-search").dispatchEvent(new window.Event("input"));
  assert.equal($("plugin-list").rows.length, 2);
  $("plugin-filter").value = "cache";
  $("plugin-filter").dispatchEvent(new window.Event("change"));
  assert.equal($("plugin-list").rows.length, 1);
  assert.match($("plugin-list").textContent, /cache_local/);
  $("plugin-search").value = "absent";
  $("plugin-search").dispatchEvent(new window.Event("input"));
  assert.equal($("plugin-list").rows.length, 0);
  assert.equal($("plugin-empty").hidden, false);
  $("plugin-search").value = "";
  $("plugin-filter").value = "all";
  $("plugin-filter").dispatchEvent(new window.Event("change"));
  document.querySelector('[data-entry="local_hosts"]').click();
  assert.equal(window.location.hash, "#query");
  assert.equal($("query-entry").value, "local_hosts");
  assert.equal(document.activeElement, $("query-name"));
  await settle();
});

test("cache cancel sends no mutation; confirmation sends the selected tag and refreshes totals", async (t) => {
  const app = await setup(t);
  const { $, calls, document, fixture } = app;
  fixture.plugins.caches.push({ tag: "cache_other", size: 7 });
  await app.refresh();
  const mutations = () =>
    calls.filter((call) => call.path === "/api/cache/flush");
  const first = document.querySelector('[data-flush="cache_local"]');
  first.click();
  assert.equal($("confirm-dialog").open, true);
  assert.match($("confirm-description").textContent, /cache_local/);
  assert.equal(document.activeElement, $("confirm-cancel"));
  $("confirm-cancel").click();
  await settle();
  assert.equal(mutations().length, 0);
  assert.equal($("confirm-dialog").open, false);
  assert.equal(document.activeElement, first);

  first.click();
  const readsBefore = calls.filter(
    (call) => call.path === "/api/plugins",
  ).length;
  $("confirm-submit").click();
  await settle();
  assert.equal(mutations().length, 1);
  assert.deepEqual(JSON.parse(mutations()[0].body), { tag: "cache_local" });
  assert.equal(
    fixture.plugins.caches.find((cache) => cache.tag === "cache_other").size,
    7,
  );
  assert.equal($("cache-total").textContent, "7");
  assert.ok(
    calls.filter((call) => call.path === "/api/plugins").length > readsBefore,
  );
  assert.equal($("confirm-dialog").open, false);
  assert.match($("toast").textContent, /已清理缓存/);

  $("flush-all").click();
  $("confirm-submit").click();
  await settle();
  assert.deepEqual(JSON.parse(mutations()[1].body), {});
  assert.equal($("cache-total").textContent, "0");
});

test("offline refresh retains visible data; reconnect clears the error and resets QPS history", async (t) => {
  const app = await setup(t);
  const { $, fixture } = app;
  fixture.stats.queries = 106;
  app.advance(3000);
  await app.refresh();
  fixture.stats.queries = 112;
  app.advance(3000);
  await app.refresh();
  assert.equal($("stat-qps").textContent, "2.0");
  assert.equal($("chart-empty").hidden, true);
  const previousTime = $("last-updated").textContent.replace("更新于 ", "");
  app.setOffline(true);
  app.advance(3000);
  await app.refresh();
  assert.equal($("stat-queries").textContent, "112");
  assert.equal($("cache-total").textContent, "12");
  assert.equal($("global-error").hidden, false);
  assert.match($("global-error").textContent, /保留上次成功同步的数据/);
  assert.match($("global-error").textContent, /fixture connection unavailable/);
  assert.ok($("last-updated").textContent.includes(previousTime));
  assert.equal($("connection-status").dataset.state, "offline");
  app.setOffline(false);
  fixture.stats.queries = 900;
  app.advance(3000);
  await app.refresh();
  assert.equal($("global-error").hidden, true);
  assert.equal($("connection-status").dataset.state, "online");
  assert.equal($("stat-queries").textContent, "900");
  assert.equal($("stat-qps").textContent, "—");
  assert.equal($("chart-empty").hidden, false);
});

test("refresh never overlaps, and hidden-page aborts do not report a false connection error", async (t) => {
  const app = await setup(t);
  const { $, calls, timers, window } = app;
  app.setHandler((call) => {
    if (call.path !== "/api/stats") return undefined;
    return new Promise((resolve, reject) => {
      call.signal.addEventListener(
        "abort",
        () => reject(new window.DOMException("Aborted", "AbortError")),
        { once: true },
      );
    });
  });
  const before = calls.length;
  $("refresh-button").click();
  $("auto-refresh").dispatchEvent(new window.Event("change"));
  assert.equal(calls.length - before, 3);
  assert.equal($("refresh-button").disabled, true);
  app.setHidden(true);
  await settle();
  assert.equal($("refresh-button").disabled, false);
  assert.equal($("global-error").hidden, true);
  assert.equal($("connection-status").dataset.state, "online");
  assert.equal(
    [...timers.values()].filter((timer) => timer.delay === 3000).length,
    0,
  );
  app.setHandler(null);
  app.setHidden(false);
  await settle();
  assert.equal(calls.length - before, 6);
  $("auto-refresh").checked = false;
  $("auto-refresh").dispatchEvent(new window.Event("change"));
  assert.equal(
    [...timers.values()].filter((timer) => timer.delay === 3000).length,
    0,
  );
});

test("server supplied markup is rendered as text in plugins, records, trace and errors", async (t) => {
  const fixture = makeFixture();
  const hostile = '<img src=x onerror="window.injected=true">';
  fixture.system.plugins.push({ tag: hostile, type: "hosts" });
  fixture.plugins.executables.push(hostile);
  fixture.result.records[0].data = hostile;
  fixture.result.trace[0].detail = hostile;
  const app = await setup(t, { fixture });
  const { $, document, window } = app;
  assert.ok($("plugin-list").textContent.includes(hostile));
  assert.equal($("plugin-list").querySelector("img"), null);
  $("query-name").value = "router.lan";
  await app.submit();
  assert.ok($("query-records").textContent.includes(hostile));
  assert.ok($("query-trace").textContent.includes(hostile));
  assert.equal($("query-result").querySelector("img"), null);
  app.setHandler((call) =>
    call.path === "/api/stats" ? app.response(hostile, 502) : undefined,
  );
  await app.refresh();
  assert.ok($("global-error").textContent.includes(hostile));
  assert.equal($("global-error").querySelector("img"), null);
  assert.equal(window.injected, undefined);
  assert.equal(document.querySelectorAll("script").length, 1);
});

test("mobile navigation uses inert while hidden, restores focus, and responds to viewport changes", async (t) => {
  const { $, document, window, setMobile } = await setup(t, { mobile: true });
  assert.equal($("sidebar").hasAttribute("inert"), true);
  $("mobile-menu").click();
  assert.equal($("sidebar").classList.contains("open"), true);
  assert.equal($("sidebar").hasAttribute("inert"), false);
  assert.equal($("mobile-menu").getAttribute("aria-expanded"), "true");
  assert.equal(document.activeElement, $("sidebar-close"));
  $("sidebar-close").click();
  assert.equal($("sidebar").hasAttribute("inert"), true);
  assert.equal(document.activeElement, $("mobile-menu"));
  setMobile(false);
  assert.equal($("sidebar").hasAttribute("inert"), false);
  const link = document.querySelector('.nav-link[data-nav="query"]');
  link.focus();
  setMobile(true);
  assert.equal($("sidebar").hasAttribute("inert"), true);
  assert.equal(document.activeElement, $("mobile-menu"));
  $("mobile-menu").click();
  document.dispatchEvent(
    new window.KeyboardEvent("keydown", { key: "Escape", bubbles: true }),
  );
  assert.equal($("sidebar").hasAttribute("inert"), true);
  assert.equal($("mobile-menu").getAttribute("aria-expanded"), "false");
});
