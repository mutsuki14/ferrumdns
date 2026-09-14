/* FerrumDNS console. No dependencies, no browser-persistent query history. */
(() => {
  "use strict";

  const REFRESH_MS = 3000;
  const HISTORY_MS = 15 * 60 * 1000;
  const formatNumber = (value) =>
    Number.isFinite(Number(value))
      ? Number(value).toLocaleString("zh-CN")
      : "—";
  const latencyMs = (value) =>
    Number.isFinite(Number(value))
      ? `${(Number(value) / 1000).toFixed(2)} ms`
      : "—";
  const isSuccessfulResponse = (rcode) =>
    /^no[\s_-]*error$/i.test(String(rcode));
  const cacheRate = (stats) => {
    const hits = Number(stats.cache_hits) || 0;
    const misses = Number(stats.cache_misses) || 0;
    return hits + misses > 0 ? hits / (hits + misses) : null;
  };

  function sampleTrend(previous, stats, at, runtimeId, reconnected = false) {
    const current = {
      queries: Number(stats.queries),
      uptime: Number(stats.uptime_secs),
      at,
    };
    const old = previous && previous.current;
    const reset =
      !old ||
      reconnected ||
      previous.runtimeId !== runtimeId ||
      current.queries < old.queries ||
      current.uptime < old.uptime;
    const elapsed = old ? (at - old.at) / 1000 : 0;
    const qps =
      !reset &&
      elapsed > 0 &&
      Number.isFinite(current.queries) &&
      Number.isFinite(old.queries)
        ? (current.queries - old.queries) / elapsed
        : null;
    const points = reset
      ? []
      : previous.points.filter((point) => point.at >= at - HISTORY_MS);
    if (qps !== null) points.push({ at, qps });
    return { current, runtimeId, qps, points };
  }

  function isIPv4(value) {
    const parts = value.split(".");
    return (
      parts.length === 4 &&
      parts.every(
        (part) => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255,
      )
    );
  }

  function ipVersion(value) {
    if (isIPv4(value)) return 4;
    if (!value.includes(":") || /[^a-fA-F0-9:.]/.test(value)) return 0;
    let normalized = value;
    if (value.includes(".")) {
      const lastColon = value.lastIndexOf(":");
      if (!isIPv4(value.slice(lastColon + 1))) return 0;
      normalized = `${value.slice(0, lastColon + 1)}0:0`;
    }
    if (normalized.includes(":::") || normalized.split("::").length > 2)
      return 0;
    const compressed = normalized.includes("::");
    const groups = normalized.split(":").filter(Boolean);
    if (!groups.every((group) => /^[a-fA-F0-9]{1,4}$/.test(group))) return 0;
    if (compressed) return groups.length < 8 ? 6 : 0;
    return groups.length === 8 &&
      !normalized.startsWith(":") &&
      !normalized.endsWith(":")
      ? 6
      : 0;
  }

  function validateQuery(values) {
    const name = String(values.name || "").trim();
    const plain = name.endsWith(".") ? name.slice(0, -1) : name;
    if (!name) return { field: "query-name", message: "请输入要查询的域名。" };
    if (
      name !== "." &&
      (plain.length > 253 ||
        !/^[a-zA-Z0-9_.*-]+$/.test(plain) ||
        plain.split(".").some((label) => !label || label.length > 63))
    ) {
      return {
        field: "query-name",
        message:
          "请输入有效域名，不含协议、端口或空格；国际化域名请使用 Punycode。",
      };
    }
    const clientIp = String(values.client_ip || "").trim();
    if (clientIp && !ipVersion(clientIp))
      return {
        field: "query-client-ip",
        message: "客户端 IP 必须是有效的 IPv4 或 IPv6 地址。",
      };
    const ecs = String(values.ecs || "").trim();
    if (ecs) {
      const parts = ecs.split("/");
      const version = ipVersion(parts[0]);
      if (
        parts.length !== 2 ||
        !version ||
        !/^\d{1,3}$/.test(parts[1]) ||
        Number(parts[1]) > (version === 4 ? 32 : 128)
      ) {
        return {
          field: "query-ecs",
          message: "ECS 请填写有效网段，例如 203.0.113.0/24 或 2001:db8::/48。",
        };
      }
    }
    const payload = { name, qtype: String(values.qtype || "A").toUpperCase() };
    const entry = String(values.entry || "").trim();
    if (entry) payload.entry = entry;
    if (clientIp) payload.client_ip = clientIp;
    if (ecs) payload.ecs = ecs;
    return { payload };
  }

  function pluginRows(system, plugins) {
    const executables = new Set(plugins.executables || []);
    const types = new Map(
      (system.plugins || []).map((plugin) => [plugin.tag, plugin.type]),
    );
    for (const tag of plugins.domain_sets || [])
      if (!types.has(tag)) types.set(tag, "domain_set");
    for (const tag of plugins.ip_sets || [])
      if (!types.has(tag)) types.set(tag, "ip_set");
    for (const cache of plugins.caches || [])
      if (!types.has(cache.tag)) types.set(cache.tag, "cache");
    for (const tag of executables)
      if (!types.has(tag)) types.set(tag, "executable");
    return [...types]
      .map(([tag, type]) => ({
        tag,
        type,
        executable: executables.has(tag),
        entry: tag === plugins.entry,
      }))
      .sort(
        (a, b) =>
          Number(b.entry) - Number(a.entry) || a.tag.localeCompare(b.tag),
      );
  }

  if (typeof document === "undefined") {
    if (typeof module !== "undefined")
      module.exports = {
        cacheRate,
        sampleTrend,
        ipVersion,
        validateQuery,
        pluginRows,
        isSuccessfulResponse,
      };
    return;
  }

  const $ = (id) => document.getElementById(id);
  const setText = (id, value) => {
    const target = $(id);
    if (target) target.textContent = value ?? "—";
  };
  const show = (id, visible) => {
    const target = $(id);
    if (target) target.hidden = !visible;
  };
  const element = (tag, className, value) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (value !== undefined) node.textContent = String(value);
    return node;
  };
  const clear = (target) => target.replaceChildren();
  const badge = (value, tone = "muted") =>
    element("span", `badge badge-${tone}`, value);
  const state = {
    stats: null,
    plugins: null,
    system: null,
    trend: null,
    online: null,
    lastUpdated: null,
    refreshController: null,
    refreshPromise: null,
    refreshTimer: null,
    queryController: null,
    queryResult: null,
    history: [],
    flushTag: undefined,
    flushing: false,
    dialogTrigger: null,
    toastTimer: null,
  };
  const pages = {
    overview: ["运行概览", "实时掌握 DNS 服务的运行状态"],
    query: ["DNS 查询", "调试解析结果，追踪每一步处理流程"],
    plugins: ["插件管理", "查看已加载的插件与执行入口"],
    cache: ["缓存管理", "查看缓存使用情况，按需清理解析记录"],
    settings: ["系统配置", "查看当前运行配置与服务信息"],
  };
  const mobileViewport = window.matchMedia("(max-width: 720px)");

  function syncSidebarInert() {
    const sidebar = $("sidebar");
    const hidden =
      mobileViewport.matches && !sidebar.classList.contains("open");
    sidebar.toggleAttribute("inert", hidden);
    if (hidden && sidebar.contains(document.activeElement))
      $("mobile-menu").focus();
  }

  function notify(message, error = false) {
    const toast = $("toast");
    clearTimeout(state.toastTimer);
    toast.textContent = message;
    toast.dataset.tone = error ? "error" : "success";
    toast.hidden = false;
    state.toastTimer = setTimeout(() => {
      toast.hidden = true;
    }, 4500);
  }

  function closeSidebar() {
    $("sidebar").classList.remove("open");
    document.body.classList.remove("sidebar-open");
    $("mobile-menu").setAttribute("aria-expanded", "false");
    syncSidebarInert();
  }

  function navigate() {
    const requested = location.hash.slice(1);
    const page = Object.hasOwn(pages, requested) ? requested : "overview";
    if (requested && requested !== page)
      history.replaceState(null, "", "#overview");
    document.querySelectorAll("[data-page]").forEach((pane) => {
      pane.hidden = pane.dataset.page !== page;
    });
    document.querySelectorAll(".nav-link[data-nav]").forEach((link) => {
      const active = link.dataset.nav === page;
      link.classList.toggle("active", active);
      if (active) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    });
    setText("page-title", pages[page][0]);
    setText("page-description", pages[page][1]);
    document.title = `${pages[page][0]} · FerrumDNS`;
    closeSidebar();
  }

  async function api(path, options = {}) {
    const response = await fetch(path, {
      credentials: "same-origin",
      cache: "no-store",
      ...options,
    });
    if (!response.ok) {
      const detail = (await response.text()).trim().slice(0, 260);
      throw new Error(`HTTP ${response.status}${detail ? ` · ${detail}` : ""}`);
    }
    const type = response.headers.get("content-type") || "";
    if (!type.includes("application/json"))
      throw new Error("服务未返回 JSON，请确认管理 API 地址。");
    return response.json();
  }

  function renderConnection() {
    const status = $("connection-status");
    status.dataset.state =
      state.online === null
        ? "connecting"
        : state.online
          ? "online"
          : "offline";
    status.classList.toggle("is-offline", state.online === false);
    status.classList.toggle("is-online", state.online === true);
    status.textContent =
      state.online === null
        ? "正在连接"
        : state.online
          ? "服务在线"
          : "连接中断";
    const updated = state.lastUpdated
      ? new Date(state.lastUpdated).toLocaleTimeString("zh-CN", {
          hour12: false,
        })
      : "尚未同步";
    setText(
      "last-updated",
      state.online === false ? `上次成功同步 ${updated}` : `更新于 ${updated}`,
    );
  }

  function uptime(seconds) {
    const total = Math.max(0, Number(seconds) || 0);
    const days = Math.floor(total / 86400);
    const hours = Math.floor((total % 86400) / 3600);
    const minutes = Math.floor((total % 3600) / 60);
    if (days) return `${days} 天 ${hours} 小时`;
    if (hours) return `${hours} 小时 ${minutes} 分钟`;
    return minutes ? `${minutes} 分钟` : `${Math.floor(total)} 秒`;
  }

  function renderStats() {
    const stats = state.stats;
    if (!stats) return;
    setText("stat-queries", formatNumber(stats.queries));
    setText(
      "stat-qps",
      state.trend.qps === null ? "—" : state.trend.qps.toFixed(1),
    );
    const rate = cacheRate(stats);
    setText(
      "stat-cache-rate",
      rate === null ? "—" : `${(rate * 100).toFixed(1)}%`,
    );
    setText(
      "stat-latency",
      Number(stats.queries) > 0 ? latencyMs(stats.avg_latency_us) : "—",
    );
    setText("response-count", formatNumber(stats.responses));
    setText("dropped-count", formatNumber(stats.dropped));
    setText("upstream-ok", formatNumber(stats.upstream_ok));
    setText("upstream-errors", formatNumber(stats.upstream_err));
    setText("cache-hits", formatNumber(stats.cache_hits));
    setText("cache-misses", formatNumber(stats.cache_misses));
    setText("cache-lazy-hits", formatNumber(stats.cache_lazy_hits));
    setText("uptime-label", uptime(stats.uptime_secs));
    renderChart();
  }

  function svgNode(tag, attrs, value) {
    const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [key, attribute] of Object.entries(attrs))
      node.setAttribute(key, attribute);
    if (value !== undefined) node.textContent = value;
    return node;
  }

  function renderChart() {
    const svg = $("query-chart");
    clear(svg);
    const minutes = Number($("chart-range").value) || 5;
    const end = state.trend?.current.at || Date.now();
    const start = end - minutes * 60000;
    const points = (state.trend?.points || []).filter(
      (point) => point.at >= start,
    );
    const left = 48,
      top = 18,
      width = 734,
      height = 166;
    const maxQps = Math.max(1, ...points.map((point) => point.qps));
    const ceiling = Math.ceil(maxQps * 1.2 * 10) / 10;
    for (let i = 0; i <= 4; i += 1) {
      const y = top + (height * i) / 4;
      svg.append(
        svgNode("line", {
          x1: left,
          x2: left + width,
          y1: y,
          y2: y,
          class: "chart-grid",
        }),
      );
      svg.append(
        svgNode(
          "text",
          {
            x: left - 12,
            y: y + 4,
            "text-anchor": "end",
            class: "chart-label",
          },
          ((ceiling * (4 - i)) / 4).toFixed(ceiling >= 20 ? 0 : 1),
        ),
      );
    }
    for (let i = 0; i <= 4; i += 1) {
      const time = new Date(start + ((end - start) * i) / 4).toLocaleTimeString(
        "zh-CN",
        {
          hour12: false,
          hour: "2-digit",
          minute: "2-digit",
          second: minutes <= 1 ? "2-digit" : undefined,
        },
      );
      svg.append(
        svgNode(
          "text",
          {
            x: left + (width * i) / 4,
            y: 210,
            "text-anchor": i === 0 ? "start" : i === 4 ? "end" : "middle",
            class: "chart-label",
          },
          time,
        ),
      );
    }
    show("chart-empty", points.length < 2);
    svg.setAttribute(
      "aria-label",
      points.length < 2
        ? "正在积累真实查询速率数据"
        : `最近 ${minutes} 分钟查询速率，共 ${points.length} 个采样点`,
    );
    if (points.length < 2) return;
    const coordinates = points.map((point) => ({
      x: left + ((point.at - start) / (end - start)) * width,
      y: top + height - (point.qps / ceiling) * height,
    }));
    const path = coordinates
      .map(
        (point, index) =>
          `${index ? "L" : "M"}${point.x.toFixed(2)},${point.y.toFixed(2)}`,
      )
      .join(" ");
    const first = coordinates[0];
    const last = coordinates[coordinates.length - 1];
    svg.append(
      svgNode("path", {
        d: `${path} L${last.x},${top + height} L${first.x},${top + height} Z`,
        class: "chart-area",
      }),
    );
    svg.append(
      svgNode("path", {
        d: path,
        class: "chart-line",
        fill: "none",
        "vector-effect": "non-scaling-stroke",
      }),
    );
    svg.append(
      svgNode("circle", { cx: last.x, cy: last.y, r: 4, class: "chart-point" }),
    );
  }

  function tableEmpty(target, columns, message) {
    const row = element("tr");
    const cell = element("td", "empty-table", message);
    cell.colSpan = columns;
    row.append(cell);
    target.append(row);
  }

  function renderListeners(target, detailed) {
    clear(target);
    const listeners = state.system.listeners || [];
    if (!listeners.length)
      return tableEmpty(target, detailed ? 5 : 3, "当前没有配置 DNS 监听服务");
    for (const listener of listeners) {
      const row = element("tr");
      const protocol = element("td");
      protocol.append(badge(String(listener.protocol || "").toUpperCase()));
      row.append(
        protocol,
        element("td", "mono", listener.addr),
        element("td", "mono", listener.entry || state.system.entry || "—"),
      );
      if (detailed)
        row.append(
          element("td", "", `${listener.timeout_secs} 秒`),
          element("td", "", listener.tls ? "已启用" : "未启用"),
        );
      target.append(row);
    }
  }

  function renderSystem() {
    const system = state.system;
    if (!system) return;
    const version = system.version
      ? `v${String(system.version).replace(/^v/, "")}`
      : "—";
    setText("version-label", version);
    setText("settings-version", version);
    setText("settings-entry", system.entry || "未配置");
    setText("settings-origin", location.origin);
    setText("overview-entry", system.entry || "未配置");
    renderListeners($("overview-listeners"), false);
    renderListeners($("settings-listeners"), true);
    const upstreams = $("settings-upstreams");
    clear(upstreams);
    for (const upstream of system.upstreams || []) {
      const row = element("tr");
      row.append(
        element("td", "mono", upstream.plugin),
        element("td", "mono", upstream.tag || "默认"),
        element("td", "mono", upstream.addr),
      );
      upstreams.append(row);
    }
    if (!upstreams.children.length)
      tableEmpty(upstreams, 3, "当前没有配置转发上游");
  }

  function updateEntries() {
    const select = $("query-entry");
    const old = select.value;
    const entries = [...(state.plugins.executables || [])].sort((a, b) =>
      a.localeCompare(b),
    );
    const signature = JSON.stringify([entries, state.plugins.entry]);
    if (select.dataset.signature === signature) return;
    select.dataset.signature = signature;
    clear(select);
    const defaultOption = element(
      "option",
      "",
      state.plugins.entry
        ? `默认入口 · ${state.plugins.entry}`
        : "选择执行入口",
    );
    defaultOption.value = "";
    select.append(defaultOption);
    for (const tag of entries) {
      const option = element("option", "", tag);
      option.value = tag;
      select.append(option);
    }
    select.value = entries.includes(old) ? old : "";
  }

  function renderPlugins() {
    if (!state.system || !state.plugins) return;
    const target = $("plugin-list");
    const keyword = $("plugin-search").value.trim().toLowerCase();
    const filter = $("plugin-filter").value;
    const all = pluginRows(state.system, state.plugins);
    const rows = all.filter(
      (plugin) =>
        `${plugin.tag} ${plugin.type}`.toLowerCase().includes(keyword) &&
        (filter === "all" ||
          (filter === "executable"
            ? plugin.executable
            : plugin.type === filter)),
    );
    setText("plugin-count", `${rows.length} / ${all.length}`);
    setText("overview-plugin-count", formatNumber(all.length));
    show("plugin-empty", rows.length === 0);
    const signature = JSON.stringify(rows);
    if (target.dataset.signature === signature) return;
    target.dataset.signature = signature;
    clear(target);
    for (const plugin of rows) {
      const row = element("tr");
      const tag = element("td", "mono plugin-tag", plugin.tag);
      const type = element("td");
      type.append(
        badge(plugin.type, plugin.type === "sequence" ? "purple" : "muted"),
      );
      const role = element("td");
      role.append(
        badge(
          plugin.entry ? "默认入口" : plugin.executable ? "可执行" : "数据集合",
          plugin.entry ? "success" : "muted",
        ),
      );
      const action = element("td", "cell-action");
      if (plugin.executable) {
        const button = element("button", "text-button", "用此入口查询");
        button.type = "button";
        button.dataset.entry = plugin.tag;
        action.append(button);
      } else action.append(element("span", "muted", "—"));
      row.append(tag, type, role, action);
      target.append(row);
    }
  }

  function renderCaches() {
    if (!state.plugins) return;
    const target = $("cache-list");
    const caches = [...(state.plugins.caches || [])].sort((a, b) =>
      a.tag.localeCompare(b.tag),
    );
    const signature = JSON.stringify(caches);
    const total = caches.reduce(
      (sum, cache) => sum + Number(cache.size || 0),
      0,
    );
    setText("cache-total", formatNumber(total));
    setText("overview-cache-count", formatNumber(caches.length));
    $("flush-all").disabled = !caches.length || state.flushing;
    show("cache-empty", caches.length === 0);
    if (target.dataset.signature === signature) return;
    target.dataset.signature = signature;
    clear(target);
    for (const cache of caches) {
      const card = element("article", "cache-card");
      const heading = element("div", "cache-card-header");
      heading.append(
        element("h3", "mono", cache.tag),
        badge("已加载", "success"),
      );
      const count = element("div", "cache-card-count");
      count.append(
        element("strong", "", formatNumber(cache.size)),
        element("span", "", " 条缓存记录"),
      );
      const footer = element("div", "cache-card-footer");
      footer.append(element("span", "muted", "当前内存缓存"));
      const button = element("button", "button secondary small", "清理缓存");
      button.type = "button";
      button.dataset.flush = cache.tag;
      button.disabled = state.flushing;
      footer.append(button);
      card.append(heading, count, footer);
      target.append(card);
    }
  }

  function scheduleRefresh() {
    clearTimeout(state.refreshTimer);
    if ($("auto-refresh").checked && !document.hidden)
      state.refreshTimer = setTimeout(refresh, REFRESH_MS);
  }

  function refresh() {
    if (state.refreshPromise) return state.refreshPromise;
    clearTimeout(state.refreshTimer);
    const controller = new AbortController();
    state.refreshController = controller;
    $("refresh-button").disabled = true;
    $("refresh-button").classList.add("is-loading");
    let timedOut = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, 12000);
    state.refreshPromise = (async () => {
      try {
        const [stats, plugins, system] = await Promise.all([
          api("/api/stats", { signal: controller.signal }),
          api("/api/plugins", { signal: controller.signal }),
          api("/api/system", { signal: controller.signal }),
        ]);
        if (controller.signal.aborted) return;
        if (
          !Number.isFinite(Number(stats.queries)) ||
          !Array.isArray(plugins.executables) ||
          !Array.isArray(system.plugins)
        ) {
          throw new Error("服务返回的数据格式不正确。");
        }
        const now = Date.now();
        state.trend = sampleTrend(
          state.trend,
          stats,
          now,
          system.runtime_id,
          state.online === false,
        );
        Object.assign(state, {
          stats,
          plugins,
          system,
          online: true,
          lastUpdated: now,
        });
        show("global-error", false);
        renderConnection();
        renderStats();
        renderSystem();
        updateEntries();
        renderPlugins();
        renderCaches();
      } catch (error) {
        if (controller.signal.aborted && !timedOut) return;
        controller.abort();
        state.online = false;
        renderConnection();
        setText(
          "global-error",
          `无法连接 FerrumDNS 管理服务。${timedOut ? "请求超时。" : error.message} ${state.lastUpdated ? "当前保留上次成功同步的数据。" : "请确认服务已启动并启用 api 配置。"}`,
        );
        show("global-error", true);
      } finally {
        clearTimeout(timeout);
        state.refreshController = null;
        state.refreshPromise = null;
        $("refresh-button").disabled = false;
        $("refresh-button").classList.remove("is-loading");
        scheduleRefresh();
      }
    })();
    return state.refreshPromise;
  }

  function renderQueryResult(result) {
    state.queryResult = result;
    show("query-empty", false);
    show("query-result", true);
    setText("result-rcode", result.rcode);
    $("result-rcode").dataset.tone = isSuccessfulResponse(result.rcode)
      ? "success"
      : "warning";
    setText("result-time", latencyMs(result.elapsed_us));
    setText("result-cache", result.cache_hit ? "命中缓存" : "未命中");
    setText("result-ecs", result.ecs || "未附带");
    const records = $("query-records");
    clear(records);
    if (Array.isArray(result.records)) {
      for (const record of result.records) {
        const row = element("tr");
        const type = element("td");
        type.append(badge(record.type));
        row.append(
          element("td", "mono", record.name),
          type,
          element("td", "mono", `${record.ttl} s`),
          element("td", "mono record-data", record.data),
        );
        records.append(row);
      }
    } else {
      for (const answer of result.answers || []) {
        const row = element("tr");
        const cell = element("td", "mono record-data", answer);
        cell.colSpan = 4;
        row.append(cell);
        records.append(row);
      }
    }
    if (!records.children.length)
      tableEmpty(records, 4, `没有返回 Answer 记录 · ${result.rcode}`);
    const trace = $("query-trace");
    clear(trace);
    for (const event of result.trace || []) {
      const item = element("li", "trace-item");
      const heading = element("div", "trace-heading");
      heading.append(
        element("strong", "mono", event.plugin),
        badge(
          event.event,
          /hit|answer|accept/.test(event.event) ? "success" : "muted",
        ),
        element("span", "trace-time", latencyMs(event.elapsed_us)),
      );
      item.append(heading, element("p", "trace-detail", event.detail));
      trace.append(item);
    }
    if (!trace.children.length)
      trace.append(element("li", "empty-table", "此次查询没有追踪事件"));
    setText("query-raw", JSON.stringify(result, null, 2));
  }

  function renderHistory() {
    const target = $("query-history");
    clear(target);
    if (!state.history.length) {
      target.append(
        element("li", "history-empty muted", "本次会话还没有查询记录"),
      );
      return;
    }
    state.history.forEach((entry, index) => {
      const item = element("li");
      const button = element("button", "history-item");
      button.type = "button";
      button.dataset.history = index;
      button.title = "载入查询参数和结果";
      const main = element("span", "history-main");
      main.append(
        element("strong", "mono", entry.payload.name),
        element(
          "span",
          "history-meta",
          `${entry.payload.qtype} · ${entry.payload.entry || "默认入口"}`,
        ),
      );
      const meta = element("span", "history-meta");
      meta.append(
        badge(
          entry.result?.rcode || "失败",
          entry.result && isSuccessfulResponse(entry.result.rcode)
            ? "success"
            : "warning",
        ),
        element(
          "span",
          "",
          new Date(entry.at).toLocaleTimeString("zh-CN", { hour12: false }),
        ),
      );
      button.append(main, meta);
      item.append(button);
      target.append(item);
    });
  }

  async function submitQuery(event) {
    event.preventDefault();
    if (state.queryController) return;
    show("query-error", false);
    document
      .querySelectorAll("#query-form [aria-invalid]")
      .forEach((input) => input.removeAttribute("aria-invalid"));
    const values = {
      name: $("query-name").value,
      qtype: $("query-type").value,
      entry: $("query-entry").value,
      client_ip: $("query-client-ip").value,
      ecs: $("query-ecs").value,
    };
    const validation = validateQuery(values);
    if (validation.message) {
      setText("query-error", validation.message);
      show("query-error", true);
      $(validation.field).setAttribute("aria-invalid", "true");
      const advanced = $(validation.field).closest("details");
      if (advanced) advanced.open = true;
      $(validation.field).focus();
      return;
    }
    const payload = validation.payload;
    const controller = new AbortController();
    state.queryController = controller;
    const submit = $("query-submit");
    const originalContent = [...submit.childNodes];
    submit.disabled = true;
    submit.textContent = "正在查询…";
    $("query-form").setAttribute("aria-busy", "true");
    show("query-result", false);
    show("query-empty", false);
    state.queryResult = null;
    const timeout = setTimeout(() => controller.abort(), 60000);
    const entry = { payload, at: Date.now(), result: null, error: null };
    try {
      entry.result = await api("/api/query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      renderQueryResult(entry.result);
    } catch (error) {
      entry.error = controller.signal.aborted
        ? "查询超时，请稍后重试。"
        : `查询失败：${error.message}`;
      setText("query-error", entry.error);
      show("query-error", true);
      show("query-empty", true);
    } finally {
      clearTimeout(timeout);
      state.queryController = null;
      submit.disabled = false;
      submit.replaceChildren(...originalContent);
      $("query-form").removeAttribute("aria-busy");
      state.history.unshift(entry);
      state.history.length = Math.min(10, state.history.length);
      renderHistory();
      if (!document.hidden) refresh();
    }
  }

  function loadHistory(index) {
    const entry = state.history[index];
    if (!entry || state.queryController) return;
    const fields = {
      name: "query-name",
      qtype: "query-type",
      entry: "query-entry",
      client_ip: "query-client-ip",
      ecs: "query-ecs",
    };
    for (const [key, id] of Object.entries(fields))
      $(id).value = entry.payload[key] || "";
    show("query-error", Boolean(entry.error));
    setText("query-error", entry.error || "");
    if (entry.result) renderQueryResult(entry.result);
    else {
      state.queryResult = null;
      show("query-result", false);
      show("query-empty", true);
    }
  }

  function openFlush(tag, trigger) {
    if (state.flushing) return;
    state.flushTag = tag;
    state.dialogTrigger = trigger;
    setText(
      "confirm-description",
      tag === null
        ? "将清空所有缓存插件中的解析记录。后续查询会重新解析并建立缓存。确定继续吗？"
        : `将清空「${tag}」中的解析记录。后续查询会重新解析并建立缓存。确定继续吗？`,
    );
    $("confirm-submit").disabled = false;
    $("confirm-cancel").disabled = false;
    $("confirm-submit").textContent = "确认清理";
    $("confirm-dialog").showModal();
    $("confirm-cancel").focus();
  }

  function closeFlush() {
    if (state.flushing) return;
    $("confirm-dialog").close();
  }

  async function confirmFlush(event) {
    event.preventDefault();
    if (state.flushing || state.flushTag === undefined) return;
    state.flushing = true;
    const tag = state.flushTag;
    $("confirm-submit").disabled = true;
    $("confirm-cancel").disabled = true;
    $("confirm-submit").textContent = "正在清理…";
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    try {
      await api("/api/cache/flush", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(tag === null ? {} : { tag }),
        signal: controller.signal,
      });
      notify(tag === null ? "已清理全部缓存" : `已清理缓存「${tag}」`);
    } catch (error) {
      notify(
        controller.signal.aborted
          ? "请求超时，请刷新后确认缓存状态。"
          : `清理失败：${error.message}`,
        true,
      );
    } finally {
      clearTimeout(timeout);
      state.flushing = false;
      closeFlush();
      // Wait for an existing read before requesting a fresh snapshot after the mutation.
      if (state.refreshPromise) await state.refreshPromise;
      if (!document.hidden) refresh();
    }
  }

  async function copyResult() {
    if (!state.queryResult) return;
    const value = JSON.stringify(state.queryResult, null, 2);
    try {
      if (navigator.clipboard && window.isSecureContext)
        await navigator.clipboard.writeText(value);
      else {
        const textarea = element("textarea", "clipboard-helper");
        textarea.value = value;
        textarea.setAttribute("readonly", "");
        document.body.append(textarea);
        textarea.select();
        let copied = false;
        try {
          copied = document.execCommand("copy");
        } finally {
          textarea.remove();
          $("copy-result").focus();
        }
        if (!copied) throw new Error("copy unavailable");
      }
      notify("查询结果已复制");
    } catch (_) {
      notify("复制失败，请展开原始响应并手动复制。", true);
    }
  }

  document.addEventListener("click", (event) => {
    const nav = event.target.closest("[data-nav]");
    if (nav && Object.hasOwn(pages, nav.dataset.nav)) {
      event.preventDefault();
      location.hash = nav.dataset.nav;
      navigate();
    }
    const queryName = event.target.closest("[data-query-name]");
    if (queryName) {
      $("query-name").value = queryName.dataset.queryName;
      $("query-name").focus();
    }
    const queryEntry = event.target.closest("[data-entry]");
    if (queryEntry) {
      $("query-entry").value = queryEntry.dataset.entry;
      location.hash = "query";
      navigate();
      $("query-name").focus();
    }
    const flush = event.target.closest("[data-flush]");
    if (flush) openFlush(flush.dataset.flush, flush);
    const historyButton = event.target.closest("[data-history]");
    if (historyButton) loadHistory(Number(historyButton.dataset.history));
  });
  window.addEventListener("hashchange", navigate);
  $("query-form").addEventListener("submit", submitQuery);
  $("plugin-search").addEventListener("input", renderPlugins);
  $("plugin-filter").addEventListener("change", renderPlugins);
  $("chart-range").addEventListener("change", renderChart);
  $("refresh-button").addEventListener("click", refresh);
  $("auto-refresh").addEventListener("change", () => {
    clearTimeout(state.refreshTimer);
    if ($("auto-refresh").checked && !document.hidden) refresh();
  });
  document.addEventListener("visibilitychange", () => {
    clearTimeout(state.refreshTimer);
    if (document.hidden) state.refreshController?.abort();
    else if ($("auto-refresh").checked) refresh();
  });
  $("flush-all").addEventListener("click", (event) =>
    openFlush(null, event.currentTarget),
  );
  $("confirm-cancel").addEventListener("click", (event) => {
    event.preventDefault();
    closeFlush();
  });
  $("confirm-submit").addEventListener("click", confirmFlush);
  $("confirm-dialog").addEventListener("cancel", (event) => {
    if (state.flushing) event.preventDefault();
  });
  $("confirm-dialog").addEventListener("close", () => {
    state.flushTag = undefined;
    if (state.dialogTrigger?.isConnected) state.dialogTrigger.focus();
    else $("flush-all").focus();
    state.dialogTrigger = null;
  });
  $("copy-result").addEventListener("click", copyResult);
  $("mobile-menu").addEventListener("click", () => {
    const open = !$("sidebar").classList.contains("open");
    $("sidebar").classList.toggle("open", open);
    document.body.classList.toggle("sidebar-open", open);
    $("mobile-menu").setAttribute("aria-expanded", String(open));
    syncSidebarInert();
    if (open) $("sidebar-close").focus();
  });
  mobileViewport.addEventListener("change", () => {
    if (!mobileViewport.matches) closeSidebar();
    else syncSidebarInert();
  });
  $("sidebar-close").addEventListener("click", () => {
    closeSidebar();
    $("mobile-menu").focus();
  });
  document.querySelector(".skip-link")?.addEventListener("click", (event) => {
    event.preventDefault();
    $("main").focus();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && $("sidebar").classList.contains("open")) {
      closeSidebar();
      $("mobile-menu").focus();
    }
  });
  window.addEventListener("pagehide", () => {
    clearTimeout(state.refreshTimer);
    state.refreshController?.abort();
    state.queryController?.abort();
  });

  navigate();
  renderConnection();
  renderHistory();
  renderChart();
  if (!document.hidden) refresh();
})();
