import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const {
  cacheRate,
  sampleTrend,
  ipVersion,
  validateQuery,
  pluginRows,
  isSuccessfulResponse,
} = require("../web/app.js");

test("successful DNS status accepts Hickory Display output as well as protocol spelling", () => {
  for (const rcode of ["No Error", "NOERROR", "NoError"])
    assert.equal(isSuccessfulResponse(rcode), true);
  for (const rcode of ["Name Error", "NXDOMAIN", "SERVFAIL", undefined])
    assert.equal(isSuccessfulResponse(rcode), false);
});

test("cache rate has no synthetic zero and excludes lazy hits from the denominator", () => {
  assert.equal(cacheRate({ cache_hits: 0, cache_misses: 0 }), null);
  assert.equal(
    cacheRate({ cache_hits: 3, cache_misses: 1, cache_lazy_hits: 8 }),
    0.75,
  );
});

test("QPS uses elapsed sample time and resets on reload, rollback and reconnect", () => {
  const first = sampleTrend(
    null,
    { queries: 100, uptime_secs: 10 },
    1000,
    "runtime-a",
  );
  assert.equal(first.qps, null);
  assert.deepEqual(first.points, []);
  const second = sampleTrend(
    first,
    { queries: 121, uptime_secs: 17 },
    8000,
    "runtime-a",
  );
  assert.equal(second.qps, 3);
  assert.equal(second.points.length, 1);
  assert.equal(
    sampleTrend(second, { queries: 122, uptime_secs: 18 }, 9000, "runtime-b")
      .qps,
    null,
  );
  assert.equal(
    sampleTrend(second, { queries: 50, uptime_secs: 18 }, 9000, "runtime-a")
      .qps,
    null,
  );
  assert.equal(
    sampleTrend(second, { queries: 130, uptime_secs: 1 }, 9000, "runtime-a")
      .qps,
    null,
  );
  const reconnected = sampleTrend(
    second,
    { queries: 130, uptime_secs: 18 },
    9000,
    "runtime-a",
    true,
  );
  assert.equal(reconnected.qps, null);
  assert.equal(reconnected.points.length, 0);
  assert.equal(
    sampleTrend(second, { queries: 130, uptime_secs: 18 }, 8000, "runtime-a")
      .qps,
    null,
  );
});

test("trend retains only the latest fifteen minutes of real samples", () => {
  let trend = sampleTrend(null, { queries: 0, uptime_secs: 0 }, 1, "a");
  trend = sampleTrend(trend, { queries: 3, uptime_secs: 3 }, 3001, "a");
  trend = sampleTrend(trend, { queries: 6, uptime_secs: 6 }, 6001, "a");
  trend = sampleTrend(trend, { queries: 9, uptime_secs: 907 }, 907001, "a");
  assert.equal(trend.points.length, 1);
  assert.equal(trend.points[0].at, 907001);
});

test("IP validation supports IPv6 compression and IPv4 tails, rejects malformed addresses", () => {
  for (const ip of ["0.0.0.0", "203.0.113.9", "255.255.255.255"])
    assert.equal(ipVersion(ip), 4, ip);
  for (const ip of [
    "::",
    "::1",
    "2001:db8::1",
    "1:2:3:4:5:6:7:8",
    "::ffff:192.0.2.1",
  ])
    assert.equal(ipVersion(ip), 6, ip);
  for (const ip of [
    "256.1.1.1",
    "01.2.3.4",
    "127.1",
    ":::",
    "::1::",
    ":1:2:3:4:5:6:7",
    "1:2:3:4:5:6:7:",
    "1:2:3:4:5:6:7:8::",
    "fe80::1%eth0",
    "::ffff:999.0.0.1",
  ])
    assert.equal(ipVersion(ip), 0, ip);
});

test("query form trims optional values and validates DNS and ECS before POST", () => {
  assert.deepEqual(
    validateQuery({
      name: " router.lan ",
      qtype: "a",
      entry: "",
      ecs: "",
      client_ip: "",
    }),
    { payload: { name: "router.lan", qtype: "A" } },
  );
  for (const name of [
    ".",
    "_dns._udp.example.org",
    "nas.lan.",
    "xn--fiqs8s.example",
  ])
    assert.ok(validateQuery({ name }).payload, name);
  for (const name of [
    "",
    "https://example.org",
    "two labels.com",
    "example..org",
    `${"a".repeat(64)}.org`,
    "<script>",
  ])
    assert.equal(validateQuery({ name }).field, "query-name", name);
  assert.ok(
    validateQuery({
      name: "example.org",
      ecs: "2001:db8::/48",
      client_ip: "::1",
    }).payload,
  );
  assert.ok(validateQuery({ name: "example.org", ecs: "0.0.0.0/0" }).payload);
  for (const ecs of [
    "1.2.3.4/33",
    "2001:db8::/129",
    "1.2.3.4",
    "1.2.3.4/-1",
    "::/1/2",
  ])
    assert.equal(
      validateQuery({ name: "example.org", ecs }).field,
      "query-ecs",
      ecs,
    );
  assert.equal(
    validateQuery({ name: "example.org", client_ip: "999.1.2.3" }).field,
    "query-client-ip",
  );
});

test("plugin inventory deduplicates overlapping registries and preserves configured types", () => {
  const rows = pluginRows(
    {
      plugins: [
        { tag: "main", type: "sequence" },
        { tag: "cache", type: "cache" },
      ],
    },
    {
      executables: ["main", "cache"],
      caches: [{ tag: "cache", size: 1 }],
      domain_sets: ["ads"],
      ip_sets: ["lan"],
      entry: "main",
    },
  );
  assert.equal(rows.length, 4);
  assert.equal(rows[0].tag, "main");
  assert.equal(rows[0].type, "sequence");
  assert.equal(rows[0].entry, true);
  assert.equal(rows.find((row) => row.tag === "ads").executable, false);
  assert.equal(rows.find((row) => row.tag === "cache").executable, true);
});
