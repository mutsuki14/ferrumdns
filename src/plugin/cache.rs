use async_trait::async_trait;
use hickory_proto::op::ResponseCode;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant};

use crate::context::QueryContext;
use crate::dnsutil;
use crate::error::Result;
use crate::metrics::Metrics;
use crate::plugin::{Action, Executable};
use crate::runtime::Runtime;

struct Entry {
    wire: Vec<u8>,
    stored: Instant,
    ttl_deadline: Instant,
    expire: Instant,
}

struct Shard {
    map: HashMap<String, Entry>,
    lru: VecDeque<String>,
    cap: usize,
}

impl Shard {
    fn new(cap: usize) -> Self {
        Self {
            map: HashMap::with_capacity(cap.min(1024)),
            lru: VecDeque::with_capacity(cap.min(1024)),
            cap: cap.max(1),
        }
    }

    fn get(&mut self, key: &str) -> Option<&Entry> {
        if self.map.contains_key(key) {
            if let Some(pos) = self.lru.iter().position(|k| k == key) {
                if let Some(k) = self.lru.remove(pos) {
                    self.lru.push_back(k);
                }
            }
            self.map.get(key)
        } else {
            None
        }
    }

    fn insert(&mut self, key: String, entry: Entry) {
        if self.map.contains_key(&key) {
            self.map.insert(key.clone(), entry);
            if let Some(pos) = self.lru.iter().position(|k| k == &key) {
                self.lru.remove(pos);
            }
            self.lru.push_back(key);
            return;
        }
        while self.map.len() >= self.cap {
            if let Some(old) = self.lru.pop_front() {
                self.map.remove(&old);
            } else {
                break;
            }
        }
        self.lru.push_back(key.clone());
        self.map.insert(key, entry);
    }

    fn flush(&mut self) {
        self.map.clear();
        self.lru.clear();
    }

    fn len(&self) -> usize {
        self.map.len()
    }
}

pub struct Cache {
    tag: String,
    shards: Vec<Mutex<Shard>>,
    lazy_ttl: Duration,
    lazy_reply_ttl: u32,
    cache_everything: bool,
    metrics: Arc<Metrics>,
    refresh: OnceLock<(Weak<Runtime>, String)>,
    inflight: Arc<Mutex<HashSet<String>>>,
}

impl Cache {
    pub fn from_args(tag: &str, args: &serde_yaml::Value, metrics: Arc<Metrics>) -> Arc<Self> {
        let size = args.get("size").and_then(|v| v.as_u64()).unwrap_or(8192) as usize;
        let n_shards = 16usize;
        let per = (size / n_shards).max(32);
        let shards = (0..n_shards).map(|_| Mutex::new(Shard::new(per))).collect();
        let lazy = args
            .get("lazy_cache_ttl")
            .or_else(|| args.get("lazy_ttl"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let lazy_reply = args
            .get("lazy_cache_reply_ttl")
            .and_then(|v| v.as_u64())
            .unwrap_or(5) as u32;
        Arc::new(Self {
            tag: tag.to_string(),
            shards,
            lazy_ttl: Duration::from_secs(lazy),
            lazy_reply_ttl: lazy_reply.max(1),
            cache_everything: args
                .get("cache_everything")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            metrics,
            refresh: OnceLock::new(),
            inflight: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    fn shard(&self, key: &str) -> &Mutex<Shard> {
        let mut h = 0u64;
        for b in key.as_bytes() {
            h = h.wrapping_mul(16777619) ^ *b as u64;
        }
        &self.shards[h as usize % self.shards.len()]
    }

    fn key_of(ctx: &QueryContext, everything: bool) -> Option<String> {
        let q = ctx.query();
        let simple = q.queries().len() == 1 && q.answers().is_empty() && q.name_servers().is_empty();
        if !simple && !everything {
            return None;
        }
        let q0 = q.queries().first()?;
        Some(format!(
            "{}|{:?}|{:?}|{}",
            dnsutil::name_ascii(q0.name()),
            q0.query_type(),
            q0.query_class(),
            dnsutil::ecs_cache_key(q)
        ))
    }

    fn lookup(&self, key: &str) -> Option<(Vec<u8>, bool, Instant)> {
        let mut shard = self.shard(key).lock();
        let now = Instant::now();
        let e = shard.get(key)?;
        if now >= e.expire {
            return None;
        }
        let lazy = now >= e.ttl_deadline && self.lazy_ttl > Duration::ZERO;
        Some((e.wire.clone(), lazy, e.stored))
    }

    fn store(&self, key: String, ctx: &QueryContext) {
        let Some(resp) = ctx.response() else {
            return;
        };
        if resp.response_code() != ResponseCode::NoError || resp.truncated() {
            return;
        }
        let Ok(wire) = dnsutil::encode(resp) else {
            return;
        };
        let min = dnsutil::min_ttl(resp);
        if min == 0 && self.lazy_ttl == Duration::ZERO {
            return;
        }
        let now = Instant::now();
        let ttl_deadline = now + Duration::from_secs(min.max(1) as u64);
        let expire = if self.lazy_ttl > Duration::ZERO {
            now + self.lazy_ttl
        } else {
            ttl_deadline
        };
        self.shard(&key).lock().insert(
            key,
            Entry {
                wire,
                stored: now,
                ttl_deadline,
                expire,
            },
        );
    }

    pub fn flush(&self) {
        for s in &self.shards {
            s.lock().flush();
        }
    }

    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().len()).sum()
    }

    pub fn maybe_store(&self, ctx: &QueryContext) {
        if ctx.served_from_cache {
            return;
        }
        if let Some(key) = Self::key_of(ctx, self.cache_everything) {
            if ctx.has_resp() {
                self.store(key, ctx);
            }
        }
    }

    pub fn bind_refresh(&self, rt: Weak<Runtime>, entry: String) {
        let _ = self.refresh.set((rt, entry));
    }

    fn kick_refresh(&self, ctx: &QueryContext, key: &str) {
        if ctx.skip_cache {
            return;
        }
        let Some((weak, entry)) = self.refresh.get() else {
            return;
        };
        if !self.inflight.lock().insert(key.to_string()) {
            return;
        }
        let mut bg = ctx.clone_for_lazy();
        let weak = weak.clone();
        let entry = ctx
            .pipeline_entry
            .clone()
            .unwrap_or_else(|| entry.clone());
        let inflight = self.inflight.clone();
        let key = key.to_string();
        tokio::spawn(async move {
            if let Some(rt) = weak.upgrade() {
                let _ = rt.handle_query(&mut bg, &entry).await;
            }
            inflight.lock().remove(&key);
        });
    }
}

#[async_trait]
impl Executable for Cache {
    async fn exec(&self, ctx: &mut QueryContext) -> Result<Action> {
        let Some(key) = Self::key_of(ctx, self.cache_everything) else {
            return Ok(Action::Continue);
        };

        if ctx.skip_cache {
            self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
            ctx.push_trace(&self.tag, "miss", "refresh");
            return Ok(Action::Continue);
        }

        if let Some((wire, lazy, stored)) = self.lookup(&key) {
            if let Ok(mut msg) = dnsutil::decode(&wire) {
                let elapsed = Instant::now().saturating_duration_since(stored).as_secs() as u32;
                if lazy {
                    dnsutil::set_all_ttl(&mut msg, self.lazy_reply_ttl);
                    self.metrics.cache_lazy_hits.fetch_add(1, Ordering::Relaxed);
                    ctx.push_trace(&self.tag, "lazy_hit", &key);
                    self.kick_refresh(ctx, &key);
                } else {
                    dnsutil::subtract_ttl(&mut msg, elapsed);
                    ctx.push_trace(&self.tag, "hit", &key);
                }
                self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
                ctx.served_from_cache = true;
                ctx.set_response(msg);
                return Ok(Action::Continue);
            }
        }

        self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
        ctx.push_trace(&self.tag, "miss", &key);
        Ok(Action::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_promotes_lru() {
        let mut s = Shard::new(2);
        let now = Instant::now();
        let mk = |wire: u8| Entry {
            wire: vec![wire],
            stored: now,
            ttl_deadline: now + Duration::from_secs(10),
            expire: now + Duration::from_secs(10),
        };
        s.insert("a".into(), mk(1));
        s.insert("b".into(), mk(2));
        s.insert("a".into(), mk(3)); // promote a
        s.insert("c".into(), mk(4)); // should evict b, not a
        assert!(s.map.contains_key("a"));
        assert!(s.map.contains_key("c"));
        assert!(!s.map.contains_key("b"));
        assert_eq!(s.map["a"].wire, vec![3]);
    }

    #[tokio::test]
    async fn skip_cache_bypasses_stored_hit() {
        use crate::context::{build_query, ClientProto, QueryContext};
        use crate::dnsutil;
        use hickory_proto::rr::{Name, RecordType};
        use std::str::FromStr;

        let metrics = crate::metrics::Metrics::new();
        let args: serde_yaml::Value = serde_yaml::from_str("size: 64").unwrap();
        let cache = Cache::from_args("cache", &args, metrics);

        let q = build_query("skip.test.", RecordType::A).unwrap();
        let mut ctx = QueryContext::new(q.clone(), None, ClientProto::Udp);
        let mut resp = dnsutil::reply_skeleton(ctx.query(), hickory_proto::op::ResponseCode::NoError);
        resp.add_answer(dnsutil::record_a(
            Name::from_str("skip.test.").unwrap(),
            60,
            "9.9.9.9".parse().unwrap(),
        ));
        ctx.set_response(resp);
        cache.maybe_store(&ctx);

        let mut hit = QueryContext::new(q.clone(), None, ClientProto::Udp);
        hit.trace_enabled = true;
        cache.exec(&mut hit).await.unwrap();
        assert!(hit.has_resp());
        assert!(hit.trace.iter().any(|t| t.event == "hit"));

        let mut skip = QueryContext::new(q, None, ClientProto::Udp);
        skip.skip_cache = true;
        skip.trace_enabled = true;
        cache.exec(&mut skip).await.unwrap();
        assert!(!skip.has_resp());
        assert!(skip.trace.iter().any(|t| t.detail == "refresh"));
    }
}
