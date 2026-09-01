use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

pub struct Metrics {
    pub queries: AtomicU64,
    pub responses: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub cache_lazy_hits: AtomicU64,
    pub upstream_ok: AtomicU64,
    pub upstream_err: AtomicU64,
    pub dropped: AtomicU64,
    pub latency_us_sum: AtomicU64,
    pub started: Instant,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            queries: AtomicU64::new(0),
            responses: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            cache_lazy_hits: AtomicU64::new(0),
            upstream_ok: AtomicU64::new(0),
            upstream_err: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            latency_us_sum: AtomicU64::new(0),
            started: Instant::now(),
        })
    }

    pub fn observe_query(&self, latency_us: u64) {
        self.queries.fetch_add(1, Ordering::Relaxed);
        self.latency_us_sum.fetch_add(latency_us, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> Snapshot {
        let q = self.queries.load(Ordering::Relaxed);
        let sum = self.latency_us_sum.load(Ordering::Relaxed);
        Snapshot {
            queries: q,
            responses: self.responses.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            cache_lazy_hits: self.cache_lazy_hits.load(Ordering::Relaxed),
            upstream_ok: self.upstream_ok.load(Ordering::Relaxed),
            upstream_err: self.upstream_err.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            avg_latency_us: if q == 0 { 0 } else { sum / q },
            uptime_secs: self.started.elapsed().as_secs(),
        }
    }

    pub fn prometheus(&self) -> String {
        let s = self.snapshot();
        format!(
            concat!(
                "# HELP ferrumdns_queries_total Total DNS queries\n",
                "# TYPE ferrumdns_queries_total counter\n",
                "ferrumdns_queries_total {}\n",
                "# TYPE ferrumdns_responses_total counter\n",
                "ferrumdns_responses_total {}\n",
                "# TYPE ferrumdns_cache_hits_total counter\n",
                "ferrumdns_cache_hits_total {}\n",
                "# TYPE ferrumdns_cache_misses_total counter\n",
                "ferrumdns_cache_misses_total {}\n",
                "# TYPE ferrumdns_upstream_ok_total counter\n",
                "ferrumdns_upstream_ok_total {}\n",
                "# TYPE ferrumdns_upstream_err_total counter\n",
                "ferrumdns_upstream_err_total {}\n",
                "# TYPE ferrumdns_avg_latency_microseconds gauge\n",
                "ferrumdns_avg_latency_microseconds {}\n",
                "# TYPE ferrumdns_uptime_seconds gauge\n",
                "ferrumdns_uptime_seconds {}\n"
            ),
            s.queries,
            s.responses,
            s.cache_hits,
            s.cache_misses,
            s.upstream_ok,
            s.upstream_err,
            s.avg_latency_us,
            s.uptime_secs
        )
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Snapshot {
    pub queries: u64,
    pub responses: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_lazy_hits: u64,
    pub upstream_ok: u64,
    pub upstream_err: u64,
    pub dropped: u64,
    pub avg_latency_us: u64,
    pub uptime_secs: u64,
}
