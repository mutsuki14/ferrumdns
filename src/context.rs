use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Instant;

use crate::dnsutil;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientProto {
    Udp,
    Tcp,
    Tls,
    Https,
}

impl ClientProto {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Tls => "tls",
            Self::Https => "https",
        }
    }
}

/// Per-query context that flows through the plugin pipeline.
pub struct QueryContext {
    pub id: u64,
    pub start: Instant,
    pub client_addr: Option<IpAddr>,
    pub protocol: ClientProto,
    query: Message,
    original: Message,
    response: Option<Message>,
    marks: HashSet<u32>,
    rewrites: Vec<(Name, Name)>,
    entry_state: Option<EntryState>,
    pub trace: Vec<TraceEvent>,
    pub trace_enabled: bool,
    /// Skip cache lookup (used by lazy-cache background refresh).
    pub skip_cache: bool,
    /// We attached ECS that the client did not send — strip it from the reply.
    pub strip_ecs_on_reply: bool,
    /// Response came from a cache hit; do not write it back (would reset TTLs).
    pub served_from_cache: bool,
    /// Listener / API pipeline tag. Lazy refresh re-enters this, not the first sequence.
    pub pipeline_entry: Option<String>,
}

#[derive(Clone)]
struct EntryState {
    query: Message,
    marks: HashSet<u32>,
    strip_ecs_on_reply: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TraceEvent {
    pub plugin: String,
    pub event: String,
    pub detail: String,
    pub elapsed_us: u64,
}

impl QueryContext {
    pub fn new(query: Message, client_addr: Option<IpAddr>, protocol: ClientProto) -> Self {
        let original = query.clone();
        Self {
            id: next_id(),
            start: Instant::now(),
            client_addr,
            protocol,
            query,
            original,
            response: None,
            marks: HashSet::new(),
            rewrites: Vec::new(),
            entry_state: None,
            trace: Vec::new(),
            trace_enabled: false,
            skip_cache: false,
            strip_ecs_on_reply: false,
            served_from_cache: false,
            pipeline_entry: None,
        }
    }

    pub fn query(&self) -> &Message {
        &self.query
    }

    pub fn query_mut(&mut self) -> &mut Message {
        &mut self.query
    }

    pub fn original(&self) -> &Message {
        &self.original
    }

    pub fn response(&self) -> Option<&Message> {
        self.response.as_ref()
    }

    pub fn response_mut(&mut self) -> Option<&mut Message> {
        self.response.as_mut()
    }

    pub fn set_response(&mut self, mut msg: Message) {
        msg.set_id(self.query.id());
        msg.set_message_type(MessageType::Response);
        self.response = Some(msg);
        self.served_from_cache = false;
    }

    pub fn drop_response(&mut self) {
        self.response = None;
        self.served_from_cache = false;
    }

    /// Capture the state before any pipeline step, once per incoming request.
    pub fn begin_pipeline(&mut self, entry: &str) {
        if self.entry_state.is_none() {
            self.entry_state = Some(EntryState {
                query: self.query.clone(),
                marks: self.marks.clone(),
                strip_ecs_on_reply: self.strip_ecs_on_reply,
            });
            self.pipeline_entry = Some(entry.to_string());
        }
    }

    /// Rewrite the upstream question while retaining the client's alias chain.
    pub fn rewrite_name(&mut self, mut name: Name) {
        // DNS wire questions are absolute, including config targets that omit
        // a trailing dot. Keep their cache identity identical to direct queries.
        name.set_fqdn(true);
        if let Some(question) = self.query.queries_mut().first_mut() {
            if question.name() != &name {
                self.rewrites.push((question.name().clone(), name.clone()));
                question.set_name(name);
            }
        }
    }

    pub(crate) fn rewrite_count(&self) -> usize {
        self.rewrites.len()
    }

    /// Rebind a reply to one question snapshot. Cache writers pass their lookup
    /// snapshot, so aliases preceding a target-cache lookup never enter it.
    pub(crate) fn response_for_query(
        &self,
        query: &Message,
        rewrite_start: usize,
    ) -> Option<Message> {
        let mut response = self.response.clone()?;
        Self::rebind_response(&mut response, query);
        let aliases = &self.rewrites[rewrite_start.min(self.rewrites.len())..];
        if !aliases.is_empty()
            && matches!(
                response.response_code(),
                ResponseCode::NoError | ResponseCode::NXDomain
            )
        {
            let ttl = dnsutil::min_ttl(&response);
            let mut records = Vec::new();
            for (from, to) in aliases {
                let already_present = response.answers().iter().any(|record| {
                    record.name() == from
                        && matches!(record.data(), RData::CNAME(target) if &target.0 == to)
                });
                if !already_present {
                    let mut record = dnsutil::record_cname(from.clone(), ttl, to.clone());
                    if let Some(question) = query.queries().first() {
                        record.set_dns_class(question.query_class());
                    }
                    records.push(record);
                }
            }
            records.extend_from_slice(response.answers());
            *response.answers_mut() = records;
            // A locally synthesized alias was not authenticated by the upstream.
            response.set_authentic_data(false);
        }
        Some(response)
    }

    pub(crate) fn rebind_response(response: &mut Message, query: &Message) {
        response.set_id(query.id());
        response.set_message_type(MessageType::Response);
        response.set_op_code(query.op_code());
        response.set_recursion_desired(query.recursion_desired());
        response.set_checking_disabled(query.checking_disabled());
        *response.queries_mut() = query.queries().to_vec();
        match (response.extensions_mut(), query.extensions()) {
            (response_edns, None) => *response_edns = None,
            (Some(response_edns), Some(query_edns)) => {
                response_edns.set_max_payload(query_edns.max_payload());
                response_edns.set_dnssec_ok(query_edns.flags().dnssec_ok);
            }
            _ => {}
        }
    }

    /// Called only after all pipeline/cache writes, immediately before sending.
    pub fn finalize_response(&mut self) {
        self.response = self.response_for_query(&self.original, 0);
    }

    pub fn has_resp(&self) -> bool {
        self.response.is_some()
    }

    pub fn qname(&self) -> Option<Name> {
        self.query.queries().first().map(|q| q.name().clone())
    }

    pub fn qname_str(&self) -> String {
        self.qname()
            .map(|n| n.to_ascii())
            .unwrap_or_else(|| ".".into())
    }

    pub fn qtype(&self) -> RecordType {
        self.query
            .queries()
            .first()
            .map(|q| q.query_type())
            .unwrap_or(RecordType::A)
    }

    pub fn question(&self) -> Option<&Query> {
        self.query.queries().first()
    }

    pub fn add_mark(&mut self, m: u32) {
        self.marks.insert(m);
    }

    pub fn has_mark(&self, m: u32) -> bool {
        self.marks.contains(&m)
    }

    pub fn push_trace(
        &mut self,
        plugin: impl Into<String>,
        event: impl Into<String>,
        detail: impl Into<String>,
    ) {
        if !self.trace_enabled {
            return;
        }
        self.trace.push(TraceEvent {
            plugin: plugin.into(),
            event: event.into(),
            detail: detail.into(),
            elapsed_us: self.start.elapsed().as_micros() as u64,
        });
    }

    pub fn make_response(&self, rcode: ResponseCode) -> Message {
        dnsutil::reply_skeleton(&self.query, rcode)
    }

    pub fn reject(&mut self, rcode: ResponseCode) {
        self.set_response(self.make_response(rcode));
    }

    pub fn clone_for_lazy(&self) -> Self {
        let mut c = Self::new(self.original.clone(), self.client_addr, self.protocol);
        if let Some(initial) = &self.entry_state {
            c.query = initial.query.clone();
            c.marks = initial.marks.clone();
            c.strip_ecs_on_reply = initial.strip_ecs_on_reply;
        }
        c.entry_state = self.entry_state.clone();
        c.pipeline_entry = self.pipeline_entry.clone();
        c.skip_cache = true;
        c
    }

    /// Independent copy of the query for a parallel pipeline (fallback).
    /// Unlike `clone_for_lazy`, cache lookup is preserved.
    pub fn fork(&self) -> Self {
        Self {
            id: next_id(),
            start: Instant::now(),
            client_addr: self.client_addr,
            protocol: self.protocol,
            query: self.query.clone(),
            original: self.original.clone(),
            response: None,
            marks: self.marks.clone(),
            rewrites: self.rewrites.clone(),
            entry_state: self.entry_state.clone(),
            trace: Vec::new(),
            trace_enabled: self.trace_enabled,
            skip_cache: self.skip_cache,
            strip_ecs_on_reply: self.strip_ecs_on_reply,
            served_from_cache: false,
            pipeline_entry: self.pipeline_entry.clone(),
        }
    }

    /// Copy pipeline results from a forked context (fallback winner).
    pub fn absorb(&mut self, other: Self) {
        self.query = other.query;
        self.response = other.response;
        self.marks = other.marks;
        self.rewrites = other.rewrites;
        self.strip_ecs_on_reply = other.strip_ecs_on_reply;
        self.skip_cache = other.skip_cache;
        self.served_from_cache = other.served_from_cache;
        if self.trace_enabled {
            self.trace.extend(other.trace);
        }
    }

    pub fn answer_ips(&self) -> Vec<IpAddr> {
        let Some(resp) = &self.response else {
            return Vec::new();
        };
        resp.answers()
            .iter()
            .filter_map(|r| match r.data() {
                RData::A(a) => Some(IpAddr::V4(a.0)),
                RData::AAAA(a) => Some(IpAddr::V6(a.0)),
                _ => None,
            })
            .collect()
    }

    pub fn has_wanted_ans(&self) -> bool {
        let Some(resp) = &self.response else {
            return false;
        };
        if resp.response_code() != ResponseCode::NoError {
            return false;
        }
        let want = self.qtype();
        resp.answers().iter().any(|r| r.record_type() == want)
    }

    pub fn apply_ttl_clamp(&mut self, min: u32, max: u32) {
        let Some(resp) = self.response.as_mut() else {
            return;
        };
        for rec in resp.answers_mut() {
            let ttl = rec.ttl().clamp(min, max);
            rec.set_ttl(ttl);
        }
        for rec in resp.name_servers_mut() {
            let ttl = rec.ttl().clamp(min, max);
            rec.set_ttl(ttl);
        }
    }

    pub fn prefer_ipv4(&mut self) {
        self.filter_answers(|rt| rt != RecordType::AAAA);
    }

    pub fn prefer_ipv6(&mut self) {
        self.filter_answers(|rt| rt != RecordType::A);
    }

    fn filter_answers(&mut self, keep: impl Fn(RecordType) -> bool) {
        let Some(resp) = self.response.as_mut() else {
            return;
        };
        let kept: Vec<Record> = resp
            .answers()
            .iter()
            .filter(|r| keep(r.record_type()))
            .cloned()
            .collect();
        resp.answers_mut().clear();
        for r in kept {
            resp.add_answer(r);
        }
    }
}

pub fn build_hosts_response(q: &Message, records: Vec<Record>) -> Message {
    let mut msg = dnsutil::reply_skeleton(q, ResponseCode::NoError);
    msg.set_authoritative(true);
    for r in records {
        msg.add_answer(r);
    }
    msg
}

pub fn build_query(name: &str, qtype: RecordType) -> anyhow::Result<Message> {
    let mut msg = Message::new();
    msg.set_id(rand::random());
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let n = Name::from_ascii(name)?;
    let mut query = Query::new();
    query.set_name(n);
    query.set_query_type(qtype);
    query.set_query_class(DNSClass::IN);
    msg.add_query(query);
    Ok(msg)
}

fn next_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static ID: AtomicU64 = AtomicU64::new(1);
    ID.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fork_keeps_cache_lookup_lazy_skips() {
        let q = build_query("fork.test.", RecordType::A).unwrap();
        let ctx = QueryContext::new(q, Some("8.8.8.8".parse().unwrap()), ClientProto::Udp);
        let f = ctx.fork();
        assert!(!f.skip_cache);
        assert_eq!(f.client_addr, ctx.client_addr);
        let lazy = ctx.clone_for_lazy();
        assert!(lazy.skip_cache);
        assert_eq!(lazy.client_addr, ctx.client_addr);
    }
}
