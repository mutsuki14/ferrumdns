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
    pub trace: Vec<TraceEvent>,
    pub trace_enabled: bool,
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
            trace: Vec::new(),
            trace_enabled: false,
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
        self.response = Some(msg);
    }

    pub fn drop_response(&mut self) {
        self.response = None;
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

    pub fn push_trace(&mut self, plugin: impl Into<String>, event: impl Into<String>, detail: impl Into<String>) {
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
        Self {
            id: next_id(),
            start: Instant::now(),
            client_addr: self.client_addr,
            protocol: self.protocol,
            query: self.query.clone(),
            original: self.original.clone(),
            response: None,
            marks: self.marks.clone(),
            trace: Vec::new(),
            trace_enabled: false,
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
