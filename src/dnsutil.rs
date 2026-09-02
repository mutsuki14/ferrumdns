use hickory_proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::{Error, Result};

pub fn decode(buf: &[u8]) -> Result<Message> {
    Message::from_vec(buf).map_err(|e| Error::protocol(e.to_string()))
}

pub fn encode(msg: &Message) -> Result<Vec<u8>> {
    msg.to_vec().map_err(|e| Error::protocol(e.to_string()))
}

/// How to treat a packet received on a listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Incoming {
    /// Already a response (or garbage) — do not reply (avoids amplification).
    Drop,
    /// Unsupported opcode — reply NOTIMP.
    NotImp,
    Ok,
}

pub fn classify_incoming(msg: &Message) -> Incoming {
    if msg.message_type() != MessageType::Query {
        Incoming::Drop
    } else if msg.op_code() != OpCode::Query {
        Incoming::NotImp
    } else {
        Incoming::Ok
    }
}

pub fn take_response(query: &Message, resp: Message) -> Result<Message> {
    if resp.message_type() != MessageType::Response {
        return Err(Error::protocol("upstream sent a query"));
    }
    if resp.id() != query.id() {
        return Err(Error::protocol("id mismatch"));
    }
    Ok(resp)
}

/// A response that should win a `concurrent` race. SERVFAIL/FORMERR from one
/// upstream must not beat a slower NOERROR from another.
pub fn is_usable_response(msg: &Message) -> bool {
    msg.message_type() == MessageType::Response
        && !matches!(
            msg.response_code(),
            ResponseCode::ServFail
                | ResponseCode::FormErr
                | ResponseCode::NotImp
                | ResponseCode::Refused
        )
}

pub fn udp_payload_max(query: &Message) -> usize {
    query
        .extensions()
        .as_ref()
        .map(|e| e.max_payload() as usize)
        .filter(|&n| n >= 512)
        .unwrap_or(512)
        .min(4096)
}

pub fn encode_udp(msg: &Message, max_len: usize) -> Result<Vec<u8>> {
    let bytes = encode(msg)?;
    if bytes.len() <= max_len {
        return Ok(bytes);
    }
    encode(&msg.truncate())
}

pub fn reply_skeleton(query: &Message, rcode: ResponseCode) -> Message {
    let mut msg = Message::new();
    msg.set_id(query.id());
    msg.set_message_type(MessageType::Response);
    msg.set_op_code(query.op_code());
    msg.set_recursion_desired(query.recursion_desired());
    msg.set_recursion_available(true);
    msg.set_response_code(rcode);
    for q in query.queries() {
        msg.add_query(q.clone());
    }
    if let Some(edns) = query.extensions() {
        msg.set_edns(edns.clone());
    }
    msg
}

pub fn min_ttl(msg: &Message) -> u32 {
    msg.answers()
        .iter()
        .chain(msg.name_servers())
        .map(|r| r.ttl())
        .min()
        .unwrap_or(0)
}

pub fn subtract_ttl(msg: &mut Message, elapsed: u32) {
    let bump = |recs: &mut [Record]| {
        for r in recs {
            // OPT CLASS/TTL are EDNS payload size + flags, not a TTL.
            if r.record_type() == RecordType::OPT {
                continue;
            }
            let ttl = r.ttl().saturating_sub(elapsed);
            r.set_ttl(ttl);
        }
    };
    bump(msg.answers_mut());
    bump(msg.name_servers_mut());
    bump(msg.additionals_mut());
}

pub fn set_all_ttl(msg: &mut Message, ttl: u32) {
    for r in msg.answers_mut() {
        r.set_ttl(ttl);
    }
    for r in msg.name_servers_mut() {
        r.set_ttl(ttl);
    }
}

pub fn record_a(name: Name, ttl: u32, ip: Ipv4Addr) -> Record {
    Record::from_rdata(name, ttl, RData::A(hickory_proto::rr::rdata::A(ip)))
}

pub fn record_aaaa(name: Name, ttl: u32, ip: Ipv6Addr) -> Record {
    Record::from_rdata(name, ttl, RData::AAAA(hickory_proto::rr::rdata::AAAA(ip)))
}

pub fn record_cname(name: Name, ttl: u32, target: Name) -> Record {
    Record::from_rdata(
        name,
        ttl,
        RData::CNAME(hickory_proto::rr::rdata::CNAME(target)),
    )
}

pub fn parse_ip(s: &str) -> Option<IpAddr> {
    s.parse().ok()
}

pub fn qtype_from_str(s: &str) -> Option<RecordType> {
    match s.to_ascii_uppercase().as_str() {
        "A" => Some(RecordType::A),
        "AAAA" => Some(RecordType::AAAA),
        "CNAME" => Some(RecordType::CNAME),
        "MX" => Some(RecordType::MX),
        "NS" => Some(RecordType::NS),
        "PTR" => Some(RecordType::PTR),
        "SOA" => Some(RecordType::SOA),
        "SRV" => Some(RecordType::SRV),
        "TXT" => Some(RecordType::TXT),
        "HTTPS" => Some(RecordType::HTTPS),
        "SVCB" => Some(RecordType::SVCB),
        "ANY" | "*" => Some(RecordType::ANY),
        other => other.parse().ok(),
    }
}

pub fn rcode_from_str(s: &str) -> ResponseCode {
    match s.to_ascii_uppercase().as_str() {
        "NOERROR" | "0" => ResponseCode::NoError,
        "FORMERR" | "1" => ResponseCode::FormErr,
        "SERVFAIL" | "2" => ResponseCode::ServFail,
        "NXDOMAIN" | "3" => ResponseCode::NXDomain,
        "NOTIMP" | "4" => ResponseCode::NotImp,
        "REFUSED" | "5" => ResponseCode::Refused,
        n => match n.parse::<u16>() {
            Ok(v) => <ResponseCode as From<u16>>::from(v),
            Err(_) => ResponseCode::Refused,
        },
    }
}

pub fn rcode_to_u16(r: ResponseCode) -> u16 {
    u16::from(r)
}

pub fn name_ascii(n: &Name) -> String {
    n.to_ascii()
}

pub fn ecs_of(msg: &Message) -> Option<ClientSubnet> {
    let edns = msg.extensions().as_ref()?;
    match edns.option(EdnsCode::Subnet)? {
        EdnsOption::Subnet(cs) => Some(*cs),
        _ => None,
    }
}

pub fn set_ecs(msg: &mut Message, cs: ClientSubnet) {
    let edns = msg.extensions_mut().get_or_insert_with(|| {
        let mut e = Edns::new();
        e.set_max_payload(1232);
        e
    });
    edns.options_mut().remove(EdnsCode::Subnet);
    edns.options_mut().insert(EdnsOption::Subnet(cs));
}

pub fn remove_ecs(msg: &mut Message) {
    if let Some(edns) = msg.extensions_mut() {
        edns.options_mut().remove(EdnsCode::Subnet);
    }
}

pub fn ecs_label(cs: Option<&ClientSubnet>) -> String {
    match cs {
        Some(cs) => format!("{}/{}", cs.addr(), cs.source_prefix()),
        None => "-".into(),
    }
}

/// Cache-key fragment so geo-steered answers don't collide.
pub fn ecs_cache_key(msg: &Message) -> String {
    match ecs_of(msg) {
        Some(cs) => format!("ecs={}/{}", cs.addr(), cs.source_prefix()),
        None => "ecs=-".into(),
    }
}

pub fn parse_ecs_spec(s: &str) -> Result<ClientSubnet> {
    let s = s.trim();
    let (addr, prefix) = if let Some((a, p)) = s.split_once('/') {
        let ip: IpAddr = a
            .parse()
            .map_err(|e| Error::config(format!("bad ecs addr: {e}")))?;
        let prefix: u8 = p
            .parse()
            .map_err(|_| Error::config("bad ecs prefix"))?;
        (ip, prefix)
    } else {
        let ip: IpAddr = s
            .parse()
            .map_err(|e| Error::config(format!("bad ecs addr: {e}")))?;
        let prefix = if ip.is_ipv4() { 24 } else { 48 };
        (ip, prefix)
    };
    let (net, prefix) = crate::plugin::ecs::masked(addr, prefix);
    Ok(ClientSubnet::new(net, prefix, 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;

    #[test]
    fn drops_response_packets() {
        let mut m = Message::new();
        m.set_message_type(MessageType::Response);
        assert_eq!(classify_incoming(&m), Incoming::Drop);
    }

    #[test]
    fn roundtrip_query() {
        let mut m = Message::new();
        m.set_id(42);
        m.set_message_type(MessageType::Query);
        m.set_op_code(OpCode::Query);
        let n = Name::from_ascii("example.com.").unwrap();
        let mut q = Query::new();
        q.set_name(n);
        q.set_query_type(RecordType::A);
        m.add_query(q);
        let bytes = encode(&m).unwrap();
        let back = decode(&bytes).unwrap();
        assert_eq!(back.id(), 42);
    }

    #[test]
    fn take_response_checks_id_and_qr() {
        let mut q = Message::new();
        q.set_id(7);
        q.set_message_type(MessageType::Query);
        let mut r = Message::new();
        r.set_id(8);
        r.set_message_type(MessageType::Response);
        assert!(take_response(&q, r).is_err());
    }

    #[test]
    fn usable_skips_servfail() {
        let mut m = Message::new();
        m.set_message_type(MessageType::Response);
        m.set_response_code(ResponseCode::ServFail);
        assert!(!is_usable_response(&m));
        m.set_response_code(ResponseCode::Refused);
        assert!(!is_usable_response(&m));
        m.set_response_code(ResponseCode::NXDomain);
        assert!(is_usable_response(&m));
        m.set_response_code(ResponseCode::NoError);
        assert!(is_usable_response(&m));
    }

    #[test]
    fn subtract_ttl_leaves_edns_flags_alone() {
        let mut m = Message::new();
        m.set_id(1);
        m.set_message_type(MessageType::Response);
        let n = Name::from_ascii("example.com.").unwrap();
        m.add_answer(record_a(n, 30, Ipv4Addr::new(1, 2, 3, 4)));
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        edns.set_max_payload(1232);
        m.set_edns(edns);
        subtract_ttl(&mut m, 5);
        assert_eq!(m.answers()[0].ttl(), 25);
        assert!(
            m.extensions().as_ref().unwrap().flags().dnssec_ok,
            "EDNS DO lives in extensions, must survive TTL decay"
        );
    }

    #[test]
    fn encode_udp_truncation_keeps_opt() {
        let mut m = Message::new();
        m.set_id(9);
        m.set_message_type(MessageType::Response);
        m.set_op_code(OpCode::Query);
        let n = Name::from_ascii("pad.example.com.").unwrap();
        for i in 0..40 {
            m.add_answer(record_a(n.clone(), 60, Ipv4Addr::new(10, 0, i, 1)));
        }
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        m.set_edns(edns);
        let bytes = encode_udp(&m, 512).unwrap();
        let back = decode(&bytes).unwrap();
        assert!(back.truncated());
        assert!(back.answers().is_empty());
        assert!(ecs_of(&back).is_none());
        assert!(back.extensions().is_some());
    }

    #[test]
    fn ecs_roundtrip_on_wire() {
        let mut m = Message::new();
        m.set_id(1);
        m.set_message_type(MessageType::Query);
        m.set_op_code(OpCode::Query);
        set_ecs(
            &mut m,
            ClientSubnet::new("203.0.113.0".parse().unwrap(), 24, 0),
        );
        let bytes = encode(&m).unwrap();
        let back = decode(&bytes).unwrap();
        let cs = ecs_of(&back).unwrap();
        assert_eq!(cs.source_prefix(), 24);
        assert_eq!(cs.addr(), "203.0.113.0".parse::<IpAddr>().unwrap());
        assert_eq!(ecs_cache_key(&back), "ecs=203.0.113.0/24");
        remove_ecs(&mut m);
        assert!(ecs_of(&m).is_none());
        assert_eq!(ecs_cache_key(&m), "ecs=-");
    }

    #[test]
    fn parse_ecs_spec_masks() {
        let cs = parse_ecs_spec("203.0.113.9/24").unwrap();
        assert_eq!(cs.addr(), "203.0.113.0".parse::<IpAddr>().unwrap());
        assert_eq!(cs.source_prefix(), 24);
        let def = parse_ecs_spec("8.8.8.8").unwrap();
        assert_eq!(def.source_prefix(), 24);
    }
}
