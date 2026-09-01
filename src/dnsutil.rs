use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::{Error, Result};

pub fn decode(buf: &[u8]) -> Result<Message> {
    Message::from_vec(buf).map_err(|e| Error::protocol(e.to_string()))
}

pub fn encode(msg: &Message) -> Result<Vec<u8>> {
    msg.to_vec().map_err(|e| Error::protocol(e.to_string()))
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

pub fn first_question(msg: &Message) -> Option<&Query> {
    msg.queries().first()
}

pub fn name_ascii(n: &Name) -> String {
    let s = n.to_ascii();
    s.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::build_query;

    #[test]
    fn roundtrip_query() {
        let q = build_query("example.com.", RecordType::A).unwrap();
        let bytes = encode(&q).unwrap();
        let back = decode(&bytes).unwrap();
        assert_eq!(back.queries()[0].name(), q.queries()[0].name());
        assert_eq!(back.queries()[0].query_type(), RecordType::A);
    }
}
