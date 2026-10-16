//! Synthesis of UDP reply packets injected back into the TUN, so the in-daemon
//! Magic DNS resolver can answer queries addressed to the magic IP without a
//! host socket, and of the TCP reset that refuses DNS over TCP. IPv6 only: the resolver is reached at [`crate::dns::MAGIC_DNS_V6`]
//! and nowhere else, so there is one family to synthesise for.

use std::net::IpAddr;
use std::net::Ipv6Addr;

use bytes::Bytes;

use crate::firewall::PacketInfo;

const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;
const TCP_HEADER_LEN: usize = 20;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;
/// Keep DNS replies within IPv6's minimum MTU, even when the TUN is larger.
const MTU: usize = 1280;

/// Builds a complete IP+UDP reply packet for a query, swapping src/dst and
/// computing the checksums. The resolver answers on [`crate::dns::MAGIC_DNS_V6`]
/// alone, so an IPv4 query never reaches here; it and a payload that would
/// overflow the MTU both return `None`.
pub fn build_udp_reply(query: &PacketInfo, dns_payload: &[u8]) -> Option<Bytes> {
    match (query.src_ip, query.dst_ip) {
        (IpAddr::V6(app), IpAddr::V6(magic)) => build_v6_reply(query, app, magic, dns_payload),
        _ => None,
    }
}

fn build_v6_reply(
    query: &PacketInfo,
    app_ip: Ipv6Addr,
    magic_ip: Ipv6Addr,
    dns_payload: &[u8],
) -> Option<Bytes> {
    let total = IPV6_HEADER_LEN + UDP_HEADER_LEN + dns_payload.len();
    if total > MTU {
        return None;
    }
    let mut p = vec![0u8; total];

    // ---- IPv6 header ----
    p[0] = 0x60; // version 6, traffic class 0
    // flow label (1..4) left zero
    let payload_len = (UDP_HEADER_LEN + dns_payload.len()) as u16;
    p[4..6].copy_from_slice(&payload_len.to_be_bytes());
    p[6] = 17; // next header: UDP
    p[7] = 64; // hop limit
    p[8..24].copy_from_slice(&magic_ip.octets()); // src = magic IP (reply from)
    p[24..40].copy_from_slice(&app_ip.octets()); // dst = the app

    // ---- UDP header ----
    let udp_off = IPV6_HEADER_LEN;
    p[udp_off..udp_off + 2].copy_from_slice(&query.dst_port.to_be_bytes()); // src port = 53
    p[udp_off + 2..udp_off + 4].copy_from_slice(&query.src_port.to_be_bytes()); // dst = app's port
    p[udp_off + 4..udp_off + 6].copy_from_slice(&payload_len.to_be_bytes());
    // checksum (udp_off+6..+8) zero while computing
    p[udp_off + UDP_HEADER_LEN..].copy_from_slice(dns_payload);

    let udp_csum = transport_checksum(magic_ip, app_ip, PROTO_UDP, &p[udp_off..]);
    let udp_csum = if udp_csum == 0 { 0xffff } else { udp_csum };
    p[udp_off + 6..udp_off + 8].copy_from_slice(&udp_csum.to_be_bytes());

    Some(Bytes::from(p))
}

/// Builds the TCP reset that refuses a segment sent to the magic resolver.
///
/// The resolver has no TCP stack, and a silently dropped SYN leaves the client
/// (systemd-resolved retrying a truncated answer over TCP, or `dig +tcp`)
/// waiting out its whole connect timeout. A reset fails it at once. Built the
/// way RFC 9293 3.10.7.1 says a closed port answers: from the segment's ACK
/// when it has one, otherwise acknowledging what it carried. A reset is never
/// answered, and an IPv4 segment cannot reach here (see [`build_udp_reply`]).
pub fn build_tcp_rst(query: &PacketInfo, pkt: &[u8]) -> Option<Bytes> {
    let (IpAddr::V6(app_ip), IpAddr::V6(magic_ip)) = (query.src_ip, query.dst_ip) else {
        return None;
    };
    let tcp = pkt.get(query.transport_offset..)?;
    if tcp.len() < TCP_HEADER_LEN {
        return None;
    }
    let flags = tcp[13];
    if flags & TCP_RST != 0 {
        return None;
    }
    let their_seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let their_ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let header_len = usize::from(tcp[12] >> 4) * 4;
    let data_len = tcp.len().saturating_sub(header_len) as u32;

    let (seq, ack, out_flags) = if flags & TCP_ACK != 0 {
        (their_ack, 0, TCP_RST)
    } else {
        let len = data_len + u32::from(flags & TCP_SYN != 0) + u32::from(flags & TCP_FIN != 0);
        (0, their_seq.wrapping_add(len), TCP_RST | TCP_ACK)
    };

    let mut p = vec![0u8; IPV6_HEADER_LEN + TCP_HEADER_LEN];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&(TCP_HEADER_LEN as u16).to_be_bytes());
    p[6] = PROTO_TCP;
    p[7] = 64;
    p[8..24].copy_from_slice(&magic_ip.octets());
    p[24..40].copy_from_slice(&app_ip.octets());

    let t = IPV6_HEADER_LEN;
    p[t..t + 2].copy_from_slice(&query.dst_port.to_be_bytes());
    p[t + 2..t + 4].copy_from_slice(&query.src_port.to_be_bytes());
    p[t + 4..t + 8].copy_from_slice(&seq.to_be_bytes());
    p[t + 8..t + 12].copy_from_slice(&ack.to_be_bytes());
    p[t + 12] = ((TCP_HEADER_LEN / 4) as u8) << 4;
    p[t + 13] = out_flags;
    // Window, checksum and urgent pointer stay zero until the checksum below.
    let csum = transport_checksum(magic_ip, app_ip, PROTO_TCP, &p[t..]);
    p[t + 16..t + 18].copy_from_slice(&csum.to_be_bytes());
    Some(Bytes::from(p))
}

/// UDP or TCP checksum over the IPv6 pseudo-header + segment.
fn transport_checksum(src: Ipv6Addr, dst: Ipv6Addr, protocol: u8, udp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for ip in [src, dst] {
        for segment in ip.segments() {
            sum += segment as u32;
        }
    }
    sum += u32::from(protocol);
    sum += udp_segment.len() as u32; // upper-layer length
    let mut i = 0;
    while i + 1 < udp_segment.len() {
        sum += u16::from_be_bytes([udp_segment[i], udp_segment[i + 1]]) as u32;
        i += 2;
    }
    if i < udp_segment.len() {
        sum += (udp_segment[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::dns::MAGIC_DNS_V6;

    /// The swap, and a UDP checksum that actually verifies: IPv6 has no header
    /// checksum to fall back on and makes the UDP one mandatory, so a wrong one is
    /// a silent drop by the receiving stack rather than a visible error.
    #[test]
    fn build_udp_reply_v6_swaps_and_checksums() {
        let app: Ipv6Addr = "200::5".parse().unwrap();
        let query = crate::firewall::PacketInfo {
            src_ip: IpAddr::V6(app),
            dst_ip: IpAddr::V6(MAGIC_DNS_V6),
            protocol: 17,
            src_port: 51000,
            dst_port: 53,
            tcp_flags: 0,
            icmp_type: 0,
            icmp_id: 0,
            transport_offset: 40,
        };
        let dns = b"\x12\x34\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00";
        let pkt = build_udp_reply(&query, dns).expect("v6 reply");
        let info = crate::firewall::parse_packet_info(&pkt).expect("parses");
        assert_eq!(info.src_ip, query.dst_ip);
        assert_eq!(info.dst_ip, query.src_ip);
        assert_eq!(info.src_port, 53);
        assert_eq!(info.dst_port, 51000);

        assert_eq!(pkt[0] >> 4, 6);
        assert_eq!(pkt[6], 17); // next header: UDP
        // Payload length covers the UDP header + the DNS body, and the header is
        // a fixed 40 bytes, so the body starts at 48.
        assert_eq!(
            u16::from_be_bytes([pkt[4], pkt[5]]) as usize,
            UDP_HEADER_LEN + dns.len()
        );
        assert_eq!(&pkt[48..], dns);

        // Recomputing over the received segment must come out zero: the sum of
        // the pseudo-header and a segment carrying a correct checksum folds to
        // 0xffff, which the routine complements to 0.
        assert_eq!(
            transport_checksum(MAGIC_DNS_V6, app, PROTO_UDP, &pkt[IPV6_HEADER_LEN..]),
            0
        );
    }

    fn tcp_segment(app: Ipv6Addr, flags: u8, seq: u32, ack: u32) -> (PacketInfo, Vec<u8>) {
        let mut pkt = vec![0u8; IPV6_HEADER_LEN + TCP_HEADER_LEN];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&(TCP_HEADER_LEN as u16).to_be_bytes());
        pkt[6] = PROTO_TCP;
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&app.octets());
        pkt[24..40].copy_from_slice(&MAGIC_DNS_V6.octets());
        let t = IPV6_HEADER_LEN;
        pkt[t..t + 2].copy_from_slice(&41000u16.to_be_bytes());
        pkt[t + 2..t + 4].copy_from_slice(&53u16.to_be_bytes());
        pkt[t + 4..t + 8].copy_from_slice(&seq.to_be_bytes());
        pkt[t + 8..t + 12].copy_from_slice(&ack.to_be_bytes());
        pkt[t + 12] = 5 << 4;
        pkt[t + 13] = flags;
        let info = crate::firewall::parse_packet_info(&pkt).expect("parses");
        (info, pkt)
    }

    /// A SYN to the resolver is refused with RST|ACK acknowledging the SYN, so
    /// the client's connect fails at once instead of timing out.
    #[test]
    fn a_syn_is_answered_with_a_reset() {
        let app: Ipv6Addr = "200::5".parse().unwrap();
        let (info, pkt) = tcp_segment(app, TCP_SYN, 1000, 0);
        let rst = build_tcp_rst(&info, &pkt).expect("reset");
        let rinfo = crate::firewall::parse_packet_info(&rst).expect("parses");
        assert_eq!(rinfo.src_ip, IpAddr::V6(MAGIC_DNS_V6));
        assert_eq!(rinfo.dst_ip, IpAddr::V6(app));
        assert_eq!(rinfo.src_port, 53);
        assert_eq!(rinfo.dst_port, 41000);
        let t = &rst[IPV6_HEADER_LEN..];
        assert_eq!(t[13], TCP_RST | TCP_ACK);
        assert_eq!(u32::from_be_bytes([t[8], t[9], t[10], t[11]]), 1001);
        assert_eq!(transport_checksum(MAGIC_DNS_V6, app, PROTO_TCP, t), 0);
    }

    #[test]
    fn an_acking_segment_is_reset_from_its_ack_and_a_reset_is_never_answered() {
        let app: Ipv6Addr = "200::5".parse().unwrap();
        let (info, pkt) = tcp_segment(app, TCP_ACK, 5, 777);
        let rst = build_tcp_rst(&info, &pkt).expect("reset");
        let t = &rst[IPV6_HEADER_LEN..];
        assert_eq!(t[13], TCP_RST);
        assert_eq!(u32::from_be_bytes([t[4], t[5], t[6], t[7]]), 777);

        let (info, pkt) = tcp_segment(app, TCP_RST, 5, 0);
        assert!(build_tcp_rst(&info, &pkt).is_none());
    }

    #[test]
    fn build_udp_reply_rejects_ipv4() {
        // The resolver answers on the IPv6 magic address alone, so an IPv4 query
        // never reaches here; guarded so a future caller that hand-builds a
        // PacketInfo gets nothing rather than a malformed reply.
        let query = crate::firewall::PacketInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 5)),
            dst_ip: IpAddr::V6(MAGIC_DNS_V6),
            protocol: 17,
            src_port: 51000,
            dst_port: 53,
            tcp_flags: 0,
            icmp_type: 0,
            icmp_id: 0,
            transport_offset: 20,
        };
        assert!(build_udp_reply(&query, b"\x00\x00").is_none());
    }

    #[test]
    fn build_udp_reply_rejects_oversize() {
        let query = crate::firewall::PacketInfo {
            src_ip: IpAddr::V6("200::5".parse().unwrap()),
            dst_ip: IpAddr::V6(MAGIC_DNS_V6),
            protocol: 17,
            src_port: 51000,
            dst_port: 53,
            tcp_flags: 0,
            icmp_type: 0,
            icmp_id: 0,
            transport_offset: 40,
        };
        // One byte past what fits: the largest payload that does still builds.
        let fits = MTU - IPV6_HEADER_LEN - UDP_HEADER_LEN;
        assert!(build_udp_reply(&query, &vec![0u8; fits]).is_some());
        assert!(build_udp_reply(&query, &vec![0u8; fits + 1]).is_none());
    }
}
