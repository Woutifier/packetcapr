extern crate rustc_serialize;
extern crate pcap;

#[derive(RustcDecodable, RustcEncodable)]
pub struct PingPacket {
    timestamp: i64,
    srcip: String,
    dstip: String,
    id: u16,
    seq: u16,
}

impl<'a> From<::pcap::Packet<'a>> for PingPacket {
    fn from(packet: ::pcap::Packet) -> PingPacket {
        let srcip = ::std::net::Ipv4Addr::new(packet.data[26],
                                              packet.data[27],
                                              packet.data[28],
                                              packet.data[29]);
        let dstip = ::std::net::Ipv4Addr::new(packet.data[30],
                                              packet.data[31],
                                              packet.data[32],
                                              packet.data[33]);
        PingPacket {
            timestamp: packet.header.ts.tv_sec,
            srcip: srcip.to_string(),
            dstip: dstip.to_string(),
            id: ((packet.data[38] as u16) << 8 | (packet.data[39] as u16)),
            seq: ((packet.data[40] as u16) << 8 | (packet.data[41] as u16)),
        }
    }
}
