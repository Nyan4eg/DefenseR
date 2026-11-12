use std::net::IpAddr;

use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Connection {
    pub protocol: &'static str,
    pub local_addr: String,
    pub local_port: u16,
    /// UDP sockets have no remote side.
    pub remote_addr: Option<String>,
    pub remote_port: Option<u16>,
    pub state: Option<String>,
    pub pid: Option<u32>,
    /// The remote address is outside loopback, private and link-local ranges.
    pub remote_is_public: bool,
}

fn is_public(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            !(v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified())
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            let unique_local = first & 0xfe00 == 0xfc00;
            let link_local = first & 0xffc0 == 0xfe80;
            !(v6.is_loopback() || v6.is_unspecified() || unique_local || link_local)
        }
    }
}

pub fn collect() -> Vec<Connection> {
    let families = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let protocols = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let Ok(sockets) = get_sockets_info(families, protocols) else {
        return Vec::new();
    };

    sockets
        .into_iter()
        .map(|socket| {
            let pid = socket.associated_pids.first().copied();
            match socket.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp) => Connection {
                    protocol: "TCP",
                    local_addr: tcp.local_addr.to_string(),
                    local_port: tcp.local_port,
                    remote_is_public: is_public(&tcp.remote_addr),
                    remote_addr: Some(tcp.remote_addr.to_string()),
                    remote_port: Some(tcp.remote_port),
                    state: Some(tcp.state.to_string()),
                    pid,
                },
                ProtocolSocketInfo::Udp(udp) => Connection {
                    protocol: "UDP",
                    local_addr: udp.local_addr.to_string(),
                    local_port: udp.local_port,
                    remote_is_public: false,
                    remote_addr: None,
                    remote_port: None,
                    state: None,
                    pid,
                },
            }
        })
        .collect()
}
