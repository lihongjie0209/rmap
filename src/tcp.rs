use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::types::PortStatus;

/// Attempt a TCP connect to determine port status.
///
/// - `Open`     — connection succeeded
/// - `Closed`   — connection actively refused (RST)
/// - `Filtered` — timeout or other network error (no response / dropped)
pub async fn scan_port(ip: IpAddr, port: u16, timeout_dur: Duration) -> PortStatus {
    let addr = SocketAddr::new(ip, port);
    match timeout(timeout_dur, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => PortStatus::Open,
        Ok(Err(e)) => {
            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                PortStatus::Closed
            } else {
                PortStatus::Filtered
            }
        }
        Err(_) => PortStatus::Filtered,
    }
}
