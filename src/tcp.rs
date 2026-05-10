use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::types::PortStatus;

/// Attempt a TCP connect to determine port status.
///
/// Returns `(status, stream)` where `stream` is `Some` only when the port is Open,
/// so the caller can reuse the connection for service detection.
pub async fn scan_port(ip: IpAddr, port: u16, timeout_dur: Duration) -> (PortStatus, Option<TcpStream>) {
    let addr = SocketAddr::new(ip, port);
    match timeout(timeout_dur, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => (PortStatus::Open, Some(stream)),
        Ok(Err(e)) => {
            let status = if e.kind() == std::io::ErrorKind::ConnectionRefused {
                PortStatus::Closed
            } else {
                PortStatus::Filtered
            };
            (status, None)
        }
        Err(_) => (PortStatus::Filtered, None),
    }
}
