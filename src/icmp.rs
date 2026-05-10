use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

/// Global counter to assign unique ICMP identifiers per probe.
static PING_ID: AtomicU16 = AtomicU16::new(1);

/// One's-complement checksum used by ICMP.
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_echo_request(id: u16, seq: u16) -> Vec<u8> {
    let mut buf = vec![
        8u8, 0, 0, 0,               // type=8 (Echo Request), code=0, checksum placeholder
        (id >> 8) as u8, id as u8,  // identifier
        (seq >> 8) as u8, seq as u8, // sequence number
    ];
    buf.extend_from_slice(b"rmap0000"); // 8-byte payload
    let ck = checksum(&buf);
    buf[2] = (ck >> 8) as u8;
    buf[3] = ck as u8;
    buf
}

/// Blocking ICMP ping. Runs in a dedicated thread via `spawn_blocking`.
fn ping_sync(ip: Ipv4Addr, timeout: Duration, id: u16) -> bool {
    let sock = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let pkt = build_echo_request(id, 1);
    let dest = SocketAddrV4::new(ip, 0);
    if sock.send_to(&pkt, &dest.into()).is_err() {
        return false;
    }

    let deadline = Instant::now() + timeout;
    let mut buf = vec![MaybeUninit::<u8>::uninit(); 256];

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        // Update per-call receive timeout so we honour the overall deadline.
        let _ = sock.set_read_timeout(Some(remaining));

        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                // SAFETY: recv_from guarantees the first `n` bytes are initialised.
                let data: &[u8] =
                    unsafe { &*(&buf[..n] as *const [MaybeUninit<u8>] as *const [u8]) };

                // Raw ICMP sockets on both Linux and Windows prepend the IP header.
                let ihl = if data.len() >= 20 && (data[0] >> 4) == 4 {
                    ((data[0] & 0x0F) as usize) * 4
                } else {
                    0
                };

                let icmp = &data[ihl..];
                // type=0 is Echo Reply; check our identifier to avoid false positives
                // from concurrent probes sharing the same raw socket queue.
                if icmp.len() >= 6 && icmp[0] == 0 {
                    let reply_id = u16::from_be_bytes([icmp[4], icmp[5]]);
                    if reply_id == id {
                        return true;
                    }
                }
            }
            // Timeout (TimedOut / WouldBlock) or other error
            Err(_) => return false,
        }
    }
}

/// Async wrapper: runs the blocking ping in a tokio blocking thread.
///
/// **Requires elevated privileges** (root on Linux / Administrator on Windows).
pub async fn ping(ip: Ipv4Addr, timeout: Duration) -> bool {
    let id = PING_ID.fetch_add(1, Ordering::Relaxed);
    tokio::task::spawn_blocking(move || ping_sync(ip, timeout, id))
        .await
        .unwrap_or(false)
}
