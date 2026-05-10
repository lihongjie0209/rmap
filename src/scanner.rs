use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use tokio::sync::Semaphore;

use crate::icmp::ping;
use crate::tcp::scan_port;
use crate::types::{HostResult, PortResult, PortStatus, ScanConfig};

fn make_progress_bar(multi: &MultiProgress, total: u64, prefix: &str, color: &str) -> ProgressBar {
    let pb = multi.add(ProgressBar::new(total));
    let tmpl = format!(
        "{{prefix:.bold}} [{{bar:40.{color}/black}}] {{pos}}/{{len}} hosts/ports  {{elapsed}}"
    );
    pb.set_style(
        ProgressStyle::default_bar()
            .template(&tmpl)
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("=>-"),
    );
    pb.set_prefix(prefix.to_string());
    pb
}

/// Entry point: orchestrates ICMP sweep + TCP port scan.
pub async fn run_scan(config: &ScanConfig) -> Vec<HostResult> {
    let timeout = Duration::from_millis(config.timeout_ms);
    let multi = MultiProgress::new();

    // Phase 1: ICMP host discovery
    let (alive_ips, mut results) = if !config.skip_icmp {
        icmp_phase(&config.targets, timeout, config.concurrency, &multi).await
    } else {
        // Treat every target as potentially alive
        let map: HashMap<IpAddr, HostResult> = config
            .targets
            .iter()
            .map(|&ip| (ip, HostResult { ip, alive: None, ports: vec![] }))
            .collect();
        (config.targets.clone(), map)
    };

    if config.skip_ports {
        let mut out: Vec<HostResult> = results.into_values().collect();
        out.sort_by_key(|h| h.ip);
        return out;
    }

    // Phase 2: TCP port scan (only alive hosts, or all if ICMP was skipped)
    port_phase(
        &alive_ips,
        &config.ports,
        timeout,
        config.concurrency,
        config.open_only,
        &multi,
        &mut results,
    )
    .await;

    let mut out: Vec<HostResult> = results.into_values().collect();
    out.sort_by_key(|h| h.ip);
    out
}

async fn icmp_phase(
    targets: &[IpAddr],
    timeout: Duration,
    concurrency: usize,
    multi: &MultiProgress,
) -> (Vec<IpAddr>, HashMap<IpAddr, HostResult>) {
    let pb = make_progress_bar(multi, targets.len() as u64, "ICMP ", "cyan");
    // Cap raw-socket concurrency to avoid exhausting the blocking thread pool.
    let sem = Arc::new(Semaphore::new(concurrency.min(256)));

    let mut futs: FuturesUnordered<_> = targets
        .iter()
        .map(|&ip| {
            let sem = Arc::clone(&sem);
            let pb = pb.clone();
            async move {
                let _permit = sem.acquire().await.unwrap();
                let alive = match ip {
                    IpAddr::V4(v4) => ping(v4, timeout).await,
                    IpAddr::V6(_) => false, // IPv6 ICMP not implemented
                };
                pb.inc(1);
                (ip, alive)
            }
        })
        .collect();

    let mut alive_ips = Vec::new();
    let mut results: HashMap<IpAddr, HostResult> = HashMap::new();

    while let Some((ip, alive)) = futs.next().await {
        if alive {
            alive_ips.push(ip);
        }
        results.insert(ip, HostResult { ip, alive: Some(alive), ports: vec![] });
    }

    pb.finish_and_clear();
    (alive_ips, results)
}

async fn port_phase(
    hosts: &[IpAddr],
    ports: &[u16],
    timeout: Duration,
    concurrency: usize,
    open_only: bool,
    multi: &MultiProgress,
    results: &mut HashMap<IpAddr, HostResult>,
) {
    if hosts.is_empty() || ports.is_empty() {
        return;
    }

    let total = hosts.len() as u64 * ports.len() as u64;
    let pb = make_progress_bar(multi, total, "PORTS", "green");
    let sem = Arc::new(Semaphore::new(concurrency));

    let mut futs: FuturesUnordered<_> = hosts
        .iter()
        .flat_map(|&ip| {
            let sem = Arc::clone(&sem);
            let pb = pb.clone();
            ports.iter().map(move |&port| {
                let sem = Arc::clone(&sem);
                let pb = pb.clone();
                async move {
                    let _permit = sem.acquire().await.unwrap();
                    let status = scan_port(ip, port, timeout).await;
                    pb.inc(1);
                    (ip, port, status)
                }
            })
        })
        .collect();

    while let Some((ip, port, status)) = futs.next().await {
        if let Some(host) = results.get_mut(&ip) {
            if !open_only || status == PortStatus::Open {
                host.ports.push(PortResult { port, status });
            }
        }
    }

    pb.finish_and_clear();

    // Keep ports in ascending order
    for host in results.values_mut() {
        host.ports.sort_by_key(|p| p.port);
    }
}
