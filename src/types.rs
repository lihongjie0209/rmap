use std::net::IpAddr;

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
}

impl std::fmt::Display for PortStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortStatus::Open => write!(f, "open"),
            PortStatus::Closed => write!(f, "closed"),
            PortStatus::Filtered => write!(f, "filtered"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PortResult {
    pub port: u16,
    pub status: PortStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostResult {
    pub ip: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alive: Option<bool>,
    pub ports: Vec<PortResult>,
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub targets: Vec<IpAddr>,
    pub ports: Vec<u16>,
    pub concurrency: usize,
    pub timeout_ms: u64,
    /// Skip ICMP sweep and scan all targets directly
    pub skip_icmp: bool,
    /// Skip port scan (ICMP-only mode)
    pub skip_ports: bool,
    pub open_only: bool,
    /// Run service/version detection on open ports
    pub detect_services: bool,
}
