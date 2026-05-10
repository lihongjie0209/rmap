//! Service and version detection using nmap-service-probes data.
//!
//! Two-phase detection:
//!   1. Passive: wait briefly for the server to send a banner (SSH, FTP, SMTP…)
//!   2. Active:  send a probe payload (e.g. `GET / HTTP/1.0\r\n\r\n`) then read the response
//!
//! Matching uses the compiled fancy-regex patterns from the nmap probe file.
//! Patterns that fail to compile (rare PCRE-only constructs) are silently skipped.

use std::time::Duration;

use fancy_regex::Regex;
use once_cell::sync::Lazy;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

// Embed the nmap-service-probes file at compile time.
static PROBES_RAW: &str = include_str!("probes.txt");

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

struct MatchRule {
    service: String,
    pattern: Regex,
    /// Template for product+version string, using $1 $2 … placeholders.
    version_template: Option<String>,
}

struct ServiceProbe {
    /// Probe name (e.g. "NULL", "GetRequest")
    #[allow(dead_code)]
    name: String,
    /// Raw bytes to send (empty for the NULL probe)
    probe_bytes: Vec<u8>,
    /// Ports this probe is recommended for
    ports: Vec<u16>,
    match_rules: Vec<MatchRule>,
}

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

static DETECTOR: Lazy<ServiceDetector> = Lazy::new(|| {
    ServiceDetector::new(PROBES_RAW)
});

pub struct ServiceDetector {
    probes: Vec<ServiceProbe>,
}

impl ServiceDetector {
    fn new(raw: &str) -> Self {
        Self { probes: parse_probes(raw) }
    }

    pub fn global() -> &'static ServiceDetector {
        &DETECTOR
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Detect the service running on an already-open `TcpStream`.
///
/// Returns `(service_name, version_string)`.
pub async fn detect_service(
    stream: TcpStream,
    port: u16,
    det_timeout: Duration,
) -> (Option<String>, Option<String>) {
    let detector = ServiceDetector::global();
    detect_with(stream, port, det_timeout, detector).await
}

async fn detect_with(
    mut stream: TcpStream,
    port: u16,
    det_timeout: Duration,
    detector: &ServiceDetector,
) -> (Option<String>, Option<String>) {
    // -- Phase 1: passive banner ------------------------------------------
    // Some services (SSH, FTP, SMTP) immediately send a banner on connect.
    let passive_dur = det_timeout.min(Duration::from_millis(1500));
    let banner = read_banner(&mut stream, passive_dur).await;

    // Try to match the passive banner against the NULL probe rules.
    if let Some(ref b) = banner {
        if let Some(result) = try_match_probes(b, port, &detector.probes, true) {
            return result;
        }
    }

    // -- Phase 2: active probe -------------------------------------------
    // Find the best probe for this port (skip the NULL probe = index 0).
    let probe_bytes = find_probe_bytes(port, &detector.probes);
    if probe_bytes.is_empty() {
        // No active probe available; return any passive partial match.
        return (None, None);
    }

    // Send probe, read response.
    let active_timeout = det_timeout.min(Duration::from_millis(2000));
    if timeout(active_timeout, stream.write_all(&probe_bytes)).await.is_err() {
        return (None, None);
    }
    let response = read_banner(&mut stream, active_timeout).await;

    if let Some(ref r) = response {
        if let Some(result) = try_match_probes(r, port, &detector.probes, false) {
            return result;
        }
    }

    (None, None)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read up to 4 KiB from the stream, stopping at timeout or EOF.
async fn read_banner(stream: &mut TcpStream, dur: Duration) -> Option<String> {
    let mut buf = vec![0u8; 4096];
    match timeout(dur, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => Some(String::from_utf8_lossy(&buf[..n]).into_owned()),
        _ => None,
    }
}

/// Walk the probe list and try each rule against `data` for `port`.
/// If `null_only` is true, only the NULL probe is tried (for passive banners).
fn try_match_probes(
    data: &str,
    port: u16,
    probes: &[ServiceProbe],
    null_only: bool,
) -> Option<(Option<String>, Option<String>)> {
    for probe in probes {
        // Respect null_only: the NULL probe has empty probe_bytes.
        if null_only && !probe.probe_bytes.is_empty() {
            continue;
        }
        // For active probes, only use probes applicable to this port.
        if !null_only && !probe.probe_bytes.is_empty() && !probe.ports.contains(&port) {
            continue;
        }
        for rule in &probe.match_rules {
            if let Ok(Some(caps)) = rule.pattern.captures(data) {
                let version = rule.version_template.as_ref().map(|tpl| {
                    apply_version_template(tpl, &caps)
                });
                return Some((Some(rule.service.clone()), version));
            }
        }
    }
    None
}

/// Find probe bytes for the given port; return empty vec if only NULL applies.
fn find_probe_bytes(port: u16, probes: &[ServiceProbe]) -> Vec<u8> {
    for probe in probes {
        if probe.probe_bytes.is_empty() {
            continue; // skip NULL probe
        }
        if probe.ports.contains(&port) {
            return probe.probe_bytes.clone();
        }
    }
    // Fall back to GetRequest if no specific probe matched
    for probe in probes {
        if probe.name == "GetRequest" {
            return probe.probe_bytes.clone();
        }
    }
    vec![]
}

/// Replace `$1`, `$2`, … in `template` with regex capture groups.
fn apply_version_template(template: &str, caps: &fancy_regex::Captures) -> String {
    let mut out = template.to_owned();
    // Replace from highest index to lowest to avoid clobbering multi-digit refs.
    for i in (1..caps.len()).rev() {
        let placeholder = format!("${}", i);
        let replacement = caps.get(i).map_or("", |m| m.as_str());
        out = out.replace(&placeholder, replacement);
    }
    out.trim().to_owned()
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

fn parse_probes(raw: &str) -> Vec<ServiceProbe> {
    let mut probes: Vec<ServiceProbe> = Vec::new();
    let mut current: Option<ServiceProbe> = None;

    for line in raw.lines() {
        let line = line.trim_end();

        if line.starts_with('#') || line.is_empty() {
            continue;
        }

        if line.starts_with("Probe ") {
            // Save previous probe.
            if let Some(p) = current.take() {
                probes.push(p);
            }
            // Parse: Probe TCP <name> q|<payload>|
            if let Some(p) = parse_probe_header(line) {
                current = Some(p);
            }
            continue;
        }

        let Some(probe) = current.as_mut() else { continue };

        if let Some(ports_str) = line.strip_prefix("ports ") {
            probe.ports = parse_port_list(ports_str);
        } else if line.starts_with("match ") || line.starts_with("softmatch ") {
            let rest = if line.starts_with("softmatch ") {
                &line["softmatch ".len()..]
            } else {
                &line["match ".len()..]
            };
            if let Some(rule) = parse_match_rule(rest) {
                probe.match_rules.push(rule);
            }
        }
        // Ignore: rarity, totalwaitms, tcpwrappedms, fallback, sslports, etc.
    }
    if let Some(p) = current {
        probes.push(p);
    }

    probes
}

/// Parse `Probe TCP NULL q||` or `Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|`
fn parse_probe_header(line: &str) -> Option<ServiceProbe> {
    // Format: Probe <proto> <name> q<delim><payload><delim>
    let rest = line.strip_prefix("Probe ")?;
    // Skip protocol (TCP/UDP)
    let rest = if rest.starts_with("TCP ") { &rest[4..] } else if rest.starts_with("UDP ") { &rest[4..] } else { rest };
    // Extract name (up to first space)
    let (name, rest) = rest.split_once(' ')?;
    let rest = rest.trim_start();
    // q<delim>...<delim>
    let rest = rest.strip_prefix('q')?;
    let delim = rest.chars().next()?;
    let inner = &rest[delim.len_utf8()..];
    let end = inner.find(delim)?;
    let payload_raw = &inner[..end];
    let probe_bytes = decode_escape(payload_raw.as_bytes());

    Some(ServiceProbe {
        name: name.to_owned(),
        probe_bytes,
        ports: vec![],
        match_rules: vec![],
    })
}

/// Parse `<service> m<delim><pattern><delim>[flags] [v|...|] [p|...|] …`
fn parse_match_rule(rest: &str) -> Option<MatchRule> {
    // service name
    let (service, rest) = rest.split_once(' ')?;
    let rest = rest.trim_start();
    // pattern starts with m<delim>
    if !rest.starts_with('m') {
        return None;
    }
    let rest = &rest[1..];
    let delim = rest.chars().next()?;
    let inner = &rest[delim.len_utf8()..];
    // Find closing delimiter (not preceded by backslash)
    let end = find_close_delim(inner, delim)?;
    let pattern_raw = &inner[..end];
    let rest = &inner[end + delim.len_utf8()..];

    // Flags: optional letters (s, i, m, x) immediately after closing delimiter
    let mut case_insensitive = false;
    let mut dot_all = false;
    let mut rest = rest;
    for ch in rest.chars() {
        if ch == 'i' { case_insensitive = true; }
        else if ch == 's' { dot_all = true; }
        else if ch == 'm' || ch == 'x' { /* unsupported, ignore */ }
        else { break; }
        rest = &rest[ch.len_utf8()..];
    }

    // Build regex string with inline flags.
    let mut regex_str = String::from("(?");
    if case_insensitive { regex_str.push('i'); }
    if dot_all { regex_str.push('s'); }
    regex_str.push(')');
    // If no flags were specified, drop the empty group.
    if regex_str == "(?)" {
        regex_str.clear();
    }
    regex_str.push_str(pattern_raw);

    let pattern = match Regex::new(&regex_str) {
        Ok(r) => r,
        Err(_) => return None, // skip incompatible patterns
    };

    // Parse optional version fields: v|…| p|…| i|…|
    let version_template = extract_version_template(rest);

    Some(MatchRule {
        service: service.to_owned(),
        pattern,
        version_template,
    })
}

/// Find the position of the closing delimiter character, respecting `\<delim>` escapes.
fn find_close_delim(s: &str, delim: char) -> Option<usize> {
    let bytes = s.as_bytes();
    let d = delim as u8; // delimiter is always ASCII in nmap probes
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2; // skip escaped char
        } else if bytes[i] == d {
            return Some(i);
        } else {
            i += 1;
        }
    }
    None
}

/// Extract version string from remaining match line fields (v|…|, p|…|, etc.).
/// We combine product (`p`) + version (`v`) into one string.
fn extract_version_template(rest: &str) -> Option<String> {
    let mut product = None::<String>;
    let mut version = None::<String>;
    let mut s = rest.trim_start();
    while !s.is_empty() {
        let Some(key) = s.chars().next() else { break };
        let field = &s[key.len_utf8()..];
        if field.starts_with('|') {
            let inner = &field[1..];
            let end = find_close_delim(inner, '|')?;
            let val = inner[..end].to_owned();
            s = &inner[end + 1..].trim_start();
            match key {
                'p' => product = Some(val),
                'v' => version = Some(val),
                _ => {} // i, h, o, d — ignore
            }
        } else {
            break;
        }
    }
    match (product, version) {
        (Some(p), Some(v)) if !v.is_empty() => Some(format!("{} {}", p, v)),
        (Some(p), _) => Some(p),
        (None, Some(v)) => Some(v),
        _ => None,
    }
}

/// Parse comma/range port list: "22,80,443,8000-8100"
fn parse_port_list(s: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if let Some((a, b)) = part.split_once('-') {
            if let (Ok(lo), Ok(hi)) = (a.parse::<u16>(), b.parse::<u16>()) {
                for p in lo..=hi {
                    ports.push(p);
                }
            }
        } else if let Ok(p) = part.parse::<u16>() {
            ports.push(p);
        }
    }
    ports
}

/// Decode nmap probe string escapes: \r \n \t \0 \xNN \\
fn decode_escape(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'\\' && i + 1 < raw.len() {
            match raw[i + 1] {
                b'r' => { out.push(b'\r'); i += 2; }
                b'n' => { out.push(b'\n'); i += 2; }
                b't' => { out.push(b'\t'); i += 2; }
                b'0' => { out.push(0u8); i += 2; }
                b'\\' => { out.push(b'\\'); i += 2; }
                b'x' if i + 3 < raw.len() => {
                    let hi = raw[i + 2];
                    let lo = raw[i + 3];
                    if let (Some(h), Some(l)) = (from_hex(hi), from_hex(lo)) {
                        out.push(h << 4 | l);
                        i += 4;
                    } else {
                        out.push(raw[i]);
                        i += 1;
                    }
                }
                other => { out.push(other); i += 2; }
            }
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    out
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
