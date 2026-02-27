use crate::parser::{LogEntry, LogLevel};
use serde::Serialize;
use std::collections::HashMap;

/// A count + percentage pair, used for level breakdowns
#[derive(Debug, Clone, Serialize)]
pub struct LevelCount {
    pub count: usize,
    pub percentage: f64,
}

/// Statistics for a single ranked item (IP or endpoint)
#[derive(Debug, Clone, Serialize)]
pub struct RankedItem {
    pub value: String,
    pub count: usize,
    pub percentage: f64,
}

/// An IP that exceeded the error threshold
#[derive(Debug, Clone, Serialize)]
pub struct FlaggedIp {
    pub ip: String,
    pub error_count: usize,
    pub total_requests: usize,
    pub error_rate: f64,
}

/// The complete analysis output
#[derive(Debug, Serialize)]
pub struct AnalysisStats {
    pub total_entries: usize,
    pub malformed_entries: usize,
    pub level_counts: HashMap<String, LevelCount>,
    pub top_ips: Vec<RankedItem>,
    pub top_endpoints: Vec<RankedItem>,
    pub flagged_ips: Vec<FlaggedIp>,
    pub status_code_distribution: HashMap<String, usize>,
    pub error_threshold: usize,
    pub top_n: usize,
}

/// Analyze a slice of log entries and return aggregated statistics.
pub fn analyze(entries: &[LogEntry], top_n: usize, error_threshold: usize) -> AnalysisStats {
    let total = entries.len();

    // ── Level counts ─────────────────────────────────────────────────────────
    let mut info_count = 0usize;
    let mut warn_count = 0usize;
    let mut error_count = 0usize;

    // ── IP tracking ──────────────────────────────────────────────────────────
    // ip → (total_requests, error_requests)
    let mut ip_totals: HashMap<&str, usize> = HashMap::new();
    let mut ip_errors: HashMap<&str, usize> = HashMap::new();

    // ── Endpoint frequency ───────────────────────────────────────────────────
    let mut endpoint_counts: HashMap<&str, usize> = HashMap::new();

    // ── Status code distribution ─────────────────────────────────────────────
    let mut status_counts: HashMap<u16, usize> = HashMap::new();

    for entry in entries {
        match entry.level {
            LogLevel::Info => info_count += 1,
            LogLevel::Warn => warn_count += 1,
            LogLevel::Error => {
                error_count += 1;
                *ip_errors.entry(entry.ip.as_str()).or_insert(0) += 1;
            }
        }

        *ip_totals.entry(entry.ip.as_str()).or_insert(0) += 1;
        *endpoint_counts.entry(entry.endpoint.as_str()).or_insert(0) += 1;
        *status_counts.entry(entry.status_code).or_insert(0) += 1;
    }

    let pct = |n: usize| -> f64 {
        if total == 0 {
            0.0
        } else {
            (n as f64 / total as f64) * 100.0
        }
    };

    let mut level_counts = HashMap::new();
    level_counts.insert(
        "INFO".to_string(),
        LevelCount { count: info_count, percentage: pct(info_count) },
    );
    level_counts.insert(
        "WARN".to_string(),
        LevelCount { count: warn_count, percentage: pct(warn_count) },
    );
    level_counts.insert(
        "ERROR".to_string(),
        LevelCount { count: error_count, percentage: pct(error_count) },
    );

    // ── Top N IPs ────────────────────────────────────────────────────────────
    let mut ip_vec: Vec<(&str, usize)> = ip_totals.iter().map(|(&k, &v)| (k, v)).collect();
    ip_vec.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let top_ips = ip_vec
        .iter()
        .take(top_n)
        .map(|(ip, count)| RankedItem {
            value: ip.to_string(),
            count: *count,
            percentage: pct(*count),
        })
        .collect();

    // ── Top N Endpoints ───────────────────────────────────────────────────────
    let mut ep_vec: Vec<(&str, usize)> =
        endpoint_counts.iter().map(|(&k, &v)| (k, v)).collect();
    ep_vec.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let top_endpoints = ep_vec
        .iter()
        .take(top_n)
        .map(|(ep, count)| RankedItem {
            value: ep.to_string(),
            count: *count,
            percentage: pct(*count),
        })
        .collect();

    // ── Flagged IPs ───────────────────────────────────────────────────────────
    let mut flagged: Vec<FlaggedIp> = ip_errors
        .iter()
        .filter(|(_, &err)| err > error_threshold)
        .map(|(&ip, &err)| {
            let total_req = *ip_totals.get(ip).unwrap_or(&0);
            let error_rate = if total_req == 0 {
                0.0
            } else {
                (err as f64 / total_req as f64) * 100.0
            };
            FlaggedIp {
                ip: ip.to_string(),
                error_count: err,
                total_requests: total_req,
                error_rate,
            }
        })
        .collect();
    flagged.sort_unstable_by(|a, b| b.error_count.cmp(&a.error_count).then(a.ip.cmp(&b.ip)));

    // ── Status code distribution ──────────────────────────────────────────────
    let status_code_distribution: HashMap<String, usize> = status_counts
        .into_iter()
        .map(|(code, count)| (code.to_string(), count))
        .collect();

    AnalysisStats {
        total_entries: total,
        malformed_entries: 0, // filled in by main after parsing
        level_counts,
        top_ips,
        top_endpoints,
        flagged_ips: flagged,
        status_code_distribution,
        error_threshold,
        top_n,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{HttpMethod, LogLevel};

    fn make_entry(ip: &str, level: LogLevel, endpoint: &str, status: u16) -> LogEntry {
        LogEntry {
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            level,
            ip: ip.to_string(),
            method: HttpMethod::Get,
            endpoint: endpoint.to_string(),
            status_code: status,
        }
    }

    #[test]
    fn counts_levels_correctly() {
        let entries = vec![
            make_entry("1.1.1.1", LogLevel::Info, "/a", 200),
            make_entry("1.1.1.1", LogLevel::Info, "/b", 200),
            make_entry("1.1.1.2", LogLevel::Warn, "/a", 429),
            make_entry("1.1.1.3", LogLevel::Error, "/c", 500),
        ];
        let stats = analyze(&entries, 5, 3);
        assert_eq!(stats.total_entries, 4);
        assert_eq!(stats.level_counts["INFO"].count, 2);
        assert_eq!(stats.level_counts["WARN"].count, 1);
        assert_eq!(stats.level_counts["ERROR"].count, 1);
    }

    #[test]
    fn top_ips_sorted_by_count() {
        let entries = vec![
            make_entry("1.1.1.1", LogLevel::Info, "/", 200),
            make_entry("1.1.1.1", LogLevel::Info, "/", 200),
            make_entry("1.1.1.2", LogLevel::Info, "/", 200),
            make_entry("1.1.1.1", LogLevel::Info, "/", 200),
        ];
        let stats = analyze(&entries, 5, 3);
        assert_eq!(stats.top_ips[0].value, "1.1.1.1");
        assert_eq!(stats.top_ips[0].count, 3);
        assert_eq!(stats.top_ips[1].value, "1.1.1.2");
    }

    #[test]
    fn flags_ips_exceeding_error_threshold() {
        let mut entries = vec![];
        for _ in 0..6 {
            entries.push(make_entry("9.9.9.9", LogLevel::Error, "/bad", 500));
        }
        entries.push(make_entry("1.1.1.1", LogLevel::Error, "/bad", 500)); // only 1 error

        let stats = analyze(&entries, 5, 5);
        assert_eq!(stats.flagged_ips.len(), 1);
        assert_eq!(stats.flagged_ips[0].ip, "9.9.9.9");
        assert_eq!(stats.flagged_ips[0].error_count, 6);
    }

    #[test]
    fn empty_entries_returns_zero_stats() {
        let stats = analyze(&[], 5, 3);
        assert_eq!(stats.total_entries, 0);
        assert!(stats.top_ips.is_empty());
        assert!(stats.flagged_ips.is_empty());
    }
}
