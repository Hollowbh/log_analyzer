use crate::analyzer::AnalysisStats;
use colored::Colorize;
use serde_json;
use std::io;
use std::path::PathBuf;

const SEPARATOR: &str =
    "════════════════════════════════════════════════════════════════════";
const THIN_SEP: &str =
    "────────────────────────────────────────────────────────────────────";

/// Print a fully formatted analysis report to stdout
pub fn print_report(stats: &AnalysisStats, malformed: usize, source_file: &PathBuf) {
    println!("\n{}", SEPARATOR.cyan().bold());
    println!(
        "{}",
        "  📋  LOG ANALYSIS REPORT".white().bold()
    );
    println!("{}", SEPARATOR.cyan().bold());
    println!("  Source : {}", source_file.display().to_string().yellow());
    println!();

    // ── Overview ──────────────────────────────────────────────────────────────
    section_header("OVERVIEW");
    let total_width = stats.total_entries.to_string().len().max(6);
    println!(
        "  {:<28} {:>width$}",
        "Total entries parsed:",
        stats.total_entries.to_string().green().bold(),
        width = total_width
    );
    println!(
        "  {:<28} {:>width$}",
        "Malformed / skipped lines:",
        if malformed > 0 {
            malformed.to_string().yellow().bold()
        } else {
            "0".normal()
        },
        width = total_width
    );
    println!();

    // ── Log Level Breakdown ───────────────────────────────────────────────────
    section_header("LOG LEVEL BREAKDOWN");
    for level_name in &["INFO", "WARN", "ERROR"] {
        if let Some(lc) = stats.level_counts.get(*level_name) {
            let bar = mini_bar(lc.percentage, 30);
            let colored_level = match *level_name {
                "INFO" => level_name.green(),
                "WARN" => level_name.yellow(),
                "ERROR" => level_name.red(),
                _ => level_name.normal(),
            };
            println!(
                "  {:<6} {:>6}  ({:5.1}%)  {}",
                colored_level,
                lc.count,
                lc.percentage,
                bar
            );
        }
    }
    println!();

    // ── Status Code Distribution ──────────────────────────────────────────────
    section_header("STATUS CODE DISTRIBUTION");
    let mut status_vec: Vec<(&String, &usize)> = stats.status_code_distribution.iter().collect();
    status_vec.sort_by_key(|(k, _)| k.parse::<u16>().unwrap_or(0));
    for (code, count) in &status_vec {
        let code_int: u16 = code.parse().unwrap_or(0);
        let pct = (**count as f64 / stats.total_entries as f64) * 100.0;
        let bar = mini_bar(pct, 20);
        let colored_code = color_status(code_int, code);
        println!(
            "  HTTP {}  {:>6}  ({:5.1}%)  {}",
            colored_code, count, pct, bar
        );
    }
    println!();

    // ── Top N IPs ─────────────────────────────────────────────────────────────
    section_header(&format!("TOP {} IP ADDRESSES BY REQUEST COUNT", stats.top_n));
    if stats.top_ips.is_empty() {
        println!("  (no data)");
    } else {
        println!("  {:<3}  {:<17}  {:>8}  {:>8}", "#", "IP Address", "Requests", "Share");
        println!("  {}", &THIN_SEP[..54]);
        for (i, item) in stats.top_ips.iter().enumerate() {
            println!(
                "  {:<3}  {:<17}  {:>8}  {:>7.2}%",
                (i + 1).to_string().dimmed(),
                item.value.cyan(),
                item.count,
                item.percentage
            );
        }
    }
    println!();

    // ── Top N Endpoints ───────────────────────────────────────────────────────
    section_header(&format!("TOP {} ENDPOINTS BY REQUEST FREQUENCY", stats.top_n));
    if stats.top_endpoints.is_empty() {
        println!("  (no data)");
    } else {
        println!("  {:<3}  {:<40}  {:>8}  {:>8}", "#", "Endpoint", "Requests", "Share");
        println!("  {}", &THIN_SEP[..66]);
        for (i, item) in stats.top_endpoints.iter().enumerate() {
            let ep = if item.value.len() > 40 {
                format!("{}…", &item.value[..39])
            } else {
                item.value.clone()
            };
            println!(
                "  {:<3}  {:<40}  {:>8}  {:>7.2}%",
                (i + 1).to_string().dimmed(),
                ep.cyan(),
                item.count,
                item.percentage
            );
        }
    }
    println!();

    // ── Flagged IPs ───────────────────────────────────────────────────────────
    section_header(&format!(
        "FLAGGED IPs — ERROR COUNT > {}",
        stats.error_threshold
    ));
    if stats.flagged_ips.is_empty() {
        println!("  {} No IPs exceeded the error threshold.", "✓".green());
    } else {
        println!(
            "  {} IPs flagged!\n",
            stats.flagged_ips.len().to_string().red().bold()
        );
        println!(
            "  {:<3}  {:<17}  {:>8}  {:>8}  {:>10}",
            "#", "IP Address", "Errors", "Total", "Error Rate"
        );
        println!("  {}", &THIN_SEP[..60]);
        for (i, item) in stats.flagged_ips.iter().enumerate() {
            println!(
                "  {:<3}  {:<17}  {:>8}  {:>8}  {:>9.1}%",
                (i + 1).to_string().dimmed(),
                item.ip.red().bold(),
                item.error_count.to_string().red(),
                item.total_requests,
                item.error_rate
            );
        }
    }

    println!("\n{}\n", SEPARATOR.cyan());
}

/// Export the analysis statistics as JSON to the given path
pub fn export_json(stats: &AnalysisStats, path: &PathBuf) -> Result<(), io::Error> {
    let json = serde_json::to_string_pretty(stats).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("serialization failed: {}", e))
    })?;
    std::fs::write(path, json)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn section_header(title: &str) {
    println!("  {} {}", "▶".cyan(), title.white().bold());
    println!("  {}", THIN_SEP);
}

/// Renders a compact ASCII progress bar of the given width
fn mini_bar(pct: f64, width: usize) -> String {
    let filled = ((pct / 100.0) * width as f64).round() as usize;
    let filled = filled.min(width);
    let empty = width - filled;
    format!(
        "{}{}",
        "█".repeat(filled).green(),
        "░".repeat(empty).dimmed()
    )
}

/// Colorize HTTP status code based on category
fn color_status(code: u16, s: &str) -> colored::ColoredString {
    match code {
        200..=299 => s.green(),
        300..=399 => s.cyan(),
        400..=499 => s.yellow(),
        500..=599 => s.red().bold(),
        _ => s.normal(),
    }
}
