mod analyzer;
mod parser;
mod report;

use clap::Parser;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

/// A high-performance CLI tool for analyzing structured web server logs
#[derive(Parser, Debug)]
#[command(
    name = "log_analyzer",
    author,
    version,
    about = "Analyzes structured web server logs and generates aggregated insights"
)]
struct Args {
    /// Path to the log file to analyze
    #[arg(value_name = "LOG_FILE")]
    file: PathBuf,

    /// Number of top IPs and endpoints to display
    #[arg(short = 'n', long = "top", default_value_t = 10, value_name = "N")]
    top_n: usize,

    /// Error count threshold — IPs exceeding this will be flagged
    #[arg(short = 'e', long = "error-threshold", default_value_t = 5, value_name = "COUNT")]
    error_threshold: usize,

    /// Export results as JSON to the specified file path
    #[arg(short = 'j', long = "json-output", value_name = "OUTPUT_FILE")]
    json_output: Option<PathBuf>,

    /// Suppress warnings for malformed log lines
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,
}

fn main() {
    let args = Args::parse();

    // Open the log file
    let file = match File::open(&args.file) {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "error: could not open file '{}': {}",
                args.file.display(),
                e
            );
            std::process::exit(1);
        }
    };

    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    let mut malformed_count = 0usize;

    // Stream through file line-by-line for memory efficiency
    for (line_num, line_result) in reader.lines().enumerate() {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                if !args.quiet {
                    eprintln!("warning: could not read line {}: {}", line_num + 1, e);
                }
                malformed_count += 1;
                continue;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        match parser::parse_log_line(&line) {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                malformed_count += 1;
                if !args.quiet {
                    eprintln!(
                        "warning: malformed line {} — {}: {:?}",
                        line_num + 1,
                        e,
                        &line[..line.len().min(80)]
                    );
                }
            }
        }
    }

    if entries.is_empty() {
        eprintln!("error: no valid log entries found in '{}'", args.file.display());
        std::process::exit(1);
    }

    // Analyze parsed entries
    let stats = analyzer::analyze(&entries, args.top_n, args.error_threshold);

    // Print terminal report
    report::print_report(&stats, malformed_count, &args.file);

    // Optionally export JSON
    if let Some(json_path) = &args.json_output {
        match report::export_json(&stats, json_path) {
            Ok(_) => println!("\n✓ JSON report saved to '{}'", json_path.display()),
            Err(e) => {
                eprintln!("error: failed to write JSON output: {}", e);
                std::process::exit(1);
            }
        }
    }
}
