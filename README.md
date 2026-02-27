# log_analyzer

A high-performance CLI tool for analyzing structured web server logs. Processes large files memory-efficiently using line-by-line streaming and produces both a rich terminal report and optional JSON export.

---

## Features

- Parses structured log lines with regex into typed fields
- Aggregates: total entries, level counts, top IPs, top endpoints, status code distribution
- Flags IPs exceeding a configurable error threshold
- Colorized, tabular terminal output with progress bars
- Optional JSON export via `--json-output`
- Memory-efficient streaming — handles arbitrarily large files
- Graceful handling of malformed lines (counts and reports them)

---

## Log Format

Each log line must follow this format:

```
TIMESTAMP [LEVEL] IP_ADDRESS HTTP_METHOD ENDPOINT STATUS_CODE
```

**Example lines:**

```
2024-01-15T10:30:00Z [INFO]  192.168.1.1 GET    /api/users  200
2024-01-15T10:30:01Z [WARN]  10.0.0.5    POST   /upload     429
2024-01-15T10:30:02Z [ERROR] 172.16.0.1  DELETE /resource   500
```

| Field        | Description                                      |
|--------------|--------------------------------------------------|
| `TIMESTAMP`  | Any non-whitespace token (ISO 8601 recommended)  |
| `LEVEL`      | One of `INFO`, `WARN`, `ERROR`                   |
| `IP_ADDRESS` | IPv4 address (`x.x.x.x`)                         |
| `HTTP_METHOD`| `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, etc.    |
| `ENDPOINT`   | URL path (no spaces)                             |
| `STATUS_CODE`| 3-digit HTTP status code                         |

---

## Installation

```bash
# Clone and build
git clone <repo>
cd log_analyzer
cargo build --release

# Binary will be at:
./target/release/log_analyzer
```

---

## Usage

```
log_analyzer [OPTIONS] <LOG_FILE>

Arguments:
  <LOG_FILE>  Path to the log file to analyze

Options:
  -n, --top <N>                  Number of top IPs/endpoints to show [default: 10]
  -e, --error-threshold <COUNT>  Flag IPs with more than this many errors [default: 5]
  -j, --json-output <FILE>       Export results as JSON to this path
  -q, --quiet                    Suppress malformed line warnings
  -h, --help                     Print help
  -V, --version                  Print version
```

### Examples

```bash
# Basic analysis
log_analyzer access.log

# Show top 20 IPs/endpoints, flag IPs with >10 errors
log_analyzer access.log --top 20 --error-threshold 10

# Export to JSON, suppress warnings
log_analyzer access.log --json-output report.json --quiet

# Use the included sample log
log_analyzer sample.log
```

---

## Running Tests

```bash
cargo test
```

Tests cover:

- `parser.rs`: valid lines, all HTTP methods, all log levels, edge cases (malformed IPs, bad levels, empty input, trailing whitespace)
- `analyzer.rs`: level counting, top-N sorting, error flagging, empty input handling

---

## Project Structure

```
log_analyzer/
├── Cargo.toml
├── sample.log          ← Sample log file for testing
├── README.md
└── src/
    ├── main.rs         ← CLI argument parsing, file streaming, orchestration
    ├── parser.rs       ← Log line parsing, LogEntry, LogLevel, HttpMethod types
    ├── analyzer.rs     ← Statistics aggregation (AnalysisStats)
    └── report.rs       ← Terminal report rendering + JSON export
```

---

## JSON Output Schema

```json
{
  "total_entries": 29,
  "malformed_entries": 0,
  "level_counts": {
    "INFO":  { "count": 18, "percentage": 62.1 },
    "WARN":  { "count": 3,  "percentage": 10.3 },
    "ERROR": { "count": 8,  "percentage": 27.6 }
  },
  "top_ips": [
    { "value": "192.168.1.1", "count": 7, "percentage": 24.1 }
  ],
  "top_endpoints": [
    { "value": "/api/users", "count": 6, "percentage": 20.7 }
  ],
  "flagged_ips": [
    {
      "ip": "10.0.0.5",
      "error_count": 8,
      "total_requests": 9,
      "error_rate": 88.9
    }
  ],
  "status_code_distribution": {
    "200": 18, "500": 7, "429": 1
  },
  "error_threshold": 5,
  "top_n": 10
}
```

---

## Dependencies

| Crate         | Purpose                              |
|---------------|--------------------------------------|
| `clap`        | CLI argument parsing (derive macros) |
| `regex`       | Log line pattern matching            |
| `serde`       | Serialization traits                 |
| `serde_json`  | JSON export                          |
| `colored`     | Terminal color output                |
| `chrono`      | Timestamp type (via serde feature)   |
| `thiserror`   | Ergonomic error type definitions     |
