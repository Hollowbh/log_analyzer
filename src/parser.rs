use regex::Regex;
use std::fmt;
use std::sync::OnceLock;

/// Represents a single parsed log entry
#[derive(Debug, Clone, PartialEq)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: LogLevel,
    pub ip: String,
    pub method: HttpMethod,
    pub endpoint: String,
    pub status_code: u16,
}

/// Log severity levels
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warn => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
        }
    }
}

/// HTTP methods
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Other(String),
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Put => write!(f, "PUT"),
            HttpMethod::Delete => write!(f, "DELETE"),
            HttpMethod::Patch => write!(f, "PATCH"),
            HttpMethod::Head => write!(f, "HEAD"),
            HttpMethod::Options => write!(f, "OPTIONS"),
            HttpMethod::Other(s) => write!(f, "{}", s),
        }
    }
}

/// Errors that can occur during log parsing
#[derive(Debug)]
pub enum ParseError {
    /// The line doesn't match the expected log format
    InvalidFormat(String),
    /// A field was present but couldn't be converted
    InvalidField { field: &'static str, value: String },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::InvalidFormat(msg) => write!(f, "invalid format: {}", msg),
            ParseError::InvalidField { field, value } => {
                write!(f, "invalid value for field '{}': '{}'", field, value)
            }
        }
    }
}

/// Expected log format:
///   TIMESTAMP [LEVEL] IP METHOD ENDPOINT STATUS_CODE
///
/// Example:
///   2024-01-15T10:30:00Z [INFO] 192.168.1.1 GET /api/users 200
///   2024-01-15T10:30:01Z [ERROR] 10.0.0.5 POST /login 500
static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_regex() -> &'static Regex {
    LOG_REGEX.get_or_init(|| {
        Regex::new(
            r#"^(?P<timestamp>\S+)\s+\[(?P<level>INFO|WARN|ERROR)\]\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?P<method>[A-Z]+)\s+(?P<endpoint>\S+)\s+(?P<status>\d{3})\s*$"#,
        )
        .expect("hard-coded regex should always compile")
    })
}

/// Parse a single log line into a structured `LogEntry`.
///
/// Returns `Err(ParseError)` if the line is malformed or contains invalid field values.
pub fn parse_log_line(line: &str) -> Result<LogEntry, ParseError> {
    let re = get_regex();

    let caps = re.captures(line.trim()).ok_or_else(|| {
        ParseError::InvalidFormat(format!(
            "line does not match expected pattern: {:?}",
            &line[..line.len().min(100)]
        ))
    })?;

    let timestamp = caps["timestamp"].to_string();
    let ip = caps["ip"].to_string();
    let endpoint = caps["endpoint"].to_string();

    let level = parse_level(&caps["level"])?;
    let method = parse_method(&caps["method"]);

    let status_str = &caps["status"];
    let status_code = status_str.parse::<u16>().map_err(|_| ParseError::InvalidField {
        field: "status_code",
        value: status_str.to_string(),
    })?;

    Ok(LogEntry {
        timestamp,
        level,
        ip,
        method,
        endpoint,
        status_code,
    })
}

fn parse_level(s: &str) -> Result<LogLevel, ParseError> {
    match s {
        "INFO" => Ok(LogLevel::Info),
        "WARN" => Ok(LogLevel::Warn),
        "ERROR" => Ok(LogLevel::Error),
        other => Err(ParseError::InvalidField {
            field: "level",
            value: other.to_string(),
        }),
    }
}

fn parse_method(s: &str) -> HttpMethod {
    match s {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "DELETE" => HttpMethod::Delete,
        "PATCH" => HttpMethod::Patch,
        "HEAD" => HttpMethod::Head,
        "OPTIONS" => HttpMethod::Options,
        other => HttpMethod::Other(other.to_string()),
    }
}

// ─── Unit Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_line() -> &'static str {
        "2024-01-15T10:30:00Z [INFO] 192.168.1.1 GET /api/users 200"
    }

    #[test]
    fn parses_valid_line() {
        let entry = parse_log_line(valid_line()).expect("should parse valid line");
        assert_eq!(entry.timestamp, "2024-01-15T10:30:00Z");
        assert_eq!(entry.level, LogLevel::Info);
        assert_eq!(entry.ip, "192.168.1.1");
        assert_eq!(entry.method, HttpMethod::Get);
        assert_eq!(entry.endpoint, "/api/users");
        assert_eq!(entry.status_code, 200);
    }

    #[test]
    fn parses_warn_level() {
        let line = "2024-01-15T10:30:01Z [WARN] 10.0.0.2 POST /upload 429";
        let entry = parse_log_line(line).unwrap();
        assert_eq!(entry.level, LogLevel::Warn);
        assert_eq!(entry.method, HttpMethod::Post);
        assert_eq!(entry.status_code, 429);
    }

    #[test]
    fn parses_error_level() {
        let line = "2024-01-15T10:30:02Z [ERROR] 172.16.0.1 DELETE /resource/42 500";
        let entry = parse_log_line(line).unwrap();
        assert_eq!(entry.level, LogLevel::Error);
        assert_eq!(entry.method, HttpMethod::Delete);
        assert_eq!(entry.status_code, 500);
    }

    #[test]
    fn parses_all_http_methods() {
        let methods = vec![
            ("GET", HttpMethod::Get),
            ("POST", HttpMethod::Post),
            ("PUT", HttpMethod::Put),
            ("DELETE", HttpMethod::Delete),
            ("PATCH", HttpMethod::Patch),
            ("HEAD", HttpMethod::Head),
            ("OPTIONS", HttpMethod::Options),
        ];
        for (method_str, expected) in methods {
            let line = format!("2024-01-15T10:30:00Z [INFO] 1.2.3.4 {} /path 200", method_str);
            let entry = parse_log_line(&line).unwrap();
            assert_eq!(entry.method, expected, "failed for method {}", method_str);
        }
    }

    #[test]
    fn rejects_missing_fields() {
        let incomplete = "2024-01-15T10:30:00Z [INFO] 192.168.1.1 GET";
        assert!(parse_log_line(incomplete).is_err());
    }

    #[test]
    fn rejects_invalid_level() {
        let bad_level = "2024-01-15T10:30:00Z [DEBUG] 192.168.1.1 GET /path 200";
        assert!(parse_log_line(bad_level).is_err());
    }

    #[test]
    fn rejects_malformed_ip() {
        let bad_ip = "2024-01-15T10:30:00Z [INFO] not_an_ip GET /path 200";
        assert!(parse_log_line(bad_ip).is_err());
    }

    #[test]
    fn rejects_empty_line() {
        assert!(parse_log_line("").is_err());
        assert!(parse_log_line("   ").is_err());
    }

    #[test]
    fn rejects_non_numeric_status() {
        // The regex only matches 3 digits so this won't match
        let bad_status = "2024-01-15T10:30:00Z [INFO] 1.2.3.4 GET /path abc";
        assert!(parse_log_line(bad_status).is_err());
    }

    #[test]
    fn handles_trailing_whitespace() {
        let line_with_spaces = "2024-01-15T10:30:00Z [INFO] 192.168.1.1 GET /api/users 200   ";
        // Trailing spaces after status: regex has \s*$ so this should still parse
        let entry = parse_log_line(line_with_spaces).expect("should handle trailing whitespace");
        assert_eq!(entry.status_code, 200);
    }

    #[test]
    fn log_level_display() {
        assert_eq!(LogLevel::Info.to_string(), "INFO");
        assert_eq!(LogLevel::Warn.to_string(), "WARN");
        assert_eq!(LogLevel::Error.to_string(), "ERROR");
    }

    #[test]
    fn http_method_display() {
        assert_eq!(HttpMethod::Get.to_string(), "GET");
        assert_eq!(HttpMethod::Other("TRACE".into()).to_string(), "TRACE");
    }
}
