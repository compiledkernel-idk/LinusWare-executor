use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;

const LOG_FILE: &str = "linusware.log";
const MAX_LOG_SIZE: u64 = 10 * 1024 * 1024;
const MAX_MEMORY_LOGS: usize = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
    Fatal = 5,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Trace => write!(f, "TRACE"),
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warn => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
            LogLevel::Fatal => write!(f, "FATAL"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: u64,
    pub level: LogLevel,
    pub module: String,
    pub message: String,
}

impl LogEntry {
    pub fn format(&self) -> String {
        let dt = chrono_lite::format_timestamp(self.timestamp);
        format!("[{}] [{}] [{}] {}", dt, self.level, self.module, self.message)
    }
}

mod chrono_lite {
    pub fn format_timestamp(ts: u64) -> String {
        let secs = ts % 60;
        let mins = (ts / 60) % 60;
        let hours = (ts / 3600) % 24;
        format!("{:02}:{:02}:{:02}", hours, mins, secs)
    }
    
    pub fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

pub struct Logger {
    log_path: PathBuf,
    min_level: LogLevel,
    file_logging: bool,
    console_logging: bool,
    memory_logs: Arc<Mutex<VecDeque<LogEntry>>>,
}

impl Logger {
    pub fn new(base_path: &str) -> Self {
        Self {
            log_path: PathBuf::from(base_path).join(LOG_FILE),
            min_level: LogLevel::Info,
            file_logging: true,
            console_logging: true,
            memory_logs: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    pub fn set_level(&mut self, level: LogLevel) {
        self.min_level = level;
    }

    pub fn set_file_logging(&mut self, enabled: bool) {
        self.file_logging = enabled;
    }

    pub fn set_console_logging(&mut self, enabled: bool) {
        self.console_logging = enabled;
    }

    fn should_log(&self, level: LogLevel) -> bool {
        level >= self.min_level
    }

    pub fn log(&self, level: LogLevel, module: &str, message: &str) {
        if !self.should_log(level) {
            return;
        }

        let entry = LogEntry {
            timestamp: chrono_lite::now(),
            level,
            module: module.to_string(),
            message: message.to_string(),
        };

        let formatted = entry.format();

        if self.console_logging {
            match level {
                LogLevel::Error | LogLevel::Fatal => eprintln!("{}", formatted),
                _ => println!("{}", formatted),
            }
        }

        if self.file_logging {
            self.write_to_file(&formatted);
        }

        if let Ok(mut logs) = self.memory_logs.lock() {
            logs.push_back(entry);
            if logs.len() > MAX_MEMORY_LOGS {
                logs.pop_front();
            }
        }
    }

    fn write_to_file(&self, message: &str) {
        if let Ok(metadata) = fs::metadata(&self.log_path) {
            if metadata.len() > MAX_LOG_SIZE {
                self.rotate_log();
            }
        }

        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
        {
            writeln!(file, "{}", message).ok();
        }
    }

    fn rotate_log(&self) {
        let backup_path = self.log_path.with_extension("log.old");
        fs::rename(&self.log_path, &backup_path).ok();
    }

    pub fn trace(&self, module: &str, message: &str) {
        self.log(LogLevel::Trace, module, message);
    }

    pub fn debug(&self, module: &str, message: &str) {
        self.log(LogLevel::Debug, module, message);
    }

    pub fn info(&self, module: &str, message: &str) {
        self.log(LogLevel::Info, module, message);
    }

    pub fn warn(&self, module: &str, message: &str) {
        self.log(LogLevel::Warn, module, message);
    }

    pub fn error(&self, module: &str, message: &str) {
        self.log(LogLevel::Error, module, message);
    }

    pub fn fatal(&self, module: &str, message: &str) {
        self.log(LogLevel::Fatal, module, message);
    }

    pub fn get_logs(&self) -> Vec<LogEntry> {
        self.memory_logs.lock()
            .map(|logs| logs.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn get_logs_by_level(&self, min_level: LogLevel) -> Vec<LogEntry> {
        self.memory_logs.lock()
            .map(|logs| logs.iter().filter(|e| e.level >= min_level).cloned().collect())
            .unwrap_or_default()
    }

    pub fn clear_logs(&self) {
        if let Ok(mut logs) = self.memory_logs.lock() {
            logs.clear();
        }
    }

    pub fn search_logs(&self, query: &str) -> Vec<LogEntry> {
        let query_lower = query.to_lowercase();
        self.memory_logs.lock()
            .map(|logs| {
                logs.iter()
                    .filter(|e| e.message.to_lowercase().contains(&query_lower) ||
                               e.module.to_lowercase().contains(&query_lower))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Default for Logger {
    fn default() -> Self {
        Self::new(".")
    }
}

static GLOBAL_LOGGER: std::sync::OnceLock<Logger> = std::sync::OnceLock::new();

pub fn init(base_path: &str) {
    GLOBAL_LOGGER.get_or_init(|| Logger::new(base_path));
}

pub fn get_logger() -> &'static Logger {
    GLOBAL_LOGGER.get_or_init(|| Logger::new("."))
}

#[macro_export]
macro_rules! log_trace {
    ($module:expr, $($arg:tt)*) => {
        $crate::logging::get_logger().trace($module, &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_debug {
    ($module:expr, $($arg:tt)*) => {
        $crate::logging::get_logger().debug($module, &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_info {
    ($module:expr, $($arg:tt)*) => {
        $crate::logging::get_logger().info($module, &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_warn {
    ($module:expr, $($arg:tt)*) => {
        $crate::logging::get_logger().warn($module, &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_error {
    ($module:expr, $($arg:tt)*) => {
        $crate::logging::get_logger().error($module, &format!($($arg)*))
    };
}
