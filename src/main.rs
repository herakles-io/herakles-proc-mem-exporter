// herakles-proc-mem-exporter - version 0.1.0
// Professional memory metrics exporter with tracing logging
use ahash::AHashMap as HashMap;
use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Router};
use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};
use once_cell::sync::Lazy;
use prometheus::{Encoder, Gauge, GaugeVec, Opts, Registry, TextEncoder};
use rand::Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt::Write as FmtWrite;
use std::sync::RwLock as StdRwLock;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};
use std::{
    collections::VecDeque,
    fs,
    io::{BufRead, BufReader},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Instant, SystemTime},
};
use tokio::{
    net::TcpListener,
    signal,
    sync::{Notify, RwLock},
    time::{interval, Duration},
};
use tracing::{debug, error, info, instrument, warn, Level};

/// Log level options for CLI parsing
#[derive(Debug, Clone, ValueEnum)]
enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

/// Configuration format options for output
#[derive(Debug, Clone, ValueEnum)]
enum ConfigFormat {
    Yaml,
    Json,
    Toml,
}

/// Main CLI arguments structure
#[derive(Parser, Debug)]
#[command(
    name = "herakles-proc-mem-exporter",
    about = "Prometheus exporter for per-process RSS/PSS/USS and CPU metrics",
    long_about = "Prometheus exporter for per-process RSS/PSS/USS and CPU metrics.\n\n\
                  A high-performance Prometheus exporter for per-process memory and CPU metrics \
                  on Linux systems. Provides detailed RSS, PSS, USS memory metrics and CPU usage \
                  with intelligent process classification.",
    author = "Michael Moll <proc-mem@herakles.io> - Herakles IO",
    version = "0.1.0",
    propagate_version = true,
    after_help = "Project: https://github.com/herakles-io/herakles-proc-mem-exporter — More info: https://www.herakles.io — Support: proc-mem@herakles.io"
)]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,

    /// HTTP listen port
    #[arg(short = 'p', long)]
    port: Option<u16>,

    /// Bind to specific interface/IP
    #[arg(long)]
    bind: Option<IpAddr>,

    /// Log level
    #[arg(long, value_enum, default_value = "info")]
    log_level: LogLevel,

    /// Config file (YAML/JSON/TOML)
    #[arg(short = 'c', long)]
    config: Option<PathBuf>,

    /// Disable all config file loading
    #[arg(long)]
    no_config: bool,

    /// Print effective merged config and exit
    #[arg(long)]
    show_config: bool,

    /// Print only the loaded user config file + full path and exit
    #[arg(long)]
    show_user_config: bool,

    /// Output format for --show-config*
    #[arg(long, value_enum, default_value = "yaml")]
    config_format: ConfigFormat,

    /// Validate config and exit (return code 1 on error)
    #[arg(long)]
    check_config: bool,

    /// Enable /debug/pprof endpoints
    #[arg(long)]
    debug: bool,

    /// Cache metrics for N seconds
    #[arg(long)]
    cache_ttl: Option<u64>,

    /// Disable /health endpoint + health metrics
    #[arg(long)]
    disable_health: bool,

    /// Disable internal exporter_* metrics
    #[arg(long)]
    disable_telemetry: bool,

    /// Disable generic collectors
    #[arg(long)]
    disable_default_collectors: bool,

    /// Override IO buffer size (KB) for generic /proc readers
    #[arg(long)]
    io_buffer_kb: Option<usize>,

    /// Override buffer size (KB) for /proc/<pid>/smaps
    #[arg(long)]
    smaps_buffer_kb: Option<usize>,

    /// Override buffer size (KB) for /proc/<pid>/smaps_rollup
    #[arg(long)]
    smaps_rollup_buffer_kb: Option<usize>,

    /// Minimum USS in KB to include process
    #[arg(long)]
    min_uss_kb: Option<u64>,

    /// Include only processes matching these names (comma-separated)
    #[arg(long)]
    include_names: Option<String>,

    /// Exclude processes matching these names (comma-separated)
    #[arg(long)]
    exclude_names: Option<String>,

    /// Parallel processing threads (0 = auto)
    #[arg(long)]
    parallelism: Option<usize>,

    /// Maximum number of processes to scan
    #[arg(long)]
    max_processes: Option<usize>,
    /// Top-N processes to export per subgroup (override config)
    #[arg(long)]
    top_n_subgroup: Option<usize>,

    /// Top-N processes to export for "other" group (override config)
    #[arg(long)]
    top_n_others: Option<usize>,

    /// Path to JSON test data file (uses synthetic data instead of /proc)
    #[arg(short = 't', long)]
    test_data_file: Option<PathBuf>,
}

/// Subcommands for additional functionality
#[derive(Subcommand, Debug)]
enum Commands {
    /// Validate configuration and system requirements
    Check {
        /// Check memory accessibility
        #[arg(long)]
        memory: bool,

        /// Check /proc filesystem
        #[arg(long)]
        proc: bool,

        /// Check all system requirements
        #[arg(long)]
        all: bool,
    },

    /// Generate configuration files
    Config {
        /// Output file path
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,

        /// Output format
        #[arg(long, value_enum, default_value = "yaml")]
        format: ConfigFormat,

        /// Include comments and examples
        #[arg(long)]
        commented: bool,
    },

    /// Test metrics collection
    Test {
        /// Number of test iterations
        #[arg(short = 'n', long, default_value_t = 1)]
        iterations: usize,

        /// Show detailed process information
        #[arg(long)]
        verbose: bool,

        /// Output format
        #[arg(long, value_enum, default_value = "yaml")]
        format: ConfigFormat,
    },

    /// List available process subgroups
    Subgroups {
        /// Show detailed matching rules
        #[arg(long)]
        verbose: bool,

        /// Filter by group name
        #[arg(short = 'g', long)]
        group: Option<String>,
    },

    /// Generate synthetic test data JSON file
    GenerateTestdata {
        /// Output file path
        #[arg(short = 'o', long, default_value = "testdata.json")]
        output: PathBuf,

        /// Minimum number of processes per subgroup
        #[arg(long, default_value_t = 6)]
        min_per_subgroup: usize,

        /// Number of "other" processes to generate
        #[arg(long, default_value_t = 12)]
        others_count: usize,
    },
}

/// Cached CPU statistics for a single process (monotonic CPU time + last computed percent)
#[derive(Clone, Copy)]
struct CpuStat {
    cpu_percent: f64,
    cpu_time_seconds: f64,
}

/// Cache entry with timestamp for delta-based CPU calculation
struct CpuEntry {
    stat: CpuStat,
    last_updated: Instant,
}

// Data structure for subgroup configuration from TOML
#[derive(Deserialize)]
struct Subgroup {
    group: String,
    subgroup: String,
    matches: Option<Vec<String>>,
    cmdline_matches: Option<Vec<String>>,
}

// Root structure for subgroups configuration
#[derive(Deserialize)]
struct SubgroupsConfig {
    subgroups: Vec<Subgroup>,
}

/// Helper: load subgroups from TOML string into map
fn load_subgroups_from_str(content: &str, map: &mut HashMap<Arc<str>, (Arc<str>, Arc<str>)>) {
    let parsed: SubgroupsConfig = match toml::from_str(content) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to parse subgroups TOML: {}", e);
            return;
        }
    };

    for sg in parsed.subgroups {
        let group_arc: Arc<str> = Arc::from(sg.group.as_str());
        let subgroup_arc: Arc<str> = Arc::from(sg.subgroup.as_str());

        if let Some(matches) = sg.matches {
            for m in matches {
                let key_arc: Arc<str> = Arc::from(m.as_str());
                map.insert(key_arc, (Arc::clone(&group_arc), Arc::clone(&subgroup_arc)));
            }
        }
        if let Some(cmdlines) = sg.cmdline_matches {
            for cmd in cmdlines {
                let key_arc: Arc<str> = Arc::from(cmd.as_str());
                map.insert(key_arc, (Arc::clone(&group_arc), Arc::clone(&subgroup_arc)));
            }
        }
    }
}

/// Helper: load subgroups from TOML file path (if exists)
fn load_subgroups_from_file(path: &str, map: &mut HashMap<Arc<str>, (Arc<str>, Arc<str>)>) {
    let p = Path::new(path);
    if !p.exists() {
        return;
    }
    match fs::read_to_string(p) {
        Ok(content) => {
            load_subgroups_from_str(&content, map);
            eprintln!("Loaded additional subgroups from {}", path);
        }
        Err(e) => {
            eprintln!("Failed to read subgroups file {}: {}", path, e);
        }
    }
}

// Static configuration for process subgroups loaded from TOML file(s)
static SUBGROUPS: Lazy<HashMap<Arc<str>, (Arc<str>, Arc<str>)>> = Lazy::new(|| {
    let mut map = HashMap::new();

    // 1) built-in subgroups from embedded file
    let content = include_str!("../data/subgroups.toml");
    load_subgroups_from_str(content, &mut map);

    // 2) optional system-wide subgroups
    load_subgroups_from_file("/etc/herakles/subgroups.toml", &mut map);

    // 3) optional subgroups in current working directory
    load_subgroups_from_file("./subgroups.toml", &mut map);

    map
});

/// Get system clock ticks per second (usually 100, but can vary)
fn get_clk_tck() -> f64 {
    #[cfg(unix)]
    {
        // SAFETY: sysconf is safe to call with _SC_CLK_TCK
        // Returns -1 on error, 0 if undefined - both are handled by the > 0 check
        unsafe {
            let tck = libc::sysconf(libc::_SC_CLK_TCK);
            if tck > 0 {
                return tck as f64;
            }
        }
    }
    // Fallback to common default for error cases or non-Unix platforms
    100.0
}

/// System clock ticks per second (for CPU time calculation)
static CLK_TCK: Lazy<f64> = Lazy::new(get_clk_tck);

// Type alias for shared application state
type SharedState = Arc<AppState>;

// Default configuration constants
const DEFAULT_BIND_ADDR: &str = "0.0.0.0";
const DEFAULT_PORT: u16 = 9215;
const DEFAULT_CACHE_TTL: u64 = 30;
const BUFFER_CAP: usize = 512 * 1024;

/// Enhanced configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    // Server configuration
    port: Option<u16>,
    bind: Option<String>,

    // Metrics collection
    min_uss_kb: Option<u64>,
    include_names: Option<Vec<String>>,
    exclude_names: Option<Vec<String>>,
    parallelism: Option<usize>,
    max_processes: Option<usize>,

    // Performance tuning
    cache_ttl: Option<u64>,
    io_buffer_kb: Option<usize>,
    smaps_buffer_kb: Option<usize>,
    smaps_rollup_buffer_kb: Option<usize>,

    // Feature flags
    enable_health: Option<bool>,
    enable_telemetry: Option<bool>,
    enable_default_collectors: Option<bool>,
    enable_pprof: Option<bool>,

    // Logging
    log_level: Option<String>,
    enable_file_logging: Option<bool>,
    log_file: Option<PathBuf>,

    // Classification / search engine
    /// "include" | "exclude" | None
    #[serde(alias = "modify-search-engine")]
    search_mode: Option<String>,
    /// List of group names
    #[serde(alias = "groups")]
    search_groups: Option<Vec<String>>,
    /// List of subgroup names
    #[serde(alias = "subgroups")]
    search_subgroups: Option<Vec<String>>,
    /// If true, completely ignore "other"/"unknown" processes
    #[serde(alias = "disable-others")]
    disable_others: Option<bool>,
    /// Top-N processes to export per subgroup (non-"other" groups)
    #[serde(alias = "top-n-subgroup")]
    top_n_subgroup: Option<usize>,
    /// Top-N processes to export for "other" group
    #[serde(alias = "top-n-others")]
    top_n_others: Option<usize>,

    // Metrics enable flags
    #[serde(alias = "enable-rss")]
    enable_rss: Option<bool>,
    #[serde(alias = "enable-pss")]
    enable_pss: Option<bool>,
    #[serde(alias = "enable-uss")]
    enable_uss: Option<bool>,
    #[serde(alias = "enable-cpu")]
    enable_cpu: Option<bool>,

    /// Path to JSON test data file (uses synthetic data instead of /proc)
    #[serde(alias = "test-data-file")]
    test_data_file: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: Some(DEFAULT_BIND_ADDR.to_string()),
            port: Some(DEFAULT_PORT),
            min_uss_kb: Some(0),
            include_names: None,
            exclude_names: None,
            parallelism: None,
            max_processes: None,
            cache_ttl: Some(DEFAULT_CACHE_TTL),
            io_buffer_kb: Some(256),
            smaps_buffer_kb: Some(512),
            smaps_rollup_buffer_kb: Some(256),
            enable_health: Some(true),
            enable_telemetry: Some(true),
            enable_default_collectors: Some(true),
            enable_pprof: Some(false),
            log_level: Some("info".into()),
            enable_file_logging: Some(false),
            log_file: None,
            search_mode: None,
            search_groups: None,
            search_subgroups: None,
            disable_others: Some(false),
            top_n_subgroup: Some(3),
            top_n_others: Some(10),
            enable_rss: Some(true),
            enable_pss: Some(true),
            enable_uss: Some(true),
            enable_cpu: Some(true),
            test_data_file: None,
        }
    }
}

/// Validate effective config (used by --check-config and at startup)
fn validate_effective_config(cfg: &Config) -> Result<(), Box<dyn std::error::Error>> {
    // Metrics flags: at least one must be true
    let enable_rss = cfg.enable_rss.unwrap_or(true);
    let enable_pss = cfg.enable_pss.unwrap_or(true);
    let enable_uss = cfg.enable_uss.unwrap_or(true);
    let enable_cpu = cfg.enable_cpu.unwrap_or(true);

    if !(enable_rss || enable_pss || enable_uss || enable_cpu) {
        return Err(
            "At least one of enable_rss/enable_pss/enable_uss/enable_cpu must be true".into(),
        );
    }

    // Search mode validation
    if let Some(mode) = cfg.search_mode.as_deref() {
        let has_groups = cfg.search_groups.as_ref().map_or(false, |v| !v.is_empty());
        let has_subgroups = cfg
            .search_subgroups
            .as_ref()
            .map_or(false, |v| !v.is_empty());

        match mode {
            "include" | "exclude" => {
                if !(has_groups || has_subgroups) {
                    return Err("search_mode is set to include/exclude, \
                        but no search_groups or search_subgroups defined"
                        .into());
                }
            }
            other => {
                return Err(format!(
                    "Invalid search_mode '{}', expected 'include' or 'exclude'",
                    other
                )
                .into());
            }
        }
    }

    Ok(())
}

/// Process entry representing a directory in /proc filesystem
#[derive(Debug, Clone)]
struct ProcEntry {
    pid: u32,
    proc_path: PathBuf,
}

/// Process memory and CPU metrics collected from /proc
#[derive(Debug, Clone)]
struct ProcMem {
    pid: u32,
    name: String,
    rss: u64,
    pss: u64,
    uss: u64,
    cpu_percent: f32,
    cpu_time_seconds: f32,
}

/// Collection of Prometheus metrics for memory and CPU monitoring
#[derive(Clone)]
struct MemoryMetrics {
    rss: GaugeVec,
    pss: GaugeVec,
    uss: GaugeVec,
    cpu_usage: GaugeVec,
    cpu_time: GaugeVec,

    // Aggregated per-subgroup sums
    agg_rss_sum: GaugeVec,
    agg_pss_sum: GaugeVec,
    agg_uss_sum: GaugeVec,
    agg_cpu_percent_sum: GaugeVec,
    agg_cpu_time_sum: GaugeVec,

    // Top-N metrics per subgroup
    top_rss: GaugeVec,
    top_pss: GaugeVec,
    top_uss: GaugeVec,
    top_cpu_percent: GaugeVec,
    top_cpu_time: GaugeVec,

    // Percentage-of-subgroup metrics for Top-N
    top_cpu_percent_of_subgroup: GaugeVec,
    top_rss_percent_of_subgroup: GaugeVec,
    top_pss_percent_of_subgroup: GaugeVec,
    top_uss_percent_of_subgroup: GaugeVec,
}

impl MemoryMetrics {
    /// Creates and registers all Prometheus metrics with the registry
    fn new(registry: &Registry) -> Result<Self, Box<dyn std::error::Error>> {
        let labels = &["pid", "name", "group", "subgroup"];

        let rss = GaugeVec::new(
            Opts::new(
                "herakles_proc_mem_rss_bytes",
                "Resident Set Size per process in bytes",
            ),
            labels,
        )?;
        let pss = GaugeVec::new(
            Opts::new(
                "herakles_proc_mem_pss_bytes",
                "Proportional Set Size per process in bytes",
            ),
            labels,
        )?;
        let uss = GaugeVec::new(
            Opts::new(
                "herakles_proc_mem_uss_bytes",
                "Unique Set Size per process in bytes",
            ),
            labels,
        )?;
        let cpu_usage = GaugeVec::new(
            Opts::new(
                "herakles_proc_mem_cpu_percent",
                "CPU usage per process in percent (delta over last scan)",
            ),
            labels,
        )?;
        let cpu_time = GaugeVec::new(
            Opts::new(
                "herakles_proc_mem_cpu_time_seconds",
                "Total CPU time used per process",
            ),
            labels,
        )?;

        // Aggregated sums per subgroup
        let agg_rss_sum = GaugeVec::new(
            Opts::new(
                "herakles_proc_mem_group_rss_bytes_sum",
                "Sum of RSS bytes per subgroup",
            ),
            &["group", "subgroup"],
        )?;
        let agg_pss_sum = GaugeVec::new(
            Opts::new(
                "herakles_proc_mem_group_pss_bytes_sum",
                "Sum of PSS bytes per subgroup",
            ),
            &["group", "subgroup"],
        )?;
        let agg_uss_sum = GaugeVec::new(
            Opts::new(
                "herakles_proc_mem_group_uss_bytes_sum",
                "Sum of USS bytes per subgroup",
            ),
            &["group", "subgroup"],
        )?;
        let agg_cpu_percent_sum = GaugeVec::new(
            Opts::new(
                "herakles_proc_mem_group_cpu_percent_sum",
                "Sum of CPU percent per subgroup",
            ),
            &["group", "subgroup"],
        )?;
        let agg_cpu_time_sum = GaugeVec::new(
            Opts::new(
                "herakles_proc_mem_group_cpu_time_seconds_sum",
                "Sum of CPU time seconds per subgroup",
            ),
            &["group", "subgroup"],
        )?;

        // Top-N metrics per subgroup
        let top_rss = GaugeVec::new(
            Opts::new("herakles_proc_mem_top_rss_bytes", "Top-N RSS per subgroup"),
            &["group", "subgroup", "rank", "pid", "name"],
        )?;
        let top_pss = GaugeVec::new(
            Opts::new("herakles_proc_mem_top_pss_bytes", "Top-N PSS per subgroup"),
            &["group", "subgroup", "rank", "pid", "name"],
        )?;
        let top_uss = GaugeVec::new(
            Opts::new("herakles_proc_mem_top_uss_bytes", "Top-N USS per subgroup"),
            &["group", "subgroup", "rank", "pid", "name"],
        )?;
        let top_cpu_percent = GaugeVec::new(
            Opts::new(
                "herakles_proc_mem_top_cpu_percent",
                "Top-N CPU percent per subgroup",
            ),
            &["group", "subgroup", "rank", "pid", "name"],
        )?;
        let top_cpu_time = GaugeVec::new(
            Opts::new(
                "herakles_proc_mem_top_cpu_time_seconds",
                "Top-N CPU time seconds per subgroup",
            ),
            &["group", "subgroup", "rank", "pid", "name"],
        )?;

        // Percentage-of-subgroup metrics
        let top_cpu_percent_of_subgroup = GaugeVec::new(
            Opts::new(
                "herakles_proc_mem_top_cpu_percent_of_subgroup",
                "Top-N CPU time as percentage of subgroup total CPU time",
            ),
            &["group", "subgroup", "rank", "pid", "name"],
        )?;
        let top_rss_percent_of_subgroup = GaugeVec::new(
            Opts::new(
                "herakles_proc_mem_top_rss_percent_of_subgroup",
                "Top-N RSS as percentage of subgroup total RSS",
            ),
            &["group", "subgroup", "rank", "pid", "name"],
        )?;
        let top_pss_percent_of_subgroup = GaugeVec::new(
            Opts::new(
                "herakles_proc_mem_top_pss_percent_of_subgroup",
                "Top-N PSS as percentage of subgroup total PSS",
            ),
            &["group", "subgroup", "rank", "pid", "name"],
        )?;
        let top_uss_percent_of_subgroup = GaugeVec::new(
            Opts::new(
                "herakles_proc_mem_top_uss_percent_of_subgroup",
                "Top-N USS as percentage of subgroup total USS",
            ),
            &["group", "subgroup", "rank", "pid", "name"],
        )?;

        registry.register(Box::new(rss.clone()))?;
        registry.register(Box::new(pss.clone()))?;
        registry.register(Box::new(uss.clone()))?;
        registry.register(Box::new(cpu_usage.clone()))?;
        registry.register(Box::new(cpu_time.clone()))?;

        registry.register(Box::new(agg_rss_sum.clone()))?;
        registry.register(Box::new(agg_pss_sum.clone()))?;
        registry.register(Box::new(agg_uss_sum.clone()))?;
        registry.register(Box::new(agg_cpu_percent_sum.clone()))?;
        registry.register(Box::new(agg_cpu_time_sum.clone()))?;

        registry.register(Box::new(top_rss.clone()))?;
        registry.register(Box::new(top_pss.clone()))?;
        registry.register(Box::new(top_uss.clone()))?;
        registry.register(Box::new(top_cpu_percent.clone()))?;
        registry.register(Box::new(top_cpu_time.clone()))?;

        registry.register(Box::new(top_cpu_percent_of_subgroup.clone()))?;
        registry.register(Box::new(top_rss_percent_of_subgroup.clone()))?;
        registry.register(Box::new(top_pss_percent_of_subgroup.clone()))?;
        registry.register(Box::new(top_uss_percent_of_subgroup.clone()))?;

        Ok(Self {
            rss,
            pss,
            uss,
            cpu_usage,
            cpu_time,
            agg_rss_sum,
            agg_pss_sum,
            agg_uss_sum,
            agg_cpu_percent_sum,
            agg_cpu_time_sum,
            top_rss,
            top_pss,
            top_uss,
            top_cpu_percent,
            top_cpu_time,
            top_cpu_percent_of_subgroup,
            top_rss_percent_of_subgroup,
            top_pss_percent_of_subgroup,
            top_uss_percent_of_subgroup,
        })
    }

    /// Resets all metrics to zero (used before updating with fresh data)
    fn reset(&self) {
        self.rss.reset();
        self.pss.reset();
        self.uss.reset();
        self.cpu_usage.reset();
        self.cpu_time.reset();

        self.agg_rss_sum.reset();
        self.agg_pss_sum.reset();
        self.agg_uss_sum.reset();
        self.agg_cpu_percent_sum.reset();
        self.agg_cpu_time_sum.reset();

        self.top_rss.reset();
        self.top_pss.reset();
        self.top_uss.reset();
        self.top_cpu_percent.reset();
        self.top_cpu_time.reset();

        self.top_cpu_percent_of_subgroup.reset();
        self.top_rss_percent_of_subgroup.reset();
        self.top_pss_percent_of_subgroup.reset();
        self.top_uss_percent_of_subgroup.reset();
    }

    /// Sets metric values for a specific process with classification
    #[allow(clippy::too_many_arguments)]
    fn set_for_process(
        &self,
        pid: &str,
        name: &str,
        group: &str,
        subgroup: &str,
        rss: u64,
        pss: u64,
        uss: u64,
        cpu_percent: f64,
        cpu_time_seconds: f64,
        cfg: &Config,
    ) {
        let labels = &[pid, name, group, subgroup];

        let enable_rss = cfg.enable_rss.unwrap_or(true);
        let enable_pss = cfg.enable_pss.unwrap_or(true);
        let enable_uss = cfg.enable_uss.unwrap_or(true);
        let enable_cpu = cfg.enable_cpu.unwrap_or(true);

        if enable_rss {
            self.rss.with_label_values(labels).set(rss as f64);
        }
        if enable_pss {
            self.pss.with_label_values(labels).set(pss as f64);
        }
        if enable_uss {
            self.uss.with_label_values(labels).set(uss as f64);
        }
        if enable_cpu {
            self.cpu_usage.with_label_values(labels).set(cpu_percent);
            self.cpu_time
                .with_label_values(labels)
                .set(cpu_time_seconds);
        }
    }
}

#[derive(Clone, Copy, Default)]
struct RunningStat {
    count: u64,
    sum: f64,
    min: f64,
    max: f64,
    last: f64,
}

impl RunningStat {
    fn add(&mut self, value: f64) {
        if self.count == 0 {
            self.min = value;
            self.max = value;
            self.last = value;
            self.sum = value;
            self.count = 1;
            return;
        }
        self.count += 1;
        self.sum += value;
        self.last = value;
        if value < self.min {
            self.min = value;
        }
        if value > self.max {
            self.max = value;
        }
    }

    fn avg(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.sum / (self.count as f64)
        }
    }
}

#[derive(Default)]
struct Stat {
    inner: Mutex<RunningStat>,
}

impl Stat {
    fn add_sample(&self, value: f64) {
        if let Ok(mut s) = self.inner.lock() {
            s.add(value);
        }
    }

    fn snapshot(&self) -> (f64, f64, f64, f64, u64) {
        if let Ok(s) = self.inner.lock() {
            (s.last, s.avg(), s.max, s.min, s.count)
        } else {
            (0.0, 0.0, 0.0, 0.0, 0)
        }
    }
}

/// Thread-safe circular buffer for tracking HTTP request timestamps
struct RequestTimestamps {
    inner: Mutex<VecDeque<Instant>>,
}

impl Default for RequestTimestamps {
    fn default() -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(1024)),
        }
    }
}

impl RequestTimestamps {
    fn record(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.push_back(Instant::now());
            // Keep only last 10 minutes of timestamps to avoid unbounded growth
            let cutoff = Instant::now() - std::time::Duration::from_secs(600);
            while guard.front().is_some_and(|&t| t < cutoff) {
                guard.pop_front();
            }
        }
    }

    fn count_last_minute(&self) -> u64 {
        if let Ok(guard) = self.inner.lock() {
            let cutoff = Instant::now() - std::time::Duration::from_secs(60);
            guard.iter().filter(|&&t| t >= cutoff).count() as u64
        } else {
            0
        }
    }
}

struct HealthStats {
    // Existing fields
    scanned_processes: Stat,
    scan_duration_seconds: Stat,
    cache_update_duration_seconds: Stat,
    total_scans: AtomicU64,

    // NEW: Scan performance
    scan_success_count: AtomicU64,
    scan_failure_count: AtomicU64,
    used_subgroups: Stat,

    // NEW: Cache performance
    cache_size: Stat,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,

    // NEW: HTTP server stats
    http_request_timestamps: RequestTimestamps,
    request_duration_ms: Stat,
    label_cardinality: Stat,
    metrics_endpoint_calls: AtomicU64,

    // NEW: Exporter resources
    exporter_memory_mb: Stat,
    exporter_cpu_percent: Stat,

    // NEW: Timing
    start_time: Instant,
    last_scan_time: StdRwLock<Option<Instant>>,
}

impl Default for HealthStats {
    fn default() -> Self {
        Self {
            scanned_processes: Stat::default(),
            scan_duration_seconds: Stat::default(),
            cache_update_duration_seconds: Stat::default(),
            total_scans: AtomicU64::new(0),
            scan_success_count: AtomicU64::new(0),
            scan_failure_count: AtomicU64::new(0),
            used_subgroups: Stat::default(),
            cache_size: Stat::default(),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            http_request_timestamps: RequestTimestamps::default(),
            request_duration_ms: Stat::default(),
            label_cardinality: Stat::default(),
            metrics_endpoint_calls: AtomicU64::new(0),
            exporter_memory_mb: Stat::default(),
            exporter_cpu_percent: Stat::default(),
            start_time: Instant::now(),
            last_scan_time: StdRwLock::new(None),
        }
    }
}

impl HealthStats {
    fn new() -> Self {
        Default::default()
    }

    fn record_scan(
        &self,
        scanned: u64,
        scan_duration_seconds: f64,
        cache_update_duration_seconds: f64,
    ) {
        self.scanned_processes.add_sample(scanned as f64);
        self.scan_duration_seconds.add_sample(scan_duration_seconds);
        self.cache_update_duration_seconds
            .add_sample(cache_update_duration_seconds);
        self.total_scans.fetch_add(1, Ordering::Relaxed);
    }

    fn record_scan_success(&self) {
        self.scan_success_count.fetch_add(1, Ordering::Relaxed);
    }

    fn record_scan_failure(&self) {
        self.scan_failure_count.fetch_add(1, Ordering::Relaxed);
    }

    fn record_used_subgroups(&self, count: u64) {
        self.used_subgroups.add_sample(count as f64);
    }

    fn record_cache_size(&self, size: u64) {
        self.cache_size.add_sample(size as f64);
    }

    fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    #[allow(dead_code)]
    fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    fn record_http_request(&self) {
        self.http_request_timestamps.record();
    }

    fn record_request_duration(&self, duration_ms: f64) {
        self.request_duration_ms.add_sample(duration_ms);
    }

    fn record_label_cardinality(&self, count: u64) {
        self.label_cardinality.add_sample(count as f64);
    }

    fn record_metrics_endpoint_call(&self) {
        self.metrics_endpoint_calls.fetch_add(1, Ordering::Relaxed);
    }

    fn record_exporter_resources(&self, memory_mb: f64, cpu_percent: f64) {
        self.exporter_memory_mb.add_sample(memory_mb);
        self.exporter_cpu_percent.add_sample(cpu_percent);
    }

    fn update_last_scan_time(&self) {
        if let Ok(mut guard) = self.last_scan_time.write() {
            *guard = Some(Instant::now());
        }
    }

    fn get_scan_success_rate(&self) -> f64 {
        let success = self.scan_success_count.load(Ordering::Relaxed);
        let failure = self.scan_failure_count.load(Ordering::Relaxed);
        let total = success + failure;
        if total == 0 {
            100.0
        } else {
            (success as f64 / total as f64) * 100.0
        }
    }

    fn get_cache_hit_ratio(&self) -> f64 {
        let hits = self.cache_hits.load(Ordering::Relaxed);
        let misses = self.cache_misses.load(Ordering::Relaxed);
        let total = hits + misses;
        if total == 0 {
            100.0 // Default to 100% when no cache operations have occurred
        } else {
            (hits as f64 / total as f64) * 100.0
        }
    }

    fn get_uptime_hours(&self) -> f64 {
        self.start_time.elapsed().as_secs_f64() / 3600.0
    }

    fn get_last_scan_time_str(&self) -> String {
        // Time constants for formatting
        const SECS_PER_DAY: u64 = 86400;
        const SECS_PER_HOUR: u64 = 3600;
        const SECS_PER_MINUTE: u64 = 60;

        if let Ok(guard) = self.last_scan_time.read() {
            if let Some(last_scan) = *guard {
                // Calculate time since epoch by using SystemTime
                let elapsed_since_scan = last_scan.elapsed();
                let now = SystemTime::now();
                if let Ok(duration) = now.duration_since(SystemTime::UNIX_EPOCH) {
                    let scan_time_secs = duration
                        .as_secs()
                        .saturating_sub(elapsed_since_scan.as_secs());
                    let hours = (scan_time_secs % SECS_PER_DAY) / SECS_PER_HOUR;
                    let minutes = (scan_time_secs % SECS_PER_HOUR) / SECS_PER_MINUTE;
                    let seconds = scan_time_secs % SECS_PER_MINUTE;
                    return format!("{:02}:{:02}:{:02}", hours, minutes, seconds);
                }
            }
        }
        "N/A".to_string()
    }

    fn render_table(&self) -> String {
        let (sc_cur, sc_avg, sc_max, sc_min, _sc_count) = self.scanned_processes.snapshot();
        let (sd_cur, sd_avg, sd_max, sd_min, _sd_count) = self.scan_duration_seconds.snapshot();
        let (cu_cur, cu_avg, cu_max, cu_min, _cu_count) =
            self.cache_update_duration_seconds.snapshot();
        let total = self.total_scans.load(Ordering::Relaxed);

        // New metrics snapshots
        let (ug_cur, ug_avg, ug_max, ug_min, _) = self.used_subgroups.snapshot();
        let (cs_cur, cs_avg, cs_max, cs_min, _) = self.cache_size.snapshot();
        let (rd_cur, rd_avg, rd_max, rd_min, _) = self.request_duration_ms.snapshot();
        let (lc_cur, lc_avg, lc_max, lc_min, _) = self.label_cardinality.snapshot();
        let (em_cur, em_avg, em_max, em_min, _) = self.exporter_memory_mb.snapshot();
        let (ec_cur, ec_avg, ec_max, ec_min, _) = self.exporter_cpu_percent.snapshot();

        let scan_success_rate = self.get_scan_success_rate();
        let cache_hit_ratio = self.get_cache_hit_ratio();
        let http_requests_last_minute = self.http_request_timestamps.count_last_minute();
        let metrics_calls = self.metrics_endpoint_calls.load(Ordering::Relaxed);
        let uptime_hours = self.get_uptime_hours();
        let last_scan = self.get_last_scan_time_str();

        let left_col = 26usize;
        let col_w = 12usize;

        let mut out = String::new();

        writeln!(out, "HEALTH ENDPOINT - EXPORTER INTERNAL STATS").ok();
        writeln!(out, "==========================================").ok();
        writeln!(out).ok();

        // Header
        writeln!(
            out,
            "{:left$} | {:^col$} | {:^col$} | {:^col$} | {:^col$}",
            "",
            "current",
            "average",
            "max",
            "min",
            left = left_col,
            col = col_w
        )
        .ok();

        // SCAN PERFORMANCE section
        writeln!(out).ok();
        writeln!(out, "SCAN PERFORMANCE").ok();
        writeln!(out, "-----------------").ok();

        writeln!(
            out,
            "{:left$} | {:^col$} | {:^col$} | {:^col$} | {:^col$}",
            "scanned_processes",
            format!("{:.0}", sc_cur),
            format!("{:.1}", sc_avg),
            format!("{:.0}", sc_max),
            format!("{:.0}", sc_min),
            left = left_col,
            col = col_w
        )
        .ok();

        writeln!(
            out,
            "{:left$} | {:^col$} | {:^col$} | {:^col$} | {:^col$}",
            "scan_duration (s)",
            format!("{:.3}", sd_cur),
            format!("{:.3}", sd_avg),
            format!("{:.3}", sd_max),
            format!("{:.3}", sd_min),
            left = left_col,
            col = col_w
        )
        .ok();

        writeln!(
            out,
            "{:left$} | {:^col$} | {:^col$} | {:^col$} | {:^col$}",
            "scan_success_rate (%)",
            format!("{:.1}", scan_success_rate),
            format!("{:.1}", scan_success_rate),
            format!("{:.1}", scan_success_rate),
            format!("{:.1}", scan_success_rate),
            left = left_col,
            col = col_w
        )
        .ok();

        writeln!(
            out,
            "{:left$} | {:^col$} | {:^col$} | {:^col$} | {:^col$}",
            "used_subgroups",
            format!("{:.0}", ug_cur),
            format!("{:.1}", ug_avg),
            format!("{:.0}", ug_max),
            format!("{:.0}", ug_min),
            left = left_col,
            col = col_w
        )
        .ok();

        // CACHE PERFORMANCE section
        writeln!(out).ok();
        writeln!(out, "CACHE PERFORMANCE").ok();
        writeln!(out, "------------------").ok();

        writeln!(
            out,
            "{:left$} | {:^col$} | {:^col$} | {:^col$} | {:^col$}",
            "cache_update_duration (s)",
            format!("{:.3}", cu_cur),
            format!("{:.3}", cu_avg),
            format!("{:.3}", cu_max),
            format!("{:.3}", cu_min),
            left = left_col,
            col = col_w
        )
        .ok();

        writeln!(
            out,
            "{:left$} | {:^col$} | {:^col$} | {:^col$} | {:^col$}",
            "cache_hit_ratio (%)",
            format!("{:.1}", cache_hit_ratio),
            format!("{:.1}", cache_hit_ratio),
            format!("{:.1}", cache_hit_ratio),
            format!("{:.1}", cache_hit_ratio),
            left = left_col,
            col = col_w
        )
        .ok();

        writeln!(
            out,
            "{:left$} | {:^col$} | {:^col$} | {:^col$} | {:^col$}",
            "cache_size",
            format!("{:.0}", cs_cur),
            format!("{:.1}", cs_avg),
            format!("{:.0}", cs_max),
            format!("{:.0}", cs_min),
            left = left_col,
            col = col_w
        )
        .ok();

        // HTTP SERVER section
        writeln!(out).ok();
        writeln!(out, "HTTP SERVER").ok();
        writeln!(out, "-----------").ok();

        writeln!(
            out,
            "{:left$} | {:^col$} | {:^col$} | {:^col$} | {:^col$}",
            "http_requests_last_minute",
            format!("{}", http_requests_last_minute),
            "N/A",
            "N/A",
            "N/A",
            left = left_col,
            col = col_w
        )
        .ok();

        writeln!(
            out,
            "{:left$} | {:^col$} | {:^col$} | {:^col$} | {:^col$}",
            "avg_request_duration (ms)",
            format!("{:.1}", rd_cur),
            format!("{:.1}", rd_avg),
            format!("{:.1}", rd_max),
            format!("{:.1}", rd_min),
            left = left_col,
            col = col_w
        )
        .ok();

        writeln!(
            out,
            "{:left$} | {:^col$} | {:^col$} | {:^col$} | {:^col$}",
            "label_cardinality_total",
            format!("{:.0}", lc_cur),
            format!("{:.1}", lc_avg),
            format!("{:.0}", lc_max),
            format!("{:.0}", lc_min),
            left = left_col,
            col = col_w
        )
        .ok();

        writeln!(
            out,
            "{:left$} | {:^col$} | {:^col$} | {:^col$} | {:^col$}",
            "metrics_endpoint_calls",
            format!("{}", metrics_calls),
            "N/A",
            "N/A",
            "N/A",
            left = left_col,
            col = col_w
        )
        .ok();

        // EXPORTER RESOURCES section
        writeln!(out).ok();
        writeln!(out, "EXPORTER RESOURCES").ok();
        writeln!(out, "-------------------").ok();

        writeln!(
            out,
            "{:left$} | {:^col$} | {:^col$} | {:^col$} | {:^col$}",
            "exporter_memory_usage (MB)",
            format!("{:.1}", em_cur),
            format!("{:.1}", em_avg),
            format!("{:.1}", em_max),
            format!("{:.1}", em_min),
            left = left_col,
            col = col_w
        )
        .ok();

        writeln!(
            out,
            "{:left$} | {:^col$} | {:^col$} | {:^col$} | {:^col$}",
            "exporter_cpu_usage (%)",
            format!("{:.1}", ec_cur),
            format!("{:.1}", ec_avg),
            format!("{:.1}", ec_max),
            format!("{:.1}", ec_min),
            left = left_col,
            col = col_w
        )
        .ok();

        // Summary line
        writeln!(out).ok();
        writeln!(
            out,
            "number of done scans: {} | last scan: {} | uptime: {:.1}h",
            total, last_scan, uptime_hours
        )
        .ok();

        out
    }
}

/// Cache state for storing process metrics with update timing information
#[derive(Clone, Default)]
struct MetricsCache {
    processes: HashMap<u32, ProcMem>,
    last_updated: Option<Instant>,
    update_duration_seconds: f64,
    update_success: bool,
    is_updating: bool,
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
struct BufferConfig {
    io_kb: usize,
    smaps_kb: usize,
    smaps_rollup_kb: usize,
}

/// Global application state shared across requests and background tasks
struct AppState {
    registry: Registry,
    metrics: MemoryMetrics,
    scrape_duration: Gauge,
    processes_total: Gauge,
    cache_update_duration: Gauge,
    cache_update_success: Gauge,
    cache_updating: Gauge,
    cache: Arc<RwLock<MetricsCache>>,
    config: Arc<Config>,
    buffer_config: BufferConfig,
    cpu_cache: StdRwLock<HashMap<u32, CpuEntry>>,
    health_stats: Arc<HealthStats>,
    /// Notification for cache update completion
    cache_ready: Arc<Notify>,
}

/// Error type for metrics endpoint failures
#[derive(Debug)]
enum MetricsError {
    EncodingFailed,
}

// Implementation of IntoResponse for metrics errors
impl IntoResponse for MetricsError {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to encode metrics",
        )
            .into_response()
    }
}

/// -------------------------------------------------------------------
/// CLI COMMAND IMPLEMENTATIONS
/// -------------------------------------------------------------------

/// Validates system requirements and configuration
fn command_check(
    memory: bool,
    proc: bool,
    all: bool,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Herakles Process Memory Exporter - System Check");
    println!("===================================================");

    let mut all_ok = true;

    // Check /proc filesystem
    if proc || all {
        println!("\n📁 Checking /proc filesystem...");
        if Path::new("/proc").exists() {
            println!("   ✅ /proc filesystem accessible");

            // Check if we can read process directories
            let proc_entries = collect_proc_entries("/proc", Some(5));
            if proc_entries.is_empty() {
                println!("   ❌ Cannot read any process entries from /proc");
                all_ok = false;
            } else {
                println!("   ✅ Can read {} process entries", proc_entries.len());
            }
        } else {
            println!("   ❌ /proc filesystem not found");
            all_ok = false;
        }
    }

    // Check memory metrics accessibility
    if memory || all {
        println!("\n💾 Checking memory metrics accessibility...");
        let test_pid = std::process::id();
        let test_path = Path::new("/proc").join(test_pid.to_string());

        if test_path.join("smaps_rollup").exists() {
            println!("   ✅ smaps_rollup available (fast path)");
        } else if test_path.join("smaps").exists() {
            println!("   ✅ smaps available (slow path)");
        } else {
            println!("   ❌ No memory maps accessible");
            all_ok = false;
        }

        // Test actual parsing
        let buffer_config = BufferConfig {
            io_kb: config.io_buffer_kb.unwrap_or(256),
            smaps_kb: config.smaps_buffer_kb.unwrap_or(512),
            smaps_rollup_kb: config.smaps_rollup_buffer_kb.unwrap_or(256),
        };

        match parse_memory_for_process(&test_path, &buffer_config) {
            Ok((rss, pss, uss)) => {
                println!(
                    "   ✅ Memory parsing successful: RSS={}MB, PSS={}MB, USS={}MB",
                    rss / 1024 / 1024,
                    pss / 1024 / 1024,
                    uss / 1024 / 1024
                );
            }
            Err(e) => {
                println!("   ❌ Memory parsing failed: {}", e);
                all_ok = false;
            }
        }
    }

    // Check configuration
    println!("\n⚙️  Checking configuration...");
    match validate_effective_config(config) {
        Ok(_) => {
            println!("   ✅ Configuration is valid");
        }
        Err(e) => {
            println!("   ❌ Configuration invalid: {}", e);
            all_ok = false;
        }
    }

    // Check subgroups configuration
    println!("\n📊 Checking subgroups configuration...");
    if SUBGROUPS.is_empty() {
        println!("   ⚠️  No subgroups configured");
    } else {
        println!("   ✅ {} subgroups loaded", SUBGROUPS.len());
    }

    println!("\n📋 Summary:");
    if all_ok {
        println!("   ✅ All checks passed - system is ready");
        Ok(())
    } else {
        println!("   ❌ Some checks failed - please review warnings");
        std::process::exit(1);
    }
}

/// Generates configuration files
fn command_config(
    output: Option<PathBuf>,
    format: ConfigFormat,
    commented: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::default();
    let output = match output {
        Some(path) => path,
        None => PathBuf::from("herakles-proc-mem-exporter.yaml"),
    };

    let content = match format {
        ConfigFormat::Json => serde_json::to_string_pretty(&config)?,
        ConfigFormat::Toml => toml::to_string_pretty(&config)?,
        ConfigFormat::Yaml => {
            let mut content = serde_yaml::to_string(&config)?;
            if commented {
                content = add_config_comments(content);
            }
            content
        }
    };

    if output.to_string_lossy() == "-" {
        print!("{}", content);
    } else {
        fs::write(&output, content)?;
        println!("✅ Configuration written to: {}", output.display());
    }

    Ok(())
}

/// Adds comments to YAML configuration
fn add_config_comments(yaml: String) -> String {
    let comments = r#"# Herakles Process Memory Exporter Configuration
# =================================================
#
# Server Configuration
# --------------------
# bind: "0.0.0.0"              # Bind IP (0.0.0.0 = all interfaces)
# port: 9215                   # HTTP port
#
# Metrics Collection
# ------------------
# min_uss_kb: 0                # Minimum USS in KB to include process
# include_names: null          # Include only processes matching these names
# exclude_names: null          # Exclude processes matching these names
# parallelism: null            # Parallel threads (null = auto)
# max_processes: null          # Maximum processes to scan
#
# Performance Tuning
# ------------------
# cache_ttl: 30                # Cache metrics for N seconds
# io_buffer_kb: 256            # Buffer size for generic /proc readers
# smaps_buffer_kb: 512         # Buffer size for smaps parsing
# smaps_rollup_buffer_kb: 256  # Buffer size for smaps_rollup parsing
#
# Feature Flags
# -------------
# enable_health: true          # Enable /health endpoint
# enable_telemetry: true       # Enable internal metrics
# enable_default_collectors: true # Enable generic collectors
# enable_pprof: false          # Enable /debug/pprof endpoints
#
# Logging
# -------
# log_level: "info"            # off, error, warn, info, debug, trace
# enable_file_logging: false   # Enable file logging
# log_file: null               # Log file path (null = stderr)
#
# Classification / Search Engine
# ------------------------------
# search_mode: null            # "include" or "exclude" or null for disabled
# search_groups: null          # List of group names (e.g. ["db", "system"])
# search_subgroups: null       # List of subgroup names (e.g. ["postgres", "nginx"])
# disable_others: false        # Skip 'other/unknown' processes completely
# top_n_subgroup: 3          # Top-N processes per subgroup (non-"other" groups)
# top_n_others: 10           # Top-N processes for "other" group
#
# Metrics Enable Flags
# --------------------
# enable_rss: true             # Export RSS metrics
# enable_pss: true             # Export PSS metrics
# enable_uss: true             # Export USS metrics
# enable_cpu: true             # Export CPU metrics
"#;

    format!("{comments}\n{yaml}")
}

/// Tests metrics collection
fn command_test(
    iterations: usize,
    verbose: bool,
    _format: ConfigFormat,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🧪 Herakles Process Memory Exporter - Test Mode");
    println!("================================================");

    let buffer_config = BufferConfig {
        io_kb: config.io_buffer_kb.unwrap_or(256),
        smaps_kb: config.smaps_buffer_kb.unwrap_or(512),
        smaps_rollup_kb: config.smaps_rollup_buffer_kb.unwrap_or(256),
    };

    for iteration in 1..=iterations {
        println!("\n🔄 Iteration {}/{}:", iteration, iterations);

        let start = Instant::now();
        let entries = collect_proc_entries("/proc", config.max_processes);
        println!("   📁 Found {} process entries", entries.len());

        let mut results = Vec::new();
        let mut error_count = 0;

        for entry in entries.iter().take(10) {
            match read_process_name(&entry.proc_path) {
                Some(name) => match parse_memory_for_process(&entry.proc_path, &buffer_config) {
                    Ok((rss, pss, uss)) => {
                        let cpu = CpuStat {
                            cpu_percent: 0.0,
                            cpu_time_seconds: 0.0,
                        };

                        results.push(ProcMem {
                            pid: entry.pid,
                            name: name.clone(),
                            rss,
                            pss,
                            uss,
                            cpu_percent: cpu.cpu_percent as f32,
                            cpu_time_seconds: cpu.cpu_time_seconds as f32,
                        });

                        if verbose {
                            let base = classify_process_raw(&name);
                            println!("   ├─ {} (PID: {})", name, entry.pid);
                            println!("   │  ├─ Group: {}/{}", base.0, base.1);
                            println!("   │  ├─ RSS: {} MB", rss / 1024 / 1024);
                            println!("   │  ├─ PSS: {} MB", pss / 1024 / 1024);
                            println!("   │  └─ USS: {} MB", uss / 1024 / 1024);
                        }
                    }
                    Err(e) => {
                        error_count += 1;
                        if verbose {
                            println!("   ├─ ❌ PID {}: {}", entry.pid, e);
                        }
                    }
                },
                None => {
                    error_count += 1;
                }
            }
        }

        let duration = start.elapsed();
        println!(
            "   ⏱️  Scan duration: {:.2}ms",
            duration.as_secs_f64() * 1000.0
        );
        println!("   📊 Successfully scanned: {} processes", results.len());
        println!("   ❌ Errors: {}", error_count);

        if !results.is_empty() {
            let total_rss: u64 = results.iter().map(|p| p.rss).sum();
            let total_pss: u64 = results.iter().map(|p| p.pss).sum();
            let total_uss: u64 = results.iter().map(|p| p.uss).sum();

            println!("   📈 Memory totals:");
            println!("      ├─ RSS: {} MB", total_rss / 1024 / 1024);
            println!("      ├─ PSS: {} MB", total_pss / 1024 / 1024);
            println!("      └─ USS: {} MB", total_uss / 1024 / 1024);
        }
    }

    println!("\n✅ Test completed successfully");
    Ok(())
}

/// Lists available process subgroups (ignores search filters intentionally)
fn command_subgroups(
    verbose: bool,
    group: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("📊 Herakles Process Memory Exporter - Available Subgroups");
    println!("=========================================================");

    let mut groups_map: HashMap<&str, Vec<(&str, &str)>> = HashMap::new();

    for (process_name, (group, subgroup)) in SUBGROUPS.iter() {
        groups_map
            .entry(group)
            .or_default()
            .push((subgroup, process_name));
    }

    for (group_name, subgroups) in &groups_map {
        if let Some(filter) = &group {
            if !group_name.contains(filter) {
                continue;
            }
        }

        println!("\n🏷️  Group: {}", group_name);
        println!("{}", "─".repeat(50));

        let mut subgroup_map: HashMap<&str, Vec<&str>> = HashMap::new();
        for (subgroup, process_name) in subgroups {
            subgroup_map.entry(subgroup).or_default().push(process_name);
        }

        for (subgroup, process_names) in subgroup_map {
            println!("   ├─ 📂 Subgroup: {}", subgroup);

            if verbose {
                for process_name in process_names {
                    println!("   │  ├─ 🔍 Matches: {}", process_name);
                }
            } else {
                let count = process_names.len();
                let examples: Vec<_> = process_names.iter().take(3).cloned().collect();
                println!("   │  ├─ {} matching processes", count);
                if !examples.is_empty() {
                    println!("   │  └─ Examples: {}", examples.join(", "));
                }
            }
        }
    }

    println!(
        "\n📋 Total: {} process patterns in {} groups",
        SUBGROUPS.len(),
        groups_map.len()
    );

    Ok(())
}

/// Test process entry for JSON serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TestProcess {
    pid: u32,
    name: String,
    group: String,
    subgroup: String,
    rss: u64,
    pss: u64,
    uss: u64,
    cpu_percent: f64,
    cpu_time_seconds: f64,
}

/// Root structure for test data JSON file
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TestData {
    version: String,
    generated_at: String,
    processes: Vec<TestProcess>,
}

/// Converts a TestProcess from JSON test data into ProcMem for metrics
impl From<TestProcess> for ProcMem {
    fn from(tp: TestProcess) -> Self {
        ProcMem {
            pid: tp.pid,
            name: tp.name,
            rss: tp.rss,
            pss: tp.pss,
            uss: tp.uss,
            cpu_percent: tp.cpu_percent as f32,
            cpu_time_seconds: tp.cpu_time_seconds as f32,
        }
    }
}

/// Load test data from JSON file
fn load_test_data_from_file(path: &Path) -> Result<TestData, String> {
    debug!("Loading test data from: {}", path.display());

    if !path.exists() {
        return Err(format!("Test data file not found: {}", path.display()));
    }

    let content =
        fs::read_to_string(path).map_err(|e| format!("Failed to read test data file: {}", e))?;
    let test_data: TestData = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse test data JSON: {}", e))?;

    info!(
        "Loaded test data version {} from {}",
        test_data.version, test_data.generated_at
    );

    Ok(test_data)
}

/// Generates synthetic test data JSON file for testing purposes
fn command_generate_testdata(
    output: PathBuf,
    min_per_subgroup: usize,
    others_count: usize,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    debug!(
        "Generating test data: min_per_subgroup={}, others_count={}, output={}",
        min_per_subgroup,
        others_count,
        output.display()
    );

    let mut rng = rand::thread_rng();
    let mut processes: Vec<TestProcess> = Vec::new();
    let mut current_pid: u32 = 1000;

    // Collect unique (group, subgroup) pairs with their associated process name matches
    let mut subgroup_matches: HashMap<(String, String), Vec<String>> = HashMap::new();

    for (process_name, (group, subgroup)) in SUBGROUPS.iter() {
        let key = (group.to_string(), subgroup.to_string());
        subgroup_matches
            .entry(key)
            .or_default()
            .push(process_name.to_string());
    }

    debug!("Found {} unique subgroups", subgroup_matches.len());

    // Generate processes for each subgroup
    for ((group, subgroup), matches) in &subgroup_matches {
        // Skip "other/unknown" - we handle it separately at the end
        if group == "other" && subgroup == "unknown" {
            continue;
        }

        // Apply config filters using classify_process_with_config
        // Pick a sample process name from matches to check if this subgroup is allowed
        if let Some(sample_name) = matches.first() {
            if classify_process_with_config(sample_name, config).is_none() {
                debug!(
                    "Skipping subgroup {}/{} due to config filters",
                    group, subgroup
                );
                continue;
            }
        }

        // Generate min_per_subgroup processes for this subgroup
        for i in 0..min_per_subgroup {
            // Pick a process name from the matches (cycle through them)
            let name = if matches.is_empty() {
                format!("{}-{}", subgroup, i + 1)
            } else {
                matches[i % matches.len()].clone()
            };

            let proc = generate_random_process(&mut rng, current_pid, name, group, subgroup);
            processes.push(proc);
            current_pid += 1;
        }

        debug!(
            "Generated {} processes for subgroup {}/{}",
            min_per_subgroup, group, subgroup
        );
    }

    // Generate "other/unknown" processes (unless disabled)
    let disable_others = config.disable_others.unwrap_or(false);
    if !disable_others {
        for i in 0..others_count {
            let name = format!("process-{}", i + 1);
            let proc = generate_random_process(&mut rng, current_pid, name, "other", "other");
            processes.push(proc);
            current_pid += 1;
        }
        debug!("Generated {} 'other' processes", others_count);
    } else {
        debug!("Skipping 'other' processes due to disable_others config");
    }

    // Create the test data structure
    let test_data = TestData {
        version: "1.0".to_string(),
        generated_at: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        processes,
    };

    // Write to file as pretty-printed JSON
    let json_content = serde_json::to_string_pretty(&test_data)?;
    fs::write(&output, &json_content)?;

    println!(
        "✅ Generated test data: {} processes in {}",
        test_data.processes.len(),
        output.display()
    );

    Ok(())
}

/// Generates a random test process with realistic memory and CPU values
fn generate_random_process(
    rng: &mut impl Rng,
    pid: u32,
    name: String,
    group: &str,
    subgroup: &str,
) -> TestProcess {
    // RSS: 10 MB - 2 GB (in bytes)
    let rss = rng.gen_range(10 * 1024 * 1024..2 * 1024 * 1024 * 1024_u64);

    // PSS: 80-95% of RSS
    let pss_ratio: f64 = rng.gen_range(0.80..0.95);
    let pss = (rss as f64 * pss_ratio) as u64;

    // USS: 60-80% of RSS
    let uss_ratio: f64 = rng.gen_range(0.60..0.80);
    let uss = (rss as f64 * uss_ratio) as u64;

    // CPU percent: 0.0 - 100.0
    let cpu_percent: f64 = rng.gen_range(0.0..100.0);

    // CPU time: 0.0 - 10000.0 seconds
    let cpu_time_seconds: f64 = rng.gen_range(0.0..10000.0);

    TestProcess {
        pid,
        name,
        group: group.to_string(),
        subgroup: subgroup.to_string(),
        rss,
        pss,
        uss,
        cpu_percent,
        cpu_time_seconds,
    }
}

/// -------------------------------------------------------------------
/// CONFIGURATION MANAGEMENT
/// -------------------------------------------------------------------

/// Resolves configuration from CLI args, config file, and defaults
// Replace the existing resolve_config() override logic for port with this:
// This enforces precedence: CLI (if provided) > config file > default.
fn resolve_config(args: &Args) -> Result<Config, Box<dyn std::error::Error>> {
    let mut config = if args.no_config {
        Config::default()
    } else {
        load_config(args.config.as_deref().and_then(|p| p.to_str()))?
    };

    // Override with CLI args
    if let Some(bind_ip) = args.bind {
        config.bind = Some(bind_ip.to_string());
    }

    // Only override port if the user supplied it on the CLI.
    if let Some(cli_port) = args.port {
        config.port = Some(cli_port);
    }

    if args.min_uss_kb.is_some() {
        config.min_uss_kb = args.min_uss_kb;
    }

    // Parse comma-separated include/exclude names
    if let Some(include_str) = &args.include_names {
        config.include_names = Some(
            include_str
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
        );
    }

    if let Some(exclude_str) = &args.exclude_names {
        config.exclude_names = Some(
            exclude_str
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
        );
    }

    // Performance settings
    if let Some(io_buffer_kb) = args.io_buffer_kb {
        config.io_buffer_kb = Some(io_buffer_kb);
    }
    if let Some(smaps_buffer_kb) = args.smaps_buffer_kb {
        config.smaps_buffer_kb = Some(smaps_buffer_kb);
    }
    if let Some(smaps_rollup_buffer_kb) = args.smaps_rollup_buffer_kb {
        config.smaps_rollup_buffer_kb = Some(smaps_rollup_buffer_kb);
    }
    if let Some(cache_ttl) = args.cache_ttl {
        config.cache_ttl = Some(cache_ttl);
    }

    // Top-N overrides: CLI wins if provided
    if let Some(n) = args.top_n_subgroup {
        config.top_n_subgroup = Some(n);
    }
    if let Some(n) = args.top_n_others {
        config.top_n_others = Some(n);
    }

    // Feature flags
    if args.disable_health {
        config.enable_health = Some(false);
    }
    if args.disable_telemetry {
        config.enable_telemetry = Some(false);
    }
    if args.disable_default_collectors {
        config.enable_default_collectors = Some(false);
    }
    if args.debug {
        config.enable_pprof = Some(true);
    }

    // Test data file: CLI wins if provided
    if let Some(test_file) = &args.test_data_file {
        config.test_data_file = Some(test_file.clone());
    }

    Ok(config)
}

/// Enhanced configuration loading with multiple format support
fn load_config(path: Option<&str>) -> Result<Config, Box<dyn std::error::Error>> {
    let path = if let Some(p) = path {
        PathBuf::from(p)
    } else {
        // Try default locations
        let defaults = [
            "/etc/herakles/proc-mem-exporter.yaml",
            "/etc/herakles/proc-mem-exporter.yml",
            "/etc/herakles/proc-mem-exporter.json",
            "./herakles-proc-mem-exporter.yaml",
            "./herakles-proc-mem-exporter.yml",
            "./herakles-proc-mem-exporter.json",
        ];

        defaults
            .iter()
            .find(|p| Path::new(p).exists())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(""))
    };

    if !path.exists() || path.to_string_lossy().is_empty() {
        return Ok(Config::default());
    }

    let content = fs::read_to_string(&path)?;

    match path.extension().and_then(|s| s.to_str()) {
        Some("json") => {
            let config: Config = serde_json::from_str(&content)?;
            info!("Loaded JSON configuration from: {}", path.display());
            Ok(config)
        }
        Some("toml") => {
            let config: Config = toml::from_str(&content)?;
            info!("Loaded TOML configuration from: {}", path.display());
            Ok(config)
        }
        _ => {
            // Default to YAML
            let config: Config = serde_yaml::from_str(&content)?;
            info!("Loaded YAML configuration from: {}", path.display());
            Ok(config)
        }
    }
}

/// Shows configuration in requested format
fn show_config(
    config: &Config,
    format: ConfigFormat,
    user_config: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let output = match format {
        ConfigFormat::Json => serde_json::to_string_pretty(config)?,
        ConfigFormat::Toml => toml::to_string_pretty(config)?,
        ConfigFormat::Yaml => serde_yaml::to_string(config)?,
    };

    if user_config {
        println!("User configuration (effective values):");
    }
    println!("{output}");
    Ok(())
}

/// -------------------------------------------------------------------
/// CLASSIFICATION & CPU
/// -------------------------------------------------------------------

// Static Arc<str> for default classification values to avoid repeated allocations
static OTHER_STR: Lazy<Arc<str>> = Lazy::new(|| Arc::from("other"));
static UNKNOWN_STR: Lazy<Arc<str>> = Lazy::new(|| Arc::from("unknown"));

/// Classifies a process into group and subgroup based on process name (raw)
fn classify_process_raw(process_name: &str) -> (Arc<str>, Arc<str>) {
    SUBGROUPS
        .get(process_name)
        .map(|(g, sg)| (Arc::clone(g), Arc::clone(sg)))
        .unwrap_or_else(|| (Arc::clone(&OTHER_STR), Arc::clone(&UNKNOWN_STR)))
}

/// Classification inklusive Config-Regeln (include/exclude, disable_others)
fn classify_process_with_config(process_name: &str, cfg: &Config) -> Option<(Arc<str>, Arc<str>)> {
    let (group, subgroup) = classify_process_raw(process_name);

    // If user explicitly disabled "other" bucket, drop these processes
    let disable_others = cfg.disable_others.unwrap_or(false);
    if disable_others && group.as_ref() == "other" {
        return None;
    }

    // Apply include/exclude/search-mode logic
    let mode = cfg.search_mode.as_deref().unwrap_or("none");

    let group_match = cfg
        .search_groups
        .as_ref()
        .is_some_and(|v| v.iter().any(|g| g == group.as_ref()));
    let subgroup_match = cfg
        .search_subgroups
        .as_ref()
        .is_some_and(|v| v.iter().any(|sg| sg == subgroup.as_ref()));

    let allowed = match mode {
        "include" => {
            // Only these groups/subgroups
            group_match || subgroup_match
        }
        "exclude" => {
            // Everything except these groups/subgroups
            !(group_match || subgroup_match)
        }
        _ => true, // no filter
    };

    if !allowed {
        return None;
    }

    // Normalize: treat all "unknown" subgroups in the "other" group as "other"
    // so that subgroup "unknown" does not appear in exports.
    if group.as_ref().eq_ignore_ascii_case("other") {
        Some((Arc::clone(&OTHER_STR), Arc::clone(&OTHER_STR)))
    } else {
        Some((group, subgroup))
    }
}

/// Parse total CPU time (user+system) in seconds from /proc/<pid>/stat
fn parse_cpu_time_seconds(proc_path: &Path) -> Result<f64, std::io::Error> {
    let stat_path = proc_path.join("stat");
    let content = fs::read_to_string(stat_path)?;

    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.len() <= 14 {
        return Err(std::io::Error::other("Invalid stat format"));
    }

    let utime: f64 = parts[13].parse().unwrap_or(0.0);
    let stime: f64 = parts[14].parse().unwrap_or(0.0);

    // Use system-detected clock ticks per second
    Ok((utime + stime) / *CLK_TCK)
}

/// Returns CPU stats for a PID using delta between samples
fn get_cpu_stat_for_pid(
    pid: u32,
    proc_path: &Path,
    cache: &StdRwLock<HashMap<u32, CpuEntry>>,
) -> CpuStat {
    let now = Instant::now();
    let cpu_time_seconds = match parse_cpu_time_seconds(proc_path) {
        Ok(v) => v,
        Err(e) => {
            debug!("Failed to read CPU time for pid {}: {}", pid, e);
            0.0
        }
    };

    let mut cpu_percent = 0.0;

    // Use delta between last and current CPU time to compute percent
    {
        let cache_read = cache.read().expect("cpu_cache read lock poisoned");
        if let Some(entry) = cache_read.get(&pid) {
            let dt = now.duration_since(entry.last_updated).as_secs_f64();
            if dt > 0.0 {
                let delta_cpu = cpu_time_seconds - entry.stat.cpu_time_seconds;
                if delta_cpu > 0.0 {
                    cpu_percent = (delta_cpu / dt) * 100.0;
                }
            }
        }
    }

    let stat = CpuStat {
        cpu_percent,
        cpu_time_seconds,
    };

    // Store updated value in cache
    {
        let mut cache_write = cache.write().expect("cpu_cache write lock poisoned");
        cache_write.insert(
            pid,
            CpuEntry {
                stat,
                last_updated: now,
            },
        );
    }

    stat
}

/// Initializes tracing logging subsystem with configured log level
fn setup_logging(_config: &Config, args: &Args) {
    let log_level = match args.log_level {
        LogLevel::Off => Level::ERROR, // Off not fully supported, use ERROR as minimal
        LogLevel::Error => Level::ERROR,
        LogLevel::Warn => Level::WARN,
        LogLevel::Info => Level::INFO,
        LogLevel::Debug => Level::DEBUG,
        LogLevel::Trace => Level::TRACE,
    };

    let subscriber = tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(true)
        .with_thread_ids(false)
        .with_file(true)
        .with_line_number(true)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");

    info!("Logging initialized with level: {:?}", args.log_level);
}

/// Resolve effective buffer sizes (CLI > config > defaults)
fn resolve_buffer_config(cfg: &Config, args: &Args) -> BufferConfig {
    // Precedence: CLI (if provided) > config file > hard-coded default.
    let io_kb = args
        .io_buffer_kb
        .unwrap_or_else(|| cfg.io_buffer_kb.unwrap_or(256));
    let smaps_kb = args
        .smaps_buffer_kb
        .unwrap_or_else(|| cfg.smaps_buffer_kb.unwrap_or(512));
    let smaps_rollup_kb = args
        .smaps_rollup_buffer_kb
        .unwrap_or_else(|| cfg.smaps_rollup_buffer_kb.unwrap_or(256));

    BufferConfig {
        io_kb,
        smaps_kb,
        smaps_rollup_kb,
    }
}

/// -------------------------------------------------------------------
/// MAIN APPLICATION ENTRY POINT
/// -------------------------------------------------------------------
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Early config resolution for show/check modes
    if args.show_config || args.show_user_config || args.check_config {
        let config = resolve_config(&args)?;

        if args.check_config {
            if let Err(e) = validate_effective_config(&config) {
                eprintln!("❌ Configuration invalid: {}", e);
                std::process::exit(1);
            }
            println!("✅ Configuration is valid");
            return Ok(());
        }

        if args.show_config {
            return show_config(&config, args.config_format, false);
        }

        if args.show_user_config {
            return show_config(&config, args.config_format, true);
        }
    }

    // Handle subcommands
    if let Some(command) = &args.command {
        let config = resolve_config(&args)?;
        // Validation is also useful for subcommands
        if let Err(e) = validate_effective_config(&config) {
            eprintln!("❌ Configuration invalid: {}", e);
            std::process::exit(1);
        }

        return match command {
            Commands::Check { memory, proc, all } => command_check(*memory, *proc, *all, &config),
            Commands::Config {
                output,
                format,
                commented,
            } => command_config(output.clone(), format.clone(), *commented),
            Commands::Test {
                iterations,
                verbose,
                format,
            } => command_test(*iterations, *verbose, format.clone(), &config),
            Commands::Subgroups { verbose, group } => command_subgroups(*verbose, group.clone()),
            Commands::GenerateTestdata {
                output,
                min_per_subgroup,
                others_count,
            } => {
                command_generate_testdata(output.clone(), *min_per_subgroup, *others_count, &config)
            }
        };
    }

    // Load configuration for main server mode
    let config = resolve_config(&args)?;

    // Validate config before starting exporter
    if let Err(e) = validate_effective_config(&config) {
        eprintln!("❌ Configuration invalid: {}", e);
        std::process::exit(1);
    }

    // Setup logging subsystem first to enable proper logging
    setup_logging(&config, &args);

    info!("Starting herakles-proc-mem-exporter");

    // Determine bind ip and port from effective config
    let bind_ip_str = config.bind.as_deref().unwrap_or(DEFAULT_BIND_ADDR);
    let port = config.port.unwrap_or(DEFAULT_PORT);

    // Configure parallel processing thread pool if specified
    if let Some(threads) = config.parallelism {
        if threads > 0 {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build_global()
                .unwrap_or_else(|e| error!("Failed to set rayon thread pool: {}", e));
            debug!("Rayon thread pool configured with {} threads", threads);
        }
    }

    // Resolve buffer configuration (CLI > config > defaults)
    let buffer_config = resolve_buffer_config(&config, &args);

    // Initialize Prometheus metrics registry
    let registry = Registry::new();
    debug!("Prometheus registry initialized");

    // Create and register all metric sets
    let metrics = MemoryMetrics::new(&registry)?;
    let scrape_duration = Gauge::new(
        "herakles_proc_mem_scrape_duration_seconds",
        "Time spent serving /metrics request (reading from cache)",
    )?;
    let processes_total = Gauge::new(
        "herakles_proc_mem_processes_total",
        "Number of processes currently exported by herakles-proc-mem-exporter",
    )?;
    let cache_update_duration = Gauge::new(
        "herakles_proc_mem_cache_update_duration_seconds",
        "Time spent updating the process metrics cache in background",
    )?;
    let cache_update_success = Gauge::new(
        "herakles_proc_mem_cache_update_success",
        "Whether the last cache update was successful (1) or failed (0)",
    )?;
    let cache_updating = Gauge::new(
        "herakles_proc_mem_cache_updating",
        "Whether cache update is currently in progress (1) or idle (0)",
    )?;

    registry.register(Box::new(scrape_duration.clone()))?;
    registry.register(Box::new(processes_total.clone()))?;
    registry.register(Box::new(cache_update_duration.clone()))?;
    registry.register(Box::new(cache_update_success.clone()))?;
    registry.register(Box::new(cache_updating.clone()))?;

    debug!("All metrics registered successfully");

    // Initialize HealthStats instance used by AppState
    let health_stats = Arc::new(HealthStats::new());
    // Create shared application state
    let state = Arc::new(AppState {
        registry,
        metrics,
        scrape_duration,
        processes_total,
        cache_update_duration,
        cache_update_success,
        cache_updating,
        cache: Arc::new(RwLock::new(MetricsCache::default())),
        config: Arc::new(config.clone()),
        buffer_config,
        cpu_cache: StdRwLock::new(HashMap::new()),
        health_stats: health_stats.clone(),
        cache_ready: Arc::new(Notify::new()),
    });

    // Perform initial cache population before starting server
    info!("Performing initial cache update");
    if let Err(e) = update_cache(&state).await {
        error!("Initial cache update failed: {}", e);
    } else {
        info!("Initial cache update completed successfully");
    }

    // Start background cache refresh task
    let bg_state = state.clone();
    //let ttl = Duration::from_secs(args.cache_ttl);
    let ttl = Duration::from_secs(state.config.cache_ttl.unwrap_or(DEFAULT_CACHE_TTL));

    let background_task = tokio::spawn(async move {
        let mut int = interval(ttl);
        debug!(
            "Background cache update task started with {}s interval",
            ttl.as_secs()
        );

        loop {
            int.tick().await;
            debug!("Starting scheduled cache update");
            if let Err(e) = update_cache(&bg_state).await {
                error!("Scheduled cache update failed: {}", e);
            } else {
                debug!("Scheduled cache update completed");
            }
        }
    });

    // Setup graceful shutdown signal handlers
    let shutdown_signal = async {
        let ctrl_c = async {
            signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to install signal handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {
                info!("Received SIGINT (Ctrl+C), shutting down gracefully...");
            }
            _ = terminate => {
                info!("Received SIGTERM, shutting down gracefully...");
            }
        }
    };

    // Configure HTTP server routes and start listening
    let addr: SocketAddr = format!("{}:{}", bind_ip_str, port).parse()?;

    let mut app = Router::new().route("/metrics", get(metrics_handler));

    // Conditionally add health endpoint
    if config.enable_health.unwrap_or(true) {
        app = app.route("/health", get(health_handler));
    }

    // Add config and subgroups endpoints
    app = app
        .route("/config", get(config_handler))
        .route("/subgroups", get(subgroups_handler))
        .route("/doc", get(doc_handler));

    // Conditionally add pprof endpoints for debugging
    if config.enable_pprof.unwrap_or(false) {
        debug!("Debug endpoints enabled at /debug/pprof");
        // pprof-rs integration could be added here
    }

    let app = app.with_state(state.clone());

    let listener = TcpListener::bind(addr).await?;
    info!(
        "herakles-proc-mem-exporter listening on http://{}:{}",
        bind_ip_str, port
    );

    // Start HTTP server with graceful shutdown capability
    let server = axum::serve(listener, app);

    tokio::select! {
        result = server => {
            if let Err(e) = result {
                error!("Server error: {}", e);
                return Err(e.into());
            }
        }
        _ = shutdown_signal => {
            info!("Shutdown signal received, exiting...");
        }
    }

    // Cleanup: cancel background task before exit
    background_task.abort();
    let _ = background_task.await;

    info!("herakles-proc-mem-exporter stopped gracefully");
    Ok(())
}

/// -------------------------------------------------------------------
/// METRICS ENDPOINT HANDLER
/// -------------------------------------------------------------------
#[instrument(skip(state))]
async fn metrics_handler(State(state): State<SharedState>) -> Result<String, MetricsError> {
    let start = Instant::now();
    debug!("Processing /metrics request");

    // Wait for cache to be available (not currently updating)
    loop {
        let cache_guard = state.cache.read().await;
        if !cache_guard.is_updating {
            let processes_vec: Vec<ProcMem> = cache_guard.processes.values().cloned().collect();
            let meta = (
                cache_guard.update_duration_seconds,
                cache_guard.update_success,
                cache_guard.is_updating,
            );

            drop(cache_guard);

            // Update cache metadata metrics
            state.cache_update_duration.set(meta.0);
            state
                .cache_update_success
                .set(if meta.1 { 1.0 } else { 0.0 });
            state.cache_updating.set(if meta.2 { 1.0 } else { 0.0 });

            // Reset metrics before populating with fresh data
            state.metrics.reset();

            let cfg = &state.config;
            let enable_rss = cfg.enable_rss.unwrap_or(true);
            let enable_pss = cfg.enable_pss.unwrap_or(true);
            let enable_uss = cfg.enable_uss.unwrap_or(true);
            let enable_cpu = cfg.enable_cpu.unwrap_or(true);

            // Aggregation map
            // Aggregation map
            let mut groups: HashMap<(Arc<str>, Arc<str>), Vec<&ProcMem>> = HashMap::new();
            let mut exported_count = 0usize;

            // Enforce an overall limit for processes classified as "other".
            // CLI/config precedence ensures top_n_others is taken from config (or default).
            let mut other_exported = 0usize;
            let other_limit = state.config.top_n_others.unwrap_or(10);

            // Populate per-process metrics + prepare aggregation
            for p in &processes_vec {
                if let Some((group, subgroup)) =
                    classify_process_with_config(&p.name, &state.config)
                {
                    // If this is the "other" group, enforce the configured per-group limit.
                    if group.as_ref().eq_ignore_ascii_case("other") {
                        if other_exported >= other_limit {
                            // skip process to limit cardinality for 'other'
                            continue;
                        }
                        other_exported += 1;
                    }

                    exported_count += 1;
                    let pid_str = p.pid.to_string();

                    state.metrics.set_for_process(
                        &pid_str,
                        &p.name,
                        group.as_ref(),
                        subgroup.as_ref(),
                        p.rss,
                        p.pss,
                        p.uss,
                        p.cpu_percent as f64,
                        p.cpu_time_seconds as f64,
                        &state.config,
                    );

                    groups.entry((group, subgroup)).or_default().push(p);
                }
            }

            state.processes_total.set(exported_count as f64);
            state.scrape_duration.set(start.elapsed().as_secs_f64());

            // ------------------------------------------------------------
            // Aggregated sums and Top-N metrics per subgroup
            // ------------------------------------------------------------
            for ((group, subgroup), mut list) in groups {
                let mut rss_sum: u64 = 0;
                let mut pss_sum: u64 = 0;
                let mut uss_sum: u64 = 0;
                let mut cpu_percent_sum: f64 = 0.0;
                let mut cpu_time_sum: f64 = 0.0;

                for p in &list {
                    rss_sum += p.rss;
                    pss_sum += p.pss;
                    uss_sum += p.uss;
                    cpu_percent_sum += p.cpu_percent as f64;
                    cpu_time_sum += p.cpu_time_seconds as f64;
                }

                // Get references to the Arc<str> contents for use with prometheus labels
                let group_ref: &str = group.as_ref();
                let subgroup_ref: &str = subgroup.as_ref();

                // Set aggregation metrics (respect enable_* flags)
                if enable_rss {
                    state
                        .metrics
                        .agg_rss_sum
                        .with_label_values(&[group_ref, subgroup_ref])
                        .set(rss_sum as f64);
                }
                if enable_pss {
                    state
                        .metrics
                        .agg_pss_sum
                        .with_label_values(&[group_ref, subgroup_ref])
                        .set(pss_sum as f64);
                }
                if enable_uss {
                    state
                        .metrics
                        .agg_uss_sum
                        .with_label_values(&[group_ref, subgroup_ref])
                        .set(uss_sum as f64);
                }
                if enable_cpu {
                    state
                        .metrics
                        .agg_cpu_percent_sum
                        .with_label_values(&[group_ref, subgroup_ref])
                        .set(cpu_percent_sum);
                    state
                        .metrics
                        .agg_cpu_time_sum
                        .with_label_values(&[group_ref, subgroup_ref])
                        .set(cpu_time_sum);
                }

                // Sort by USS for Top-N selection
                list.sort_by_key(|p| std::cmp::Reverse(p.uss));

                // Treat both "other" and "others" (case-insensitive) as the special bucket.
                let is_other_group = group_ref.eq_ignore_ascii_case("other")
                    || group_ref.eq_ignore_ascii_case("others")
                    || subgroup_ref.eq_ignore_ascii_case("other")
                    || subgroup_ref.eq_ignore_ascii_case("others");

                // Obtain configured Top-N values with safe defaults.
                let top_subgroup = state.config.top_n_subgroup.unwrap_or(3);
                let top_others = state.config.top_n_others.unwrap_or(10);
                // Ensure the limit is at least 1 (avoid accidental 0)
                let limit = if is_other_group {
                    std::cmp::max(1, top_others)
                } else {
                    std::cmp::max(1, top_subgroup)
                };

                let rss_total = rss_sum as f64;
                let pss_total = pss_sum as f64;
                let uss_total = uss_sum as f64;
                let cpu_total = cpu_time_sum;

                for (rank, p) in list.iter().take(limit).enumerate() {
                    let pid_s = p.pid.to_string();
                    let rank_s = (rank + 1).to_string();
                    let name_s = p.name.as_str();

                    // Absolute Top-N values
                    if enable_rss {
                        state
                            .metrics
                            .top_rss
                            .with_label_values(&[group_ref, subgroup_ref, &rank_s, &pid_s, name_s])
                            .set(p.rss as f64);
                    }
                    if enable_pss {
                        state
                            .metrics
                            .top_pss
                            .with_label_values(&[group_ref, subgroup_ref, &rank_s, &pid_s, name_s])
                            .set(p.pss as f64);
                    }
                    if enable_uss {
                        state
                            .metrics
                            .top_uss
                            .with_label_values(&[group_ref, subgroup_ref, &rank_s, &pid_s, name_s])
                            .set(p.uss as f64);
                    }
                    if enable_cpu {
                        state
                            .metrics
                            .top_cpu_percent
                            .with_label_values(&[group_ref, subgroup_ref, &rank_s, &pid_s, name_s])
                            .set(p.cpu_percent as f64);
                        state
                            .metrics
                            .top_cpu_time
                            .with_label_values(&[group_ref, subgroup_ref, &rank_s, &pid_s, name_s])
                            .set(p.cpu_time_seconds as f64);
                    }

                    // Percentage-of-subgroup values
                    if enable_cpu && cpu_total > 0.0 {
                        let pct = (p.cpu_time_seconds as f64 / cpu_total) * 100.0;
                        state
                            .metrics
                            .top_cpu_percent_of_subgroup
                            .with_label_values(&[group_ref, subgroup_ref, &rank_s, &pid_s, name_s])
                            .set(pct);
                    }

                    if enable_rss && rss_total > 0.0 {
                        let pct = (p.rss as f64 / rss_total) * 100.0;
                        state
                            .metrics
                            .top_rss_percent_of_subgroup
                            .with_label_values(&[group_ref, subgroup_ref, &rank_s, &pid_s, name_s])
                            .set(pct);
                    }

                    if enable_pss && pss_total > 0.0 {
                        let pct = (p.pss as f64 / pss_total) * 100.0;
                        state
                            .metrics
                            .top_pss_percent_of_subgroup
                            .with_label_values(&[group_ref, subgroup_ref, &rank_s, &pid_s, name_s])
                            .set(pct);
                    }

                    if enable_uss && uss_total > 0.0 {
                        let pct = (p.uss as f64 / uss_total) * 100.0;
                        state
                            .metrics
                            .top_uss_percent_of_subgroup
                            .with_label_values(&[group_ref, subgroup_ref, &rank_s, &pid_s, name_s])
                            .set(pct);
                    }
                }
            }

            // Encode metrics in Prometheus text format
            let families = state.registry.gather();

            // Calculate label cardinality (total number of label pairs across all metrics)
            let mut label_count: u64 = 0;
            for family in &families {
                for metric in family.get_metric() {
                    label_count += metric.get_label().len() as u64;
                }
            }
            state.health_stats.record_label_cardinality(label_count);

            let mut buffer = Vec::with_capacity(BUFFER_CAP);
            let encoder = TextEncoder::new();

            if encoder.encode(&families, &mut buffer).is_err() {
                error!("Failed to encode Prometheus metrics");
                return Err(MetricsError::EncodingFailed);
            }

            // Record metrics request statistics
            let request_duration_ms = start.elapsed().as_secs_f64() * 1000.0;
            state.health_stats.record_metrics_endpoint_call();
            state
                .health_stats
                .record_request_duration(request_duration_ms);
            state.health_stats.record_http_request();
            state.health_stats.record_cache_hit();

            debug!(
                "Metrics request completed: {} processes (exported {}), {} bytes, {:.3}ms",
                processes_vec.len(),
                exported_count,
                buffer.len(),
                request_duration_ms
            );

            return String::from_utf8(buffer).map_err(|_| MetricsError::EncodingFailed);
        }

        drop(cache_guard);
        // Wait for notification that cache update is complete instead of busy-waiting
        state.cache_ready.notified().await;
    }
}

/// -------------------------------------------------------------------
/// HEALTH CHECK ENDPOINT HANDLER
/// -------------------------------------------------------------------
#[instrument(skip(state))]
async fn health_handler(State(state): State<SharedState>) -> impl IntoResponse {
    debug!("Processing /health request");

    // Track HTTP request for health endpoint
    state.health_stats.record_http_request();

    let cache = state.cache.read().await;

    // derive HTTP status from cache state
    let status = if cache.update_success && cache.last_updated.is_some() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    // short status message for human-readable heading
    let message = if cache.is_updating {
        "OK - Cache updating"
    } else if cache.update_success {
        "OK"
    } else {
        "Cache update failed"
    };

    // render plain-text table from HealthStats
    let table = state.health_stats.render_table();

    debug!("Health check: {} - {}", status, message);
    (status, format!("{message}\n\n{table}"))
}

/// Escapes special HTML characters to prevent XSS attacks
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// -------------------------------------------------------------------
/// CONFIG ENDPOINT HANDLER
/// -------------------------------------------------------------------
/// Renders the current configuration as an HTML table
#[instrument(skip(state))]
async fn config_handler(State(state): State<SharedState>) -> impl IntoResponse {
    debug!("Processing /config request");

    // Track HTTP request
    state.health_stats.record_http_request();

    let cfg = &state.config;

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Herakles Proc Mem Exporter - Configuration</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            margin: 40px;
            background-color: #f5f5f5;
            color: #333;
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            max-width: 800px;
            background-color: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }}
        th, td {{
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }}
        th {{
            background-color: #3498db;
            color: white;
            font-weight: 600;
        }}
        tr:hover {{
            background-color: #f8f9fa;
        }}
        tr:last-child td {{
            border-bottom: none;
        }}
        .value {{
            font-family: 'Monaco', 'Consolas', monospace;
            color: #27ae60;
        }}
        .section {{
            margin-top: 30px;
            margin-bottom: 10px;
            font-size: 1.2em;
            color: #34495e;
            font-weight: 600;
        }}
    </style>
</head>
<body>
    <h1>Herakles Proc Mem Exporter - Configuration</h1>
    
    <div class="section">Server Configuration</div>
    <table>
        <tr><th>Parameter</th><th>Value</th></tr>
        <tr><td>bind</td><td class="value">{}</td></tr>
        <tr><td>port</td><td class="value">{}</td></tr>
        <tr><td>cache_ttl</td><td class="value">{} seconds</td></tr>
    </table>

    <div class="section">Metrics Collection</div>
    <table>
        <tr><th>Parameter</th><th>Value</th></tr>
        <tr><td>min_uss_kb</td><td class="value">{}</td></tr>
        <tr><td>include_names</td><td class="value">{}</td></tr>
        <tr><td>exclude_names</td><td class="value">{}</td></tr>
        <tr><td>parallelism</td><td class="value">{}</td></tr>
        <tr><td>max_processes</td><td class="value">{}</td></tr>
        <tr><td>top_n_subgroup</td><td class="value">{}</td></tr>
        <tr><td>top_n_others</td><td class="value">{}</td></tr>
    </table>

    <div class="section">Performance Tuning</div>
    <table>
        <tr><th>Parameter</th><th>Value</th></tr>
        <tr><td>io_buffer_kb</td><td class="value">{}</td></tr>
        <tr><td>smaps_buffer_kb</td><td class="value">{}</td></tr>
        <tr><td>smaps_rollup_buffer_kb</td><td class="value">{}</td></tr>
    </table>

    <div class="section">Feature Flags</div>
    <table>
        <tr><th>Parameter</th><th>Value</th></tr>
        <tr><td>enable_health</td><td class="value">{}</td></tr>
        <tr><td>enable_telemetry</td><td class="value">{}</td></tr>
        <tr><td>enable_default_collectors</td><td class="value">{}</td></tr>
        <tr><td>enable_pprof</td><td class="value">{}</td></tr>
    </table>

    <div class="section">Metrics Flags</div>
    <table>
        <tr><th>Parameter</th><th>Value</th></tr>
        <tr><td>enable_rss</td><td class="value">{}</td></tr>
        <tr><td>enable_pss</td><td class="value">{}</td></tr>
        <tr><td>enable_uss</td><td class="value">{}</td></tr>
        <tr><td>enable_cpu</td><td class="value">{}</td></tr>
    </table>

    <div class="section">Classification</div>
    <table>
        <tr><th>Parameter</th><th>Value</th></tr>
        <tr><td>search_mode</td><td class="value">{}</td></tr>
        <tr><td>search_groups</td><td class="value">{}</td></tr>
        <tr><td>search_subgroups</td><td class="value">{}</td></tr>
        <tr><td>disable_others</td><td class="value">{}</td></tr>
    </table>

    <div class="section">Logging</div>
    <table>
        <tr><th>Parameter</th><th>Value</th></tr>
        <tr><td>log_level</td><td class="value">{}</td></tr>
        <tr><td>enable_file_logging</td><td class="value">{}</td></tr>
        <tr><td>log_file</td><td class="value">{}</td></tr>
    </table>

    <div class="section">Test Data</div>
    <table>
        <tr><th>Parameter</th><th>Value</th></tr>
        <tr><td>test_data_file</td><td class="value">{}</td></tr>
    </table>
</body>
</html>"#,
        // Server Configuration
        html_escape(cfg.bind.as_deref().unwrap_or(DEFAULT_BIND_ADDR)),
        cfg.port.unwrap_or(DEFAULT_PORT),
        cfg.cache_ttl.unwrap_or(DEFAULT_CACHE_TTL),
        // Metrics Collection
        cfg.min_uss_kb.unwrap_or(0),
        html_escape(
            &cfg.include_names
                .as_ref()
                .map(|v| v.join(", "))
                .unwrap_or_else(|| "none".to_string())
        ),
        html_escape(
            &cfg.exclude_names
                .as_ref()
                .map(|v| v.join(", "))
                .unwrap_or_else(|| "none".to_string())
        ),
        cfg.parallelism
            .map(|v| v.to_string())
            .unwrap_or_else(|| "auto".to_string()),
        cfg.max_processes
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unlimited".to_string()),
        cfg.top_n_subgroup.unwrap_or(3),
        cfg.top_n_others.unwrap_or(10),
        // Performance Tuning
        cfg.io_buffer_kb.unwrap_or(256),
        cfg.smaps_buffer_kb.unwrap_or(512),
        cfg.smaps_rollup_buffer_kb.unwrap_or(256),
        // Feature Flags
        cfg.enable_health.unwrap_or(true),
        cfg.enable_telemetry.unwrap_or(true),
        cfg.enable_default_collectors.unwrap_or(true),
        cfg.enable_pprof.unwrap_or(false),
        // Metrics Flags
        cfg.enable_rss.unwrap_or(true),
        cfg.enable_pss.unwrap_or(true),
        cfg.enable_uss.unwrap_or(true),
        cfg.enable_cpu.unwrap_or(true),
        // Classification
        html_escape(cfg.search_mode.as_deref().unwrap_or("none")),
        html_escape(
            &cfg.search_groups
                .as_ref()
                .map(|v| v.join(", "))
                .unwrap_or_else(|| "none".to_string())
        ),
        html_escape(
            &cfg.search_subgroups
                .as_ref()
                .map(|v| v.join(", "))
                .unwrap_or_else(|| "none".to_string())
        ),
        cfg.disable_others.unwrap_or(false),
        // Logging
        html_escape(cfg.log_level.as_deref().unwrap_or("info")),
        cfg.enable_file_logging.unwrap_or(false),
        html_escape(
            &cfg.log_file
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "none".to_string())
        ),
        // Test Data
        html_escape(
            &cfg.test_data_file
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "none".to_string())
        ),
    );

    (
        StatusCode::OK,
        [("Content-Type", "text/html; charset=utf-8")],
        html,
    )
}

/// -------------------------------------------------------------------
/// SUBGROUPS ENDPOINT HANDLER
/// -------------------------------------------------------------------
/// Renders the monitored subgroups as an HTML table
#[instrument(skip(state))]
async fn subgroups_handler(State(state): State<SharedState>) -> impl IntoResponse {
    debug!("Processing /subgroups request");

    // Track HTTP request
    state.health_stats.record_http_request();

    // Collect unique (group, subgroup) pairs with their associated process name matches
    let mut subgroup_data: HashMap<(String, String), Vec<String>> = HashMap::new();

    for (process_name, (group, subgroup)) in SUBGROUPS.iter() {
        let key = (group.to_string(), subgroup.to_string());
        subgroup_data
            .entry(key)
            .or_default()
            .push(process_name.to_string());
    }

    // Sort by group then subgroup for consistent output
    let mut sorted_entries: Vec<_> = subgroup_data.into_iter().collect();
    sorted_entries.sort_by(|a, b| {
        let group_cmp = a.0 .0.cmp(&b.0 .0);
        if group_cmp == std::cmp::Ordering::Equal {
            a.0 .1.cmp(&b.0 .1)
        } else {
            group_cmp
        }
    });

    // Count unique subgroups
    let unique_subgroups_count = sorted_entries.len();

    // Build HTML table rows
    let mut table_rows = String::new();
    for ((group, subgroup), mut matches) in sorted_entries {
        matches.sort();
        let matches_str = matches.join(", ");
        table_rows.push_str(&format!(
            "        <tr><td>{}</td><td>{}</td><td class=\"matches\">{}</td></tr>\n",
            html_escape(&group),
            html_escape(&subgroup),
            html_escape(&matches_str)
        ));
    }

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Herakles Proc Mem Exporter - Subgroups</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            margin: 40px;
            background-color: #f5f5f5;
            color: #333;
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }}
        .summary {{
            margin-bottom: 20px;
            padding: 15px;
            background-color: #e8f4f8;
            border-radius: 8px;
            color: #2c3e50;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            background-color: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }}
        th, td {{
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }}
        th {{
            background-color: #3498db;
            color: white;
            font-weight: 600;
        }}
        tr:hover {{
            background-color: #f8f9fa;
        }}
        tr:last-child td {{
            border-bottom: none;
        }}
        .matches {{
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.9em;
            color: #27ae60;
            max-width: 600px;
            word-wrap: break-word;
        }}
    </style>
</head>
<body>
    <h1>Herakles Proc Mem Exporter - Subgroups</h1>
    
    <div class="summary">
        <strong>Total patterns:</strong> {} | <strong>Unique subgroups:</strong> {}
    </div>

    <table>
        <tr><th>Group</th><th>Subgroup</th><th>Process Matches</th></tr>
{}    </table>
</body>
</html>"#,
        SUBGROUPS.len(),
        unique_subgroups_count,
        table_rows,
    );

    (
        StatusCode::OK,
        [("Content-Type", "text/html; charset=utf-8")],
        html,
    )
}

/// -------------------------------------------------------------------
/// DOCUMENTATION ENDPOINT HANDLER
/// -------------------------------------------------------------------
/// Renders comprehensive documentation in plain text format for CLI usage
#[instrument(skip(state))]
async fn doc_handler(State(state): State<SharedState>) -> impl IntoResponse {
    debug!("Processing /doc request");

    // Track HTTP request
    state.health_stats.record_http_request();

    let version = env!("CARGO_PKG_VERSION");
    let doc = format!(
        r#"HERAKLES PROCESS MEMORY EXPORTER - DOCUMENTATION
================================================

VERSION: {}
DESCRIPTION: Prometheus exporter for per-process RSS/PSS/USS and CPU metrics

HTTP ENDPOINTS
--------------
GET /metrics     - Prometheus metrics endpoint
GET /health      - Health check with internal statistics
GET /config      - Current configuration (HTML)
GET /subgroups   - Loaded subgroups overview (HTML)
GET /doc         - This documentation (plain text)

AVAILABLE METRICS
-----------------
herakles_proc_mem_rss_bytes              - Resident Set Size per process
herakles_proc_mem_pss_bytes              - Proportional Set Size per process
herakles_proc_mem_uss_bytes              - Unique Set Size per process
herakles_proc_mem_cpu_percent            - CPU usage per process
herakles_proc_mem_cpu_time_seconds       - Total CPU time per process

herakles_proc_mem_group_*_sum            - Aggregated metrics per subgroup
herakles_proc_mem_top_*                  - Top-N metrics per subgroup

CONFIGURATION
-------------
Config file locations (in order):
1. CLI specified: -c /path/to/config.yaml
2. Current directory: ./herakles-proc-mem-exporter.yaml
3. User config: ~/.config/herakles/config.yaml
4. System config: /etc/herakles/config.yaml

Key configuration options:
- port: HTTP listen port (default: 9215)
- bind: Bind address (default: 0.0.0.0)
- cache_ttl: Cache TTL in seconds (default: 30)
- min_uss_kb: Minimum USS threshold (default: 0)
- top_n_subgroup: Top-N processes per subgroup (default: 3)
- top_n_others: Top-N processes for "other" group (default: 10)

CLI COMMANDS
------------
herakles-proc-mem-exporter                    - Start the exporter
herakles-proc-mem-exporter check --all        - Validate system requirements
herakles-proc-mem-exporter config -o config.yaml - Generate config file
herakles-proc-mem-exporter test               - Test metrics collection
herakles-proc-mem-exporter subgroups          - List available subgroups
herakles-proc-mem-exporter --help             - Show all CLI options

EXAMPLE USAGE
-------------
# Start exporter
herakles-proc-mem-exporter

# View this documentation
curl http://localhost:9215/doc

# Get metrics
curl http://localhost:9215/metrics

# Check health
curl http://localhost:9215/health

EXAMPLE PROMQL QUERIES
----------------------
# Top 10 processes by USS memory
topk(10, herakles_proc_mem_uss_bytes)

# Memory usage by group
sum by (group) (herakles_proc_mem_rss_bytes)

# CPU usage by subgroup
sum by (group, subgroup) (herakles_proc_mem_cpu_percent)

# Process count per subgroup
count by (group, subgroup) (herakles_proc_mem_uss_bytes)

PROMETHEUS SCRAPE CONFIG
------------------------
scrape_configs:
  - job_name: 'herakles-proc-mem'
    static_configs:
      - targets: ['localhost:9215']
    scrape_interval: 60s
    scrape_timeout: 30s

MORE INFORMATION
----------------
GitHub: https://github.com/herakles-io/herakles-proc-mem-exporter
Documentation: See /config and /subgroups endpoints for runtime info
"#,
        version
    );

    (
        StatusCode::OK,
        [("Content-Type", "text/plain; charset=utf-8")],
        doc,
    )
}

/// -------------------------------------------------------------------
/// CACHE UPDATE FUNCTION
/// -------------------------------------------------------------------
#[instrument(skip(state))]
async fn update_cache(state: &SharedState) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    info!("Starting cache update");

    // Mark cache as updating (keep old data until new snapshot is ready)
    {
        let mut cache = state.cache.write().await;
        cache.is_updating = true;
        cache.update_success = false;
        state.cache_updating.set(1.0);
        debug!("Cache marked as updating (old snapshot still available)");
    }

    // Apply configuration filters
    let min_uss_bytes = state.config.min_uss_kb.unwrap_or(0) * 1024;

    // Use atomic counters for thread-safe progress tracking
    use std::sync::atomic::{AtomicUsize, Ordering};
    let included_count = AtomicUsize::new(0);
    let skipped_count = AtomicUsize::new(0);

    // Collect process metrics either from test data file or /proc filesystem
    let results: Vec<ProcMem> = if let Some(test_file) = &state.config.test_data_file {
        info!("Using test data from file: {}", test_file.display());

        // Handle error case first, without any awaits in the error path
        let test_data = match load_test_data_from_file(test_file) {
            Ok(data) => data,
            Err(err_msg) => {
                error!("Failed to load test data: {}", err_msg);
                state.health_stats.record_scan_failure();
                // Mark cache as no longer updating on error
                {
                    let mut cache = state.cache.write().await;
                    cache.is_updating = false;
                    state.cache_updating.set(0.0);
                }
                return Err(err_msg.into());
            }
        };

        info!("Loaded {} test processes", test_data.processes.len());

        // Apply filters to test data as well
        test_data
            .processes
            .into_iter()
            .filter_map(|tp| {
                // Apply include/exclude filters
                if !should_include_process(&tp.name, &state.config) {
                    debug!("Skipping process {}: filtered by name config", tp.name);
                    skipped_count.fetch_add(1, Ordering::Relaxed);
                    return None;
                }

                // Apply USS threshold filter
                if tp.uss < min_uss_bytes {
                    debug!(
                        "Skipping process {}: USS {} bytes below threshold {} bytes",
                        tp.name, tp.uss, min_uss_bytes
                    );
                    skipped_count.fetch_add(1, Ordering::Relaxed);
                    return None;
                }

                debug!(
                    "Including test process {}: {} (RSS: {} MB, PSS: {} MB, USS: {} MB, CPU: {:.6}%)",
                    tp.pid,
                    tp.name,
                    tp.rss / 1024 / 1024,
                    tp.pss / 1024 / 1024,
                    tp.uss / 1024 / 1024,
                    tp.cpu_percent
                );

                included_count.fetch_add(1, Ordering::Relaxed);
                Some(ProcMem::from(tp))
            })
            .collect()
    } else {
        // Collect process entries from /proc filesystem
        let entries = collect_proc_entries("/proc", state.config.max_processes);
        debug!("Collected {} process entries from /proc", entries.len());

        // Process entries in parallel and collect metrics
        entries
            .par_iter()
            .filter_map(|entry| {
                let name = match read_process_name(&entry.proc_path) {
                    Some(name) => name,
                    None => {
                        debug!("Skipping process {}: could not read name", entry.pid);
                        skipped_count.fetch_add(1, Ordering::Relaxed);
                        return None;
                    }
                };

                // Apply include/exclude filters
                if !should_include_process(&name, &state.config) {
                    debug!("Skipping process {}: filtered by name config", name);
                    skipped_count.fetch_add(1, Ordering::Relaxed);
                    return None;
                }

                // Parse CPU metrics as delta over last sample
                let cpu = get_cpu_stat_for_pid(entry.pid, &entry.proc_path, &state.cpu_cache);

                // Parse memory metrics with best available strategy
                match parse_memory_for_process(&entry.proc_path, &state.buffer_config) {
                    Ok((rss, pss, uss)) => {
                        if uss < min_uss_bytes {
                            debug!(
                                "Skipping process {}: USS {} bytes below threshold {} bytes",
                                name, uss, min_uss_bytes
                            );
                            skipped_count.fetch_add(1, Ordering::Relaxed);
                            return None;
                        }

                        debug!(
                            "Including process {}: {} (RSS: {} MB, PSS: {} MB, USS: {} MB, CPU: {:.6}%)",
                            entry.pid,
                            name,
                            rss / 1024 / 1024,
                            pss / 1024 / 1024,
                            uss / 1024 / 1024,
                            cpu.cpu_percent
                        );

                        included_count.fetch_add(1, Ordering::Relaxed);
                        Some(ProcMem {
                            pid: entry.pid,
                            name,
                            rss,
                            pss,
                            uss,
                            cpu_percent: cpu.cpu_percent as f32,
                            cpu_time_seconds: cpu.cpu_time_seconds as f32,
                        })
                    }
                    Err(e) => {
                        debug!("Skipping process {}: failed to parse memory: {}", name, e);
                        skipped_count.fetch_add(1, Ordering::Relaxed);
                        None
                    }
                }
            })
            .collect()
    };

    let final_included = included_count.load(Ordering::Relaxed);
    let final_skipped = skipped_count.load(Ordering::Relaxed);

    debug!(
        "Process filtering completed: {} included, {} skipped",
        final_included, final_skipped
    );

    if results.is_empty() {
        warn!("No processes matched filters after sorting");
    }

    // Update cache with new data (swap snapshot under short write lock)
    {
        let mut cache = state.cache.write().await;
        cache.processes.clear();
        for p in &results {
            cache.processes.insert(p.pid, p.clone());
        }

        cache.update_duration_seconds = start.elapsed().as_secs_f64();
        cache.update_success = true;
        cache.last_updated = Some(start);
        cache.is_updating = false;

        state.cache_updating.set(0.0);
    }

    // Notify all waiting handlers that cache update is complete
    state.cache_ready.notify_waiters();

    // Count unique subgroups used in this scan
    use std::collections::HashSet;
    let mut used_subgroups_set: HashSet<(Arc<str>, Arc<str>)> = HashSet::new();
    for p in &results {
        let (group, subgroup) = classify_process_raw(&p.name);
        used_subgroups_set.insert((group, subgroup));
    }
    let subgroups_count = used_subgroups_set.len() as u64;

    // Record completed scan metrics in HealthStats (call outside cache write-lock)
    let scanned = results.len() as u64;
    let scan_duration = start.elapsed().as_secs_f64();
    state
        .health_stats
        .record_scan(scanned, scan_duration, scan_duration);

    // Record new health stats
    state.health_stats.record_scan_success();
    state.health_stats.record_used_subgroups(subgroups_count);
    state.health_stats.record_cache_size(scanned);
    state.health_stats.update_last_scan_time();

    // Read exporter's own resource usage from /proc/self
    let (exporter_mem_mb, exporter_cpu_pct) = read_self_resources();
    state
        .health_stats
        .record_exporter_resources(exporter_mem_mb, exporter_cpu_pct);

    info!(
        "Cache update completed: {} processes (subgroup filters applied at scrape), {} total scanned, {:.2}ms",
        results.len(),
        final_included + final_skipped,
        start.elapsed().as_secs_f64() * 1000.0
    );

    Ok(())
}

/// Scans /proc directory for process entries with numeric PIDs
fn collect_proc_entries(root: &str, max: Option<usize>) -> Vec<ProcEntry> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let p = entry.path();
            let name = match p.file_name().and_then(|s| s.to_str()) {
                Some(v) => v,
                None => continue,
            };
            if !name.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            if !p.join("smaps").exists() && !p.join("smaps_rollup").exists() {
                continue;
            }
            let pid: u32 = match name.parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            out.push(ProcEntry { pid, proc_path: p });
            if let Some(maxp) = max {
                if out.len() >= maxp {
                    break;
                }
            }
        }
    }
    out
}

/// Reads process name from comm file or extracts from cmdline
fn read_process_name(proc_path: &Path) -> Option<String> {
    let comm = proc_path.join("comm");
    if let Ok(s) = fs::read_to_string(&comm) {
        let t = s.trim();
        if !t.is_empty() {
            return Some(t.into());
        }
    }

    let cmd = proc_path.join("cmdline");
    if let Ok(content) = fs::read(&cmd) {
        if !content.is_empty() {
            let parts: Vec<&str> = content
                .split(|&b| b == 0u8)
                .filter_map(|s| std::str::from_utf8(s).ok())
                .collect();
            if !parts.is_empty() {
                if let Some(name) = Path::new(parts[0]).file_name() {
                    return name.to_str().map(|s| s.to_string());
                }
            }
        }
    }
    None
}

/// Fast parser for /proc/<pid>/smaps_rollup (Linux >= 4.14)
/// Much faster than reading the full smaps file.
fn parse_smaps_rollup(path: &Path, buf_kb: usize) -> Result<(u64, u64, u64), std::io::Error> {
    let file = fs::File::open(path)?;
    let reader = BufReader::with_capacity(buf_kb * 1024, file);

    let mut rss_kb = 0;
    let mut pss_kb = 0;
    let mut private_clean_kb = 0;
    let mut private_dirty_kb = 0;

    for line in reader.lines() {
        let l = line?;
        if let Some(v) = l.strip_prefix("Rss:") {
            rss_kb += parse_kb_value(v).unwrap_or(0);
        } else if let Some(v) = l.strip_prefix("Pss:") {
            pss_kb += parse_kb_value(v).unwrap_or(0);
        } else if let Some(v) = l.strip_prefix("Private_Clean:") {
            private_clean_kb += parse_kb_value(v).unwrap_or(0);
        } else if let Some(v) = l.strip_prefix("Private_Dirty:") {
            private_dirty_kb += parse_kb_value(v).unwrap_or(0);
        }
    }

    Ok((
        rss_kb * 1024,
        pss_kb * 1024,
        (private_clean_kb + private_dirty_kb) * 1024,
    ))
}

/// Parses memory metrics from /proc/pid/smaps file
fn parse_smaps(path: &Path, buf_kb: usize) -> Result<(u64, u64, u64), std::io::Error> {
    let file = fs::File::open(path)?;
    let reader = BufReader::with_capacity(buf_kb * 1024, file);

    let mut rss = 0;
    let mut pss = 0;
    let mut pc = 0;
    let mut pd = 0;

    for line in reader.lines() {
        let l = line?;
        if let Some(kb) = l.strip_prefix("Rss:") {
            rss += parse_kb_value(kb).unwrap_or(0);
        } else if let Some(kb) = l.strip_prefix("Pss:") {
            pss += parse_kb_value(kb).unwrap_or(0);
        } else if let Some(kb) = l.strip_prefix("Private_Clean:") {
            pc += parse_kb_value(kb).unwrap_or(0);
        } else if let Some(kb) = l.strip_prefix("Private_Dirty:") {
            pd += parse_kb_value(kb).unwrap_or(0);
        }
    }

    Ok((rss * 1024, pss * 1024, (pc + pd) * 1024))
}

/// Parses kilobyte values from smaps file lines
fn parse_kb_value(v: &str) -> Option<u64> {
    v.split_whitespace().next()?.parse().ok()
}

/// Determines if a process should be included based on configuration filters
fn should_include_process(name: &str, cfg: &Config) -> bool {
    if let Some(ex) = &cfg.exclude_names {
        if ex.iter().any(|s| name.contains(s)) {
            return false;
        }
    }
    if let Some(inc) = &cfg.include_names {
        if !inc.is_empty() {
            return inc.iter().any(|s| name.contains(s));
        }
    }
    true
}

/// Wrapper that selects the fastest available memory parser.
/// Uses smaps_rollup when available, otherwise falls back to full smaps.
fn parse_memory_for_process(
    proc_path: &Path,
    buffers: &BufferConfig,
) -> Result<(u64, u64, u64), std::io::Error> {
    let rollup = proc_path.join("smaps_rollup");
    if rollup.exists() {
        return parse_smaps_rollup(&rollup, buffers.smaps_rollup_kb);
    }

    let smaps = proc_path.join("smaps");
    parse_smaps(&smaps, buffers.smaps_kb)
}

/// Reads the exporter's own memory and CPU usage from /proc/self
/// Returns (memory_mb, cpu_percent)
fn read_self_resources() -> (f64, f64) {
    let memory_mb = read_self_memory_mb().unwrap_or(0.0);
    let cpu_percent = read_self_cpu_percent().unwrap_or(0.0);
    (memory_mb, cpu_percent)
}

/// Reads the exporter's RSS memory usage from /proc/self/status
fn read_self_memory_mb() -> Option<f64> {
    let content = fs::read_to_string("/proc/self/status").ok()?;
    for line in content.lines() {
        if let Some(value) = line.strip_prefix("VmRSS:") {
            let kb: u64 = value.split_whitespace().next()?.parse().ok()?;
            return Some(kb as f64 / 1024.0);
        }
    }
    None
}

/// Reads the exporter's CPU usage from /proc/self/stat
///
/// NOTE: This calculation provides an *average* CPU usage over the exporter's lifetime,
/// not an instantaneous measurement. For long-running processes, this value trends toward
/// the average load and may not reflect current CPU activity. This approach is simpler
/// and doesn't require maintaining state for delta-based calculations, but users should
/// be aware of this limitation when interpreting the value.
fn read_self_cpu_percent() -> Option<f64> {
    // CPU percent estimation from /proc/self/stat
    // Fields 14 (utime) and 15 (stime) are in clock ticks
    let content = fs::read_to_string("/proc/self/stat").ok()?;
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.len() <= 14 {
        return None;
    }

    let utime: f64 = parts[13].parse().ok()?;
    let stime: f64 = parts[14].parse().ok()?;
    let total_ticks = utime + stime;

    // Get system uptime to calculate approximate CPU percentage
    let uptime_content = fs::read_to_string("/proc/uptime").ok()?;
    let uptime_seconds: f64 = uptime_content.split_whitespace().next()?.parse().ok()?;

    if uptime_seconds > 0.0 {
        // Calculate average CPU percentage over lifetime
        // This is (cpu_time_seconds / uptime) * 100
        let cpu_time_seconds = total_ticks / *CLK_TCK;
        Some((cpu_time_seconds / uptime_seconds) * 100.0)
    } else {
        None
    }
}
