// herakles-proc-mem-exporter - version 0.1.0
// Professional memory metrics exporter with tracing logging
use ahash::AHashMap as HashMap;
use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Router};
use clap::{Parser, Subcommand, ValueEnum};
use once_cell::sync::Lazy;
use prometheus::{Encoder, Gauge, GaugeVec, Opts, Registry, TextEncoder};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt::Write as FmtWrite;
use std::sync::RwLock as StdRwLock;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};
use std::{
    fs,
    io::{BufRead, BufReader},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};
use tokio::{
    net::TcpListener,
    signal,
    sync::RwLock,
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
    author = "Michael Moll <proc-mem@herakles.io> - Herakles IO",
    version = "0.1.0",
    propagate_version = true
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
    #[arg(long, default_value_t = 30)]
    cache_ttl: u64,

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
    #[arg(long, default_value_t = 256)]
    io_buffer_kb: usize,

    /// Override buffer size (KB) for /proc/<pid>/smaps
    #[arg(long, default_value_t = 512)]
    smaps_buffer_kb: usize,

    /// Override buffer size (KB) for /proc/<pid>/smaps_rollup
    #[arg(long, default_value_t = 256)]
    smaps_rollup_buffer_kb: usize,

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
fn load_subgroups_from_str(
    content: &str,
    map: &mut HashMap<&'static str, (&'static str, &'static str)>,
) {
    let parsed: SubgroupsConfig = match toml::from_str(content) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to parse subgroups TOML: {}", e);
            return;
        }
    };

    for sg in parsed.subgroups {
        let group_static: &'static str = Box::leak(sg.group.into_boxed_str());
        let subgroup_static: &'static str = Box::leak(sg.subgroup.into_boxed_str());

        if let Some(matches) = sg.matches {
            for m in matches {
                let key_static: &'static str = Box::leak(m.into_boxed_str());
                map.insert(key_static, (group_static, subgroup_static));
            }
        }
        if let Some(cmdlines) = sg.cmdline_matches {
            for cmd in cmdlines {
                let key_static: &'static str = Box::leak(cmd.into_boxed_str());
                map.insert(key_static, (group_static, subgroup_static));
            }
        }
    }
}

/// Helper: load subgroups from TOML file path (if exists)
fn load_subgroups_from_file(
    path: &str,
    map: &mut HashMap<&'static str, (&'static str, &'static str)>,
) {
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
static SUBGROUPS: Lazy<HashMap<&'static str, (&'static str, &'static str)>> = Lazy::new(|| {
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

#[derive(Default)]
struct HealthStats {
    scanned_processes: Stat,
    scan_duration_seconds: Stat,
    cache_update_duration_seconds: Stat,
    total_scans: AtomicU64,
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

    fn render_table(&self) -> String {
        let (sc_cur, sc_avg, sc_max, sc_min, _sc_count) = self.scanned_processes.snapshot();
        let (sd_cur, sd_avg, sd_max, sd_min, _sd_count) = self.scan_duration_seconds.snapshot();
        let (cu_cur, cu_avg, cu_max, cu_min, _cu_count) =
            self.cache_update_duration_seconds.snapshot();
        let total = self.total_scans.load(Ordering::Relaxed);

        let left_col = 26usize;
        let col_w = 12usize;

        let mut out = String::new();

        writeln!(
            out,
            "{:left$} | {:^col$} | {:^col$} | {:^col$} | {:^col$}",
            "metric",
            "current",
            "average",
            "max",
            "min",
            left = left_col,
            col = col_w
        )
        .ok();

        writeln!(out, "{}", "-".repeat(left_col + 3 + (col_w + 3) * 4)).ok();

        writeln!(
            out,
            "{:left$} | {:^col$} | {:^col$} | {:^col$} | {:^col$}",
            "scanned processes",
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
            "scan duration (s)",
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
            "cache_update_duration (s)",
            format!("{:.3}", cu_cur),
            format!("{:.3}", cu_avg),
            format!("{:.3}", cu_max),
            format!("{:.3}", cu_min),
            left = left_col,
            col = col_w
        )
        .ok();

        writeln!(out).ok();
        writeln!(out, "number of done scans: {}", total).ok();

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
    if args.io_buffer_kb != 256 {
        config.io_buffer_kb = Some(args.io_buffer_kb);
    }
    if args.smaps_buffer_kb != 512 {
        config.smaps_buffer_kb = Some(args.smaps_buffer_kb);
    }
    if args.smaps_rollup_buffer_kb != 256 {
        config.smaps_rollup_buffer_kb = Some(args.smaps_rollup_buffer_kb);
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

/// Classifies a process into group and subgroup based on process name (raw)
fn classify_process_raw(process_name: &str) -> (&'static str, &'static str) {
    SUBGROUPS
        .get(process_name)
        .copied()
        .unwrap_or(("other", "unknown"))
}

/// Classification inklusive Config-Regeln (include/exclude, disable_others)
fn classify_process_with_config(
    process_name: &str,
    cfg: &Config,
) -> Option<(&'static str, &'static str)> {
    let (group, subgroup) = classify_process_raw(process_name);

    // If user explicitly disabled "other" bucket, drop these processes
    let disable_others = cfg.disable_others.unwrap_or(false);
    if disable_others && group == "other" {
        return None;
    }

    // Apply include/exclude/search-mode logic
    let mode = cfg.search_mode.as_deref().unwrap_or("none");

    let group_match = cfg
        .search_groups
        .as_ref()
        .map_or(false, |v| v.iter().any(|g| g == group));
    let subgroup_match = cfg
        .search_subgroups
        .as_ref()
        .map_or(false, |v| v.iter().any(|sg| sg == subgroup));

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
    if group.eq_ignore_ascii_case("other") {
        Some(("other", "other"))
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

    // Most Linux systems use 100 jiffies per second
    let jiffies_per_second = 100.0;
    Ok((utime + stime) / jiffies_per_second)
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
    // Precedence: CLI (if explicitly different from its derive default) >
    //             config file > hard-coded default.
    let io_kb = if args.io_buffer_kb != 256 {
        args.io_buffer_kb
    } else {
        cfg.io_buffer_kb.unwrap_or(256)
    };
    let smaps_kb = if args.smaps_buffer_kb != 512 {
        args.smaps_buffer_kb
    } else {
        cfg.smaps_buffer_kb.unwrap_or(512)
    };
    let smaps_rollup_kb = if args.smaps_rollup_buffer_kb != 256 {
        args.smaps_rollup_buffer_kb
    } else {
        cfg.smaps_rollup_buffer_kb.unwrap_or(256)
    };

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
        // Validierung auch für Subcommands sinnvoll
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
            let mut groups: HashMap<(&'static str, &'static str), Vec<&ProcMem>> = HashMap::new();
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
                    if group.eq_ignore_ascii_case("other") {
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
                        group,
                        subgroup,
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

                // Set aggregation metrics (respect enable_* flags)
                if enable_rss {
                    state
                        .metrics
                        .agg_rss_sum
                        .with_label_values(&[group, subgroup])
                        .set(rss_sum as f64);
                }
                if enable_pss {
                    state
                        .metrics
                        .agg_pss_sum
                        .with_label_values(&[group, subgroup])
                        .set(pss_sum as f64);
                }
                if enable_uss {
                    state
                        .metrics
                        .agg_uss_sum
                        .with_label_values(&[group, subgroup])
                        .set(uss_sum as f64);
                }
                if enable_cpu {
                    state
                        .metrics
                        .agg_cpu_percent_sum
                        .with_label_values(&[group, subgroup])
                        .set(cpu_percent_sum);
                    state
                        .metrics
                        .agg_cpu_time_sum
                        .with_label_values(&[group, subgroup])
                        .set(cpu_time_sum);
                }

                // Sort by USS for Top-N selection
                list.sort_by_key(|p| std::cmp::Reverse(p.uss));

                // Treat both "other" and "others" (case-insensitive) as the special bucket.
                let is_other_group = group.eq_ignore_ascii_case("other")
                    || group.eq_ignore_ascii_case("others")
                    || subgroup.eq_ignore_ascii_case("other")
                    || subgroup.eq_ignore_ascii_case("others");

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
                            .with_label_values(&[group, subgroup, &rank_s, &pid_s, name_s])
                            .set(p.rss as f64);
                    }
                    if enable_pss {
                        state
                            .metrics
                            .top_pss
                            .with_label_values(&[group, subgroup, &rank_s, &pid_s, name_s])
                            .set(p.pss as f64);
                    }
                    if enable_uss {
                        state
                            .metrics
                            .top_uss
                            .with_label_values(&[group, subgroup, &rank_s, &pid_s, name_s])
                            .set(p.uss as f64);
                    }
                    if enable_cpu {
                        state
                            .metrics
                            .top_cpu_percent
                            .with_label_values(&[group, subgroup, &rank_s, &pid_s, name_s])
                            .set(p.cpu_percent as f64);
                        state
                            .metrics
                            .top_cpu_time
                            .with_label_values(&[group, subgroup, &rank_s, &pid_s, name_s])
                            .set(p.cpu_time_seconds as f64);
                    }

                    // Percentage-of-subgroup values
                    if enable_cpu && cpu_total > 0.0 {
                        let pct = (p.cpu_time_seconds as f64 / cpu_total) * 100.0;
                        state
                            .metrics
                            .top_cpu_percent_of_subgroup
                            .with_label_values(&[group, subgroup, &rank_s, &pid_s, name_s])
                            .set(pct);
                    }

                    if enable_rss && rss_total > 0.0 {
                        let pct = (p.rss as f64 / rss_total) * 100.0;
                        state
                            .metrics
                            .top_rss_percent_of_subgroup
                            .with_label_values(&[group, subgroup, &rank_s, &pid_s, name_s])
                            .set(pct);
                    }

                    if enable_pss && pss_total > 0.0 {
                        let pct = (p.pss as f64 / pss_total) * 100.0;
                        state
                            .metrics
                            .top_pss_percent_of_subgroup
                            .with_label_values(&[group, subgroup, &rank_s, &pid_s, name_s])
                            .set(pct);
                    }

                    if enable_uss && uss_total > 0.0 {
                        let pct = (p.uss as f64 / uss_total) * 100.0;
                        state
                            .metrics
                            .top_uss_percent_of_subgroup
                            .with_label_values(&[group, subgroup, &rank_s, &pid_s, name_s])
                            .set(pct);
                    }
                }
            }

            // Encode metrics in Prometheus text format
            let families = state.registry.gather();
            let mut buffer = Vec::with_capacity(BUFFER_CAP);
            let encoder = TextEncoder::new();

            if encoder.encode(&families, &mut buffer).is_err() {
                error!("Failed to encode Prometheus metrics");
                return Err(MetricsError::EncodingFailed);
            }

            debug!(
                "Metrics request completed: {} processes (exported {}), {} bytes, {:.3}ms",
                processes_vec.len(),
                exported_count,
                buffer.len(),
                start.elapsed().as_secs_f64() * 1000.0
            );

            return String::from_utf8(buffer).map_err(|_| MetricsError::EncodingFailed);
        }

        drop(cache_guard);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// -------------------------------------------------------------------
/// HEALTH CHECK ENDPOINT HANDLER
/// -------------------------------------------------------------------
#[instrument(skip(state))]
async fn health_handler(State(state): State<SharedState>) -> impl IntoResponse {
    debug!("Processing /health request");

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

    // Collect process entries from /proc filesystem
    let entries = collect_proc_entries("/proc", state.config.max_processes);
    debug!("Collected {} process entries from /proc", entries.len());

    // Apply configuration filters
    let min_uss_bytes = state.config.min_uss_kb.unwrap_or(0) * 1024;

    // Use atomic counters for thread-safe progress tracking
    use std::sync::atomic::{AtomicUsize, Ordering};
    let included_count = AtomicUsize::new(0);
    let skipped_count = AtomicUsize::new(0);

    // Process entries in parallel and collect metrics
    let results: Vec<ProcMem> = entries
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
        .collect();

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

    // Record completed scan metrics in HealthStats (call outside cache write-lock)
    let scanned = results.len() as u64;
    let scan_duration = start.elapsed().as_secs_f64();
    state
        .health_stats
        .record_scan(scanned, scan_duration, scan_duration);

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
