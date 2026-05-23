mod config;
mod constants;
mod detection;
mod errors;
mod filters;
mod output;
mod parser;
mod scanner;
mod types;
mod utils;

use {
    crate::{
        output::{
            print_detailed_file_report, print_finding_statistics, print_general_info,
            print_severity_matrix,
        },
        scanner::scan::CollapseScanner,
        types::{DetectionMode, FindingType, Progress, ProgressScope, ScanResult, ScannerOptions},
    },
    clap::Parser,
    colored::Colorize,
    indicatif::{ProgressBar, ProgressStyle},
    serde::Deserialize,
    serde_json::json,
    std::{
        collections::{HashMap, HashSet},
        fs,
        io::{self, IsTerminal},
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
        thread,
        time::Duration,
    },
    walkdir::WalkDir,
};

#[derive(Debug, Deserialize, Default)]
struct FileConfig {
    path: Option<String>,
    verbose: Option<bool>,
    output: Option<String>,
    json: Option<bool>,
    mode: Option<String>,
    ignore_keywords: Option<PathBuf>,
    exclude: Option<Vec<String>>,
    find: Option<Vec<String>>,
    threads: Option<usize>,
}

#[derive(Clone)]
struct ResolvedArgs {
    path: Option<String>,
    verbose: bool,
    output: Option<String>,
    json: bool,
    mode: DetectionMode,
    ignore_keywords: Option<PathBuf>,
    exclude: Vec<String>,
    find: Vec<String>,
    threads: usize,
    config: Option<PathBuf>,
}

#[derive(Parser, Clone)]
#[clap(
    name = "CollapseScanner",
    author,
    version,
    about = "Static triage for Java JARs, class files, and nested archive contents",
    long_about = "CollapseScanner inspects Java jars without running them. It looks for risky APIs, hardcoded infrastructure, token-like secrets, obfuscation, native payloads, and archive anomalies.\n\nExamples:\n  collapsescanner sample.jar\n  collapsescanner mods/ --mode network\n  collapsescanner sample.jar --config scanner.toml\n  collapsescanner mods/ --json --output report.json"
)]
struct Args {
    #[clap(value_parser, help = "JAR, class file, or directory to scan")]
    path: Option<String>,

    #[clap(
        long,
        value_parser,
        help = "Load default scan settings from this TOML file"
    )]
    config: Option<PathBuf>,

    #[clap(short, long, action = clap::ArgAction::SetTrue, help = "Print parser and scanning details")]
    verbose: bool,

    #[clap(long, hide = true)]
    strings: bool,

    #[clap(long, hide = true)]
    extract: bool,

    #[clap(long, value_parser, help = "Write a JSON report to this path")]
    output: Option<String>,

    #[clap(
        long,
        help = "Print machine-readable JSON instead of the terminal report"
    )]
    json: bool,

    #[clap(value_enum, long, help = "Detection group to run (default: all)")]
    mode: Option<DetectionMode>,

    #[clap(long, value_parser, help = "File with suspicious keywords to suppress")]
    ignore_keywords: Option<PathBuf>,

    #[clap(long, action = clap::ArgAction::Append, value_parser, help = "Skip paths matching this wildcard pattern")]
    exclude: Vec<String>,

    #[clap(long, action = clap::ArgAction::Append, value_parser, help = "Only scan paths matching this wildcard pattern")]
    find: Vec<String>,

    #[clap(
        long,
        value_parser,
        help = "Worker threads to use; 0 lets Rayon decide"
    )]
    threads: Option<usize>,
}

struct ProgressReporter {
    shared: Option<Arc<Mutex<Progress>>>,
    render_handle: Option<thread::JoinHandle<()>>,
}

impl ProgressReporter {
    fn start(enabled: bool) -> Self {
        if !enabled {
            return Self {
                shared: None,
                render_handle: None,
            };
        }

        let shared = Arc::new(Mutex::new(Progress {
            current: 0,
            total: 0,
            message: "Preparing scan".to_string(),
            cancelled: false,
            finished: false,
            scope: ProgressScope::Preparing,
        }));

        let render_state = Arc::clone(&shared);
        let render_handle = thread::spawn(move || {
            let progress_bar = ProgressBar::new_spinner();
            let spinner_style = ProgressStyle::with_template("{spinner:.cyan} {msg}")
                .expect("valid spinner template");
            let bar_style = ProgressStyle::with_template(
                "{spinner:.cyan} {prefix:<8} [{wide_bar:.cyan/blue}] {pos:>4}/{len:<4} {msg}",
            )
            .expect("valid progress template");

            progress_bar.enable_steady_tick(Duration::from_millis(120));

            loop {
                let snapshot = match render_state.lock() {
                    Ok(state) => state.clone(),
                    Err(_) => break,
                };

                if snapshot.total > 0 {
                    progress_bar.set_style(bar_style.clone());
                    progress_bar.set_prefix(snapshot.scope.label().to_string());
                    progress_bar.set_length(snapshot.total as u64);
                    progress_bar.set_position(snapshot.current.min(snapshot.total) as u64);
                } else {
                    progress_bar.set_style(spinner_style.clone());
                    progress_bar.set_prefix("");
                }

                progress_bar.set_message(snapshot.message.clone());

                if snapshot.finished {
                    progress_bar.finish_and_clear();
                    break;
                }

                thread::sleep(Duration::from_millis(80));
            }
        });

        Self {
            shared: Some(shared),
            render_handle: Some(render_handle),
        }
    }

    fn shared_state(&self) -> Option<Arc<Mutex<Progress>>> {
        self.shared.clone()
    }

    fn finish(mut self, message: impl Into<String>) {
        if let Some(state) = &self.shared {
            if let Ok(mut progress) = state.lock() {
                progress.message = message.into();
                progress.finished = true;
                if progress.total > 0 {
                    progress.current = progress.current.min(progress.total);
                }
            }
        }

        if let Some(handle) = self.render_handle.take() {
            let _ = handle.join();
        }
    }
}

const BANNER_BOX: &str =
    "+------------------------------------------------------------------------------+";
const BANNER_BOTTOM: &str =
    "+------------------------------------------------------------------------------+";

fn print_banner() {
    println!("\n{}", BANNER_BOX.bright_blue().bold());
    println!(
        "{}",
        concat!(
            "|                           CollapseScanner v",
            env!("CARGO_PKG_VERSION"),
            "                             |"
        )
        .bright_blue()
        .bold()
    );
    println!(
        "{}",
        "|                     Java scanner, without exceptions                         |"
            .bright_blue()
            .bold()
    );
    println!("{}", BANNER_BOTTOM.bright_blue().bold());
}

fn load_file_config(path: &Path) -> Result<FileConfig, Box<dyn std::error::Error>> {
    let file_contents = fs::read_to_string(path)?;
    Ok(toml::from_str(&file_contents)?)
}

fn merge_string_lists(config_values: Option<Vec<String>>, cli_values: Vec<String>) -> Vec<String> {
    let mut merged = config_values.unwrap_or_default();

    for value in cli_values {
        if !merged.iter().any(|existing| existing == &value) {
            merged.push(value);
        }
    }

    merged
}

fn parse_detection_mode(raw_mode: &str) -> Result<DetectionMode, Box<dyn std::error::Error>> {
    match raw_mode.trim().to_ascii_lowercase().as_str() {
        "all" => Ok(DetectionMode::All),
        "network" => Ok(DetectionMode::Network),
        "malicious" => Ok(DetectionMode::Malicious),
        "obfuscation" => Ok(DetectionMode::Obfuscation),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Unsupported config mode '{other}'. Expected one of: all, network, malicious, obfuscation"
            ),
        )
        .into()),
    }
}

fn resolve_args(args: Args) -> Result<ResolvedArgs, Box<dyn std::error::Error>> {
    let config = if let Some(config_path) = &args.config {
        Some(load_file_config(config_path)?)
    } else {
        None
    };

    let config_mode = match config.as_ref().and_then(|cfg| cfg.mode.as_deref()) {
        Some(raw_mode) => Some(parse_detection_mode(raw_mode)?),
        None => None,
    };

    Ok(ResolvedArgs {
        path: args
            .path
            .or_else(|| config.as_ref().and_then(|cfg| cfg.path.clone())),
        verbose: if args.verbose {
            true
        } else {
            config.as_ref().and_then(|cfg| cfg.verbose).unwrap_or(false)
        },
        output: args
            .output
            .or_else(|| config.as_ref().and_then(|cfg| cfg.output.clone())),
        json: if args.json {
            true
        } else {
            config.as_ref().and_then(|cfg| cfg.json).unwrap_or(false)
        },
        mode: args.mode.or(config_mode).unwrap_or(DetectionMode::All),
        ignore_keywords: args
            .ignore_keywords
            .or_else(|| config.as_ref().and_then(|cfg| cfg.ignore_keywords.clone())),
        exclude: merge_string_lists(
            config.as_ref().and_then(|cfg| cfg.exclude.clone()),
            args.exclude,
        ),
        find: merge_string_lists(config.as_ref().and_then(|cfg| cfg.find.clone()), args.find),
        threads: args
            .threads
            .or_else(|| config.as_ref().and_then(|cfg| cfg.threads))
            .unwrap_or(0),
        config: args.config,
    })
}

fn create_scanner_options(
    args: &ResolvedArgs,
    progress: Option<Arc<Mutex<Progress>>>,
) -> ScannerOptions {
    ScannerOptions {
        mode: args.mode,
        verbose: args.verbose,
        ignore_keywords_file: args.ignore_keywords.clone(),
        exclude_patterns: args.exclude.clone(),
        find_patterns: args.find.clone(),
        progress,
    }
}

fn configure_threading(args: &ResolvedArgs) -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = rayon::ThreadPoolBuilder::new().stack_size(64 * 1024 * 1024);

    if args.threads > 0 {
        if args.threads > 1024 {
            eprintln!(
                "(!) Thread count {} is very high. A range around 1-64 is usually enough.",
                args.threads
            );
        }
        builder = builder.num_threads(args.threads);
        if args.verbose {
            println!("[*] Using {} worker thread(s).", args.threads);
        }
    } else if args.verbose {
        println!("[*] Using Rayon default worker count.");
    }

    builder.build_global().map_err(io::Error::other)?;
    Ok(())
}

fn validate_and_prepare_path(args: &ResolvedArgs) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path_arg = args.path.clone().unwrap_or_else(|| ".".to_string());
    let path = PathBuf::from(&path_arg);
    if !path.exists() {
        eprintln!("[X] Target path does not exist: {}", path.display());
        eprintln!("[i] Check the path spelling and try again.");
        std::process::exit(1);
    }
    Ok(path)
}

fn mode_description(mode: DetectionMode) -> &'static str {
    match mode {
        DetectionMode::All => "all checks",
        DetectionMode::Network => "network indicators",
        DetectionMode::Malicious => "malicious APIs, keywords, and secrets",
        DetectionMode::Obfuscation => "obfuscation indicators",
    }
}

fn print_scan_configuration(path: &Path, args: &ResolvedArgs, scanner: &CollapseScanner) {
    println!("\n{}", "Scan setup".bright_white().bold());
    println!("  Target : {}", path.display().to_string().bright_white());
    println!(
        "  Mode   : {} ({})",
        args.mode.to_string().bright_white(),
        mode_description(args.mode).dimmed()
    );

    print_optional_configurations(scanner, args);
}

fn print_optional_configurations(scanner: &CollapseScanner, args: &ResolvedArgs) {
    if let Some(config_path) = &args.config {
        println!("  Config : {}", config_path.display().to_string().dimmed());
    }

    if !scanner.options.exclude_patterns.is_empty() {
        println!("  Exclude:");
        for pattern in &scanner.options.exclude_patterns {
            println!("    - {}", pattern.dimmed());
        }
    }

    if !scanner.options.find_patterns.is_empty() {
        println!("  Match only:");
        for pattern in &scanner.options.find_patterns {
            println!("    - {}", pattern.dimmed());
        }
    }

    if let Some(p) = &scanner.options.ignore_keywords_file {
        println!("  Ignore : {}", p.display().to_string().dimmed());
    }

    if args.verbose {
        println!("  Verbose: {}", "enabled".bright_white());
    }
}

fn calculate_scan_score(results: &[&ScanResult]) -> (u8, &'static str, &'static str) {
    if results.is_empty() {
        return (1, "green", "MINIMAL RISK");
    }

    let mut weighted_sum: u32 = 0;
    let mut weight_total: u32 = 0;
    let mut max_danger_score: u8 = 0;

    for result in results {
        let weight = if result.danger_score >= 8 { 5 } else { 1 };
        weighted_sum += (result.danger_score as u32) * weight;
        weight_total += weight;
        max_danger_score = max_danger_score.max(result.danger_score);
    }

    let weighted_avg = (weighted_sum as f32 / weight_total as f32).round() as u8;
    let score = if max_danger_score == 10 {
        10
    } else {
        weighted_avg.max(max_danger_score).clamp(1, 10)
    };

    let score_color = match score {
        1 => "green",
        2 => "bright_green",
        3 => "cyan",
        4 => "bright_cyan",
        5 => "yellow",
        6 => "bright_yellow",
        7 => "magenta",
        8..=10 => "red",
        _ => "green",
    };

    let risk_level = match score {
        8..=10 => "HIGH RISK",
        5..=7 => "MODERATE RISK",
        3..=4 => "LOW RISK",
        _ => "MINIMAL RISK",
    };

    (score, score_color, risk_level)
}

fn print_section_header(title: &str) {
    println!("\n{}", BANNER_BOX.bright_blue().bold());
    println!("{}", format!("| {:<76} |", title).bright_blue().bold());
    println!("{}", BANNER_BOTTOM.bright_blue().bold());
}

fn format_scan_stats(duration: Duration, total_files: usize) -> (f64, f64) {
    let scan_time = duration.as_secs_f64();
    let scan_rate = if scan_time > 0.0 {
        total_files as f64 / scan_time
    } else {
        0.0
    };
    (scan_time, scan_rate)
}

fn build_json_report(
    results: &[ScanResult],
    significant_results: &[&ScanResult],
    elapsed: Duration,
) -> serde_json::Value {
    let (score, _, risk_level) = calculate_scan_score(significant_results);
    let total_findings: usize = significant_results.iter().map(|r| r.matches.len()).sum();

    let compact_results: Vec<serde_json::Value> = significant_results
        .iter()
        .map(|r| {
            let findings: Vec<serde_json::Value> = r
                .matches
                .iter()
                .map(|(ft, val)| json!({"type": format!("{:?}", ft), "value": val}))
                .collect();

            json!({
                "file_path": r.file_path,
                "danger_score": r.danger_score,
                "danger_explanation": r.danger_explanation,
                "findings": findings
            })
        })
        .collect();

    json!({
        "scan_time_seconds": elapsed.as_secs_f64(),
        "total_files_scanned": results.len(),
        "files_with_findings": significant_results.len(),
        "total_findings": total_findings,
        "risk_level": risk_level,
        "score": score,
        "results": compact_results
    })
}

fn write_json_report(
    output_path: &str,
    report: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(output_path, serde_json::to_string_pretty(report)?)?;
    Ok(())
}

fn has_scannable_files(path: &Path) -> bool {
    if path.is_file() {
        return path
            .extension()
            .is_some_and(|ext| ext == "jar" || ext == "class");
    }

    if path.is_dir() {
        return WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .any(|e| {
                e.file_type().is_file()
                    && e.path()
                        .extension()
                        .is_some_and(|ext| ext == "jar" || ext == "class")
            });
    }

    false
}

fn collect_finding_stats(
    results: &[&ScanResult],
) -> (usize, HashMap<FindingType, HashSet<String>>) {
    let mut total_findings = 0;
    let mut all_findings: HashMap<FindingType, HashSet<String>> = HashMap::new();

    for result in results {
        for (finding_type, value) in result.matches.iter() {
            total_findings += 1;
            all_findings
                .entry(*finding_type)
                .or_default()
                .insert(value.clone());
        }
    }

    (total_findings, all_findings)
}

fn print_empty_scan_result(path: &Path, scanner: &CollapseScanner) {
    print_section_header("SCAN RESULTS");

    if !has_scannable_files(path) {
        println!(
            "\n[-] {}",
            "No .jar or .class files were found in the target path.".yellow()
        );
    } else if !scanner.options.exclude_patterns.is_empty()
        || !scanner.options.find_patterns.is_empty()
    {
        println!(
            "\n[+] {}",
            "No findings in files that matched your filters.".green()
        );
    } else {
        println!("\n[+] {}", "No findings for the selected mode.".green());
    }
}

fn print_text_report(
    significant_results: Vec<&ScanResult>,
    path: &Path,
    scanner: &CollapseScanner,
    elapsed: Duration,
) {
    if significant_results.is_empty() {
        print_empty_scan_result(path, scanner);
        return;
    }

    let mut sorted_results = significant_results;
    sorted_results.sort_by_key(|r| &r.file_path);

    print_section_header("SCAN SUMMARY");

    if sorted_results.is_empty() {
        return;
    }

    print_detailed_file_report(&sorted_results);

    print_severity_matrix(&sorted_results);
    print_finding_statistics(&sorted_results);

    print_general_info(&sorted_results, elapsed);

    println!("Scan complete. Review the findings above");
}

fn handle_json_output(
    args: &ResolvedArgs,
    results: &[ScanResult],
    significant_results: &[&ScanResult],
    elapsed: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut sorted_results = significant_results.to_vec();
    sorted_results.sort_by_key(|r| &r.file_path);

    let json_output = build_json_report(results, &sorted_results, elapsed);
    if let Some(output_path) = &args.output {
        write_json_report(output_path, &json_output)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&json_output)?);
    }

    Ok(())
}

fn maybe_write_text_mode_json_report(
    args: &ResolvedArgs,
    results: &[ScanResult],
    scanner: &CollapseScanner,
    elapsed: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(output_path) = &args.output {
        let mut output_results: Vec<&ScanResult> = results
            .iter()
            .filter(|r| !r.matches.is_empty() || scanner.options.verbose)
            .collect();
        output_results.sort_by_key(|r| &r.file_path);

        let report = build_json_report(results, &output_results, elapsed);
        write_json_report(output_path, &report)?;
        println!(
            "\n[+] JSON report written to {}",
            output_path.bright_white()
        );
    }

    Ok(())
}

fn should_render_progress(args: &ResolvedArgs) -> bool {
    !args.json && io::stderr().is_terminal()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = resolve_args(Args::parse())?;
    let progress_reporter = ProgressReporter::start(should_render_progress(&args));
    let options = create_scanner_options(&args, progress_reporter.shared_state());

    if !args.json {
        print_banner();
    }

    configure_threading(&args)?;

    let scanner = CollapseScanner::new(options.clone())?;
    let path = validate_and_prepare_path(&args)?;

    if !args.json {
        print_scan_configuration(&path, &args, &scanner);
        if !should_render_progress(&args) {
            println!("\n>>> {}", "Scanning...".bright_green());
        }
    }

    let scan_start_time = std::time::Instant::now();

    match scanner.scan_path(&path) {
        Ok(results) => {
            let elapsed = scan_start_time.elapsed();
            let significant_results: Vec<&ScanResult> = results
                .iter()
                .filter(|r| !r.matches.is_empty() || scanner.options.verbose)
                .collect();

            progress_reporter.finish(format!(
                "Scanned {} file(s) in {:.2}s",
                results.len(),
                elapsed.as_secs_f64()
            ));

            if args.json {
                handle_json_output(&args, &results, &significant_results, elapsed)?;
                return Ok(());
            }

            print_text_report(significant_results, &path, &scanner, elapsed);

            let found_custom_jvm = *scanner.found_custom_jvm_indicator.lock().unwrap();
            if found_custom_jvm {
                println!("\n(!) {}", "Custom JVM warning".yellow().bold());
                println!(
                    "   {}",
                    "Some class files use unusual magic bytes. Review them with custom ClassLoader behavior in mind.".yellow()
                );
            }

            maybe_write_text_mode_json_report(&args, &results, &scanner, elapsed)?;
        }
        Err(error) => {
            progress_reporter.finish("Scan failed".to_string());

            if args.json {
                let error_json = json!({
                    "error": error.to_string()
                });
                println!("{}", serde_json::to_string_pretty(&error_json)?);
                std::process::exit(1);
            }

            eprintln!("\n[X] {}", "Scan failed".red().bold());
            eprintln!("   {}", error);
            if options.verbose {
                eprintln!("   [i] Check file permissions, disk space, and archive integrity.");
            }
            std::process::exit(1);
        }
    }

    Ok(())
}
