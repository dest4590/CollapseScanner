//! Output formatting and reporting module
//!
//! Provides functions for formatting and displaying scan results in text and JSON formats.

use crate::{
    calculate_scan_score,
    types::{FindingType, ScanResult},
};
use colored::Colorize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::time::Duration;

pub fn collect_finding_stats(
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

pub fn format_scan_stats(duration: Duration, total_files: usize) -> (f64, f64) {
    let scan_time = duration.as_secs_f64();
    let scan_rate = if scan_time > 0.0 {
        total_files as f64 / scan_time
    } else {
        0.0
    };
    (scan_time, scan_rate)
}

pub fn print_section_header(title: &str) {
    println!("\n{}", title.bright_cyan().bold());
    println!("{}", "─".repeat(70).bright_white());
}

pub fn print_banner() {
    const BANNER_BOX: &str =
        "+------------------------------------------------------------------------------+";
    const BANNER_BOTTOM: &str =
        "+------------------------------------------------------------------------------+";

    println!("\n{}", BANNER_BOX.bright_blue().bold());
    println!(
        "{}",
        format!(
            "|{:>28}CollapseScanner v{}{:>28}|",
            "",
            env!("CARGO_PKG_VERSION"),
            ""
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

pub fn print_scan_config(
    path: &Path,
    mode_label: String,
    mode_description: &str,
    config_path: &Option<std::path::PathBuf>,
    exclude_patterns: &[String],
    find_patterns: &[String],
    ignore_keywords_file: &Option<std::path::PathBuf>,
    verbose: bool,
) {
    println!("\n  {}", "SCAN SETUP".bright_white().bold());
    println!(
        "  {} {}",
        "Target:".bright_white(),
        path.display().to_string().bright_white()
    );
    println!(
        "  {} {} {}",
        "Mode:  ".bright_white(),
        mode_label.bright_cyan(),
        format!("({})", mode_description).bright_white()
    );

    if let Some(config_path) = config_path {
        println!(
            "  {} {}",
            "Config:".bright_white(),
            config_path.display().to_string().bright_white()
        );
    }

    if !exclude_patterns.is_empty() {
        println!(
            "  {} {}",
            "Exclude:".bright_white(),
            exclude_patterns.join(", ").bright_white()
        );
    }

    if !find_patterns.is_empty() {
        println!(
            "  {} {}",
            "Match:  ".bright_white(),
            find_patterns.join(", ").bright_white()
        );
    }

    if let Some(p) = ignore_keywords_file {
        println!(
            "  {} {}",
            "Ignore: ".bright_white(),
            p.display().to_string().bright_white()
        );
    }

    if verbose {
        println!(
            "  {} {}",
            "Level: ".bright_white(),
            "Verbose".bright_yellow()
        );
    }
}

pub fn print_empty_scan_result(path: &Path, exclude_patterns: &[String], find_patterns: &[String]) {
    const BANNER_BOX: &str =
        "+------------------------------------------------------------------------------+";
    const BANNER_BOTTOM: &str =
        "+------------------------------------------------------------------------------+";

    println!("\n{}", BANNER_BOX.bright_blue().bold());
    println!(
        "{}",
        format!("| {:<76} |", "SCAN RESULTS").bright_blue().bold()
    );
    println!("{}", BANNER_BOTTOM.bright_blue().bold());

    if !crate::utils::path_contains_scannable_files(path) {
        println!(
            "\n[-] {}",
            "No .jar or .class files were found in the target path.".yellow()
        );
    } else if !exclude_patterns.is_empty() || !find_patterns.is_empty() {
        println!(
            "\n[+] {}",
            "No findings in files that matched your filters.".green()
        );
    } else {
        println!("\n[+] {}", "No findings for the selected mode.".green());
    }
}

pub fn write_json_report(
    output_path: &str,
    report: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(output_path, serde_json::to_string_pretty(report)?)?;
    Ok(())
}

pub fn print_general_info(sorted_results: &[&ScanResult], elapsed: std::time::Duration) {
    print_section_header("SCAN REPORT");

    let (total_findings, _all_findings) = collect_finding_stats(sorted_results);

    if total_findings == 0 {
        let (scan_time, scan_rate) = format_scan_stats(elapsed, sorted_results.len());
        println!(
            "\n[+] {}",
            "No specific findings in the selected mode.".green()
        );
        println!(
            "[*] Scan time: {:.2}s | Processing rate: {:.1} files/sec",
            scan_time, scan_rate
        );
        return;
    }

    let (score, score_color, risk_level) = calculate_scan_score(sorted_results);
    let (scan_time, scan_rate) = format_scan_stats(elapsed, sorted_results.len());

    println!(
        "\nRisk: {} ({}/10)",
        risk_level.color(score_color).bold(),
        score
    );
    println!(
        "Findings: {} across {} file(s)",
        total_findings.to_string().bright_white().bold(),
        sorted_results.len().to_string().bright_white().bold()
    );
    println!(
        "Scanned: {} file(s) in {:.2}s ({:.1} files/sec)",
        sorted_results.len().to_string().bright_white(),
        scan_time,
        scan_rate
    );

    println!()
}

pub fn print_detailed_file_report(results: &[&ScanResult]) {
    let mut sorted = results
        .iter()
        .filter(|r| !r.matches.is_empty())
        .copied()
        .collect::<Vec<_>>();

    sorted.sort_by(|a, b| b.danger_score.cmp(&a.danger_score));

    print_section_header("FINDINGS BY FILE");

    for result in sorted {
        let risk_label = match result.danger_score {
            8..=10 => "SEVERE".on_red().white().bold(),
            5..=7 => "DANGER".red().bold(),
            3..=4 => "SUSPICIOUS".yellow().bold(),
            _ => "LOW".green().bold(),
        };

        let cvss_score = format!("({:.1})", result.danger_score as f64 / 10.0).bright_white();

        println!(
            "  {} {} {}",
            "◆".bright_cyan(),
            result.file_path.bright_white().bold(),
            cvss_score
        );
        println!(
            "    {} · {} findings",
            risk_label,
            result.matches.len().to_string().bright_white()
        );

        let mut grouped: HashMap<FindingType, Vec<String>> = HashMap::new();
        for (ft, value) in result.matches.iter() {
            grouped.entry(*ft).or_default().push(value.clone());
        }

        let order = [
            FindingType::DiscordWebhook,
            FindingType::TamperedClass,
            FindingType::SuspiciousUrl,
            FindingType::JavaAPI,
            FindingType::CredentialSecret,
            FindingType::EncodedPayload,
            FindingType::IpAddress,
            FindingType::SuspiciousKeyword,
            FindingType::Url,
            FindingType::NativeLibrary,
            FindingType::ArchiveEntry,
            FindingType::IpV6Address,
            FindingType::ObfuscationUnicode,
        ];

        for ft in &order {
            if let Some(values) = grouped.get(ft) {
                let (_icon, color) = ft.with_symbol();

                if values.len() == 1 {
                    println!(
                        "    {:>12} {} {}",
                        ft.to_string().color(color).bold(),
                        "→".bright_white(),
                        values[0].bright_white()
                    );
                } else {
                    println!(
                        "    {:>12} {} {} items",
                        ft.to_string().color(color).bold(),
                        "↴".bright_white(),
                        values.len().to_string().bright_white()
                    );
                    for value in values {
                        println!("                 {} {}", "•".bright_white(), value);
                    }
                }
            }
        }

        println!();
    }
}

pub fn print_severity_matrix(results: &[&ScanResult]) {
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;

    for result in results {
        match result.danger_score {
            s if s >= 8 => critical += 1,
            s if s >= 5 => high += 1,
            s if s >= 3 => medium += 1,
            _ => low += 1,
        }
    }

    let total = critical + high + medium + low;
    if total == 0 {
        return;
    }

    print_section_header("SEVERITY DISTRIBUTION");

    let bar_width = 50;
    let crit_pct = (critical as f64 / total as f64 * bar_width as f64) as usize;
    let high_pct = (high as f64 / total as f64 * bar_width as f64) as usize;
    let med_pct = (medium as f64 / total as f64 * bar_width as f64) as usize;
    let low_pct = bar_width - crit_pct - high_pct - med_pct;

    print!("  ");
    print!("{}", "■".repeat(crit_pct).red());
    print!("{}", "■".repeat(high_pct).bright_red());
    print!("{}", "■".repeat(med_pct).yellow());
    print!("{}", "■".repeat(low_pct).green());
    println!("  {}", total.to_string().bright_white());

    println!(
        "  {} {}     {} {}     {} {}     {} {}",
        "●".red(),
        "Critical".bright_white(),
        "●".bright_red(),
        "High".bright_white(),
        "●".yellow(),
        "Medium".bright_white(),
        "●".green(),
        "Low".bright_white()
    );
}

pub fn print_finding_statistics(results: &[&ScanResult]) {
    print_section_header("FINDING TYPES SUMMARY");

    let mut type_stats: HashMap<FindingType, usize> = HashMap::new();

    for result in results {
        for (ft, _) in result.matches.iter() {
            *type_stats.entry(*ft).or_insert(0) += 1;
        }
    }

    let mut sorted: Vec<_> = type_stats.iter().collect();
    sorted.sort_by_key(|(_ft, count)| std::cmp::Reverse(**count));

    for (ft, count) in sorted.iter() {
        let (_icon, color) = ft.with_symbol();
        println!(
            "  {}: {}",
            ft.to_string().color(color).bold(),
            count.to_string().bright_white().bold()
        );
    }
}
