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
    println!("{}", "─".repeat(70).bright_black());
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
            "|{:>28}CollapseScanner v{}{:>30}|",
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
    println!("\n{}", "Scan setup".bright_white().bold());
    println!("  Target : {}", path.display().to_string().bright_white());
    println!(
        "  Mode   : {} ({})",
        mode_label.bright_white(),
        mode_description.dimmed()
    );

    if let Some(config_path) = config_path {
        println!("  Config : {}", config_path.display().to_string().dimmed());
    }

    if !exclude_patterns.is_empty() {
        println!("  Exclude:");
        for pattern in exclude_patterns {
            println!("    - {}", pattern.dimmed());
        }
    }

    if !find_patterns.is_empty() {
        println!("  Match only:");
        for pattern in find_patterns {
            println!("    - {}", pattern.dimmed());
        }
    }

    if let Some(p) = ignore_keywords_file {
        println!("  Ignore : {}", p.display().to_string().dimmed());
    }

    if verbose {
        println!("  Verbose: {}", "enabled".bright_white());
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

    print_section_header("ALL FINDINGS");

    for result in sorted {
        let risk_label_str = match result.danger_score {
            s if s >= 8 => "CRITICAL",
            s if s >= 5 => "HIGH",
            s if s >= 3 => "MEDIUM",
            _ => "LOW",
        };

        let risk_color = match result.danger_score {
            s if s >= 8 => "red",
            s if s >= 5 => "bright_red",
            s if s >= 3 => "yellow",
            _ => "green",
        };

        let mut jar_summary = format!(
            "{} · CVSS {:.1} · {} finding{}",
            risk_label_str,
            result.danger_score as f64 / 10.0,
            result.matches.len(),
            if result.matches.len() == 1 { "" } else { "s" }
        );

        if let Some(ri) = &result.resource_info {
            if ri.is_dead_class_candidate {
                jar_summary.push_str(" · dead code");
            }
        }

        println!(
            "  {}  {}",
            result.file_path.bright_white().bold(),
            jar_summary.color(risk_color).bold()
        );

        let mut grouped: HashMap<FindingType, Vec<String>> = HashMap::new();
        for (ft, value) in result.matches.iter() {
            grouped.entry(*ft).or_default().push(value.clone());
        }

        for ft in &[
            FindingType::DiscordWebhook,
            FindingType::TamperedClass,
            FindingType::SuspiciousUrl,
            FindingType::SuspiciousApi,
            FindingType::CredentialSecret,
            FindingType::EncodedPayload,
            FindingType::IpAddress,
            FindingType::SuspiciousKeyword,
            FindingType::Url,
            FindingType::NativeLibrary,
            FindingType::SuspiciousArchiveEntry,
            FindingType::IpV6Address,
            FindingType::ObfuscationUnicode,
        ] {
            if let Some(values) = grouped.get(ft) {
                let (icon, color) = ft.with_symbol();
                if values.len() == 1 {
                    println!(
                        "    {} {}: {}",
                        icon.color(color).bold(),
                        ft.to_string().color(color).bold(),
                        values[0]
                    );
                } else {
                    println!(
                        "    {} {} ({})",
                        icon.color(color).bold(),
                        ft.to_string().color(color).bold(),
                        values.len()
                    );
                    for value in values {
                        println!("      - {}", value);
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

    println!(
        "  {} CRITICAL │ {} HIGH │ {} MEDIUM │ {} LOW",
        format!("{:>2}", critical).bright_red().bold(),
        format!("{:>2}", high).red().bold(),
        format!("{:>2}", medium).yellow().bold(),
        format!("{:>2}", low).green().bold()
    );

    let bar_width = 50;
    let crit_pct = (critical as f64 / total as f64 * bar_width as f64) as usize;
    let high_pct = (high as f64 / total as f64 * bar_width as f64) as usize;
    let med_pct = (medium as f64 / total as f64 * bar_width as f64) as usize;
    let low_pct = bar_width - crit_pct - high_pct - med_pct;

    print!("  ");
    print!("{}", "█".repeat(crit_pct).red());
    print!("{}", "█".repeat(high_pct).bright_red());
    print!("{}", "█".repeat(med_pct).yellow());
    print!("{}", "█".repeat(low_pct).green());
    println!();
}

pub fn print_finding_statistics(results: &[&ScanResult]) {
    println!("\n{}", "FINDING TYPES".bright_cyan().bold());
    println!("{}", "─".repeat(70).bright_black());

    let mut type_stats: HashMap<FindingType, usize> = HashMap::new();

    for result in results {
        for (ft, _) in result.matches.iter() {
            *type_stats.entry(*ft).or_insert(0) += 1;
        }
    }

    let mut sorted: Vec<_> = type_stats.iter().collect();
    sorted.sort_by_key(|(_ft, count)| std::cmp::Reverse(**count));

    for (ft, count) in sorted.iter() {
        let (icon, color) = ft.with_symbol();
        println!(
            "  {} {} {}",
            icon.color(color).bold(),
            ft.to_string().color(color),
            format!("x{}", count).bright_white()
        );
    }
}
