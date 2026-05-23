use crate::{
    calculate_scan_score, collect_finding_stats, format_scan_stats,
    types::{FindingType, ScanResult},
};
use colored::Colorize;
use std::collections::HashMap;

pub fn print_section_header(title: &str) {
    println!("\n{}", title.bright_cyan().bold());
    println!("{}", "─".repeat(70).bright_black());
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
