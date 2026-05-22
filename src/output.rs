use crate::types::{FindingType, ScanResult};
use colored::Colorize;
use std::collections::HashMap;

pub fn print_scan_report_structured(results: &[&ScanResult]) {
    if results.is_empty() {
        return;
    }

    print_critical_findings(results);

    print_detailed_file_report(results);

    print_severity_matrix(results);
    print_finding_statistics(results);
}

pub fn print_critical_findings(results: &[&ScanResult]) {
    let mut sorted = results
        .iter()
        .filter(|r| !r.matches.is_empty())
        .copied()
        .collect::<Vec<_>>();

    sorted.sort_by(|a, b| {
        b.danger_score
            .cmp(&a.danger_score)
            .then_with(|| b.matches.len().cmp(&a.matches.len()))
    });

    if sorted.is_empty() {
        return;
    }

    println!("\n{}", "CRITICAL ISSUES".bright_red().bold());
    println!("{}", "─".repeat(70).bright_black());

    for (idx, result) in sorted.into_iter().take(10).enumerate() {
        let risk_color = if result.danger_score >= 8 {
            "red"
        } else if result.danger_score >= 5 {
            "bright_red"
        } else if result.danger_score >= 3 {
            "yellow"
        } else {
            "green"
        };

        println!(
            "\n  {}. {} — {} {}",
            idx + 1,
            result.file_path.bright_white().bold(),
            format!("CVSS {:.1}", result.danger_score as f64 / 10.0)
                .color(risk_color)
                .bold(),
            format!(
                "[{} finding{}]",
                result.matches.len(),
                if result.matches.len() == 1 { "" } else { "s" }
            )
            .bright_black()
        );
    }
}

pub fn print_detailed_file_report(results: &[&ScanResult]) {
    let mut sorted = results
        .iter()
        .filter(|r| !r.matches.is_empty())
        .copied()
        .collect::<Vec<_>>();

    sorted.sort_by(|a, b| b.danger_score.cmp(&a.danger_score));

    println!("\n{}", "FINDINGS BY ARTIFACT".bright_cyan().bold());
    println!("{}", "─".repeat(70).bright_black());

    for result in sorted {
        println!("\n  {}", result.file_path.bright_white().bold());

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

        println!(
            "      Risk: {} · CVSS {:.1} · {} finding{}",
            risk_label_str.color(risk_color).bold(),
            result.danger_score as f64 / 10.0,
            result.matches.len(),
            if result.matches.len() == 1 { "" } else { "s" }
        );

        if let Some(ri) = &result.resource_info {
            if ri.is_dead_class_candidate {
                println!("      ⚠ Dead code marker detected");
            }
        }

        let mut grouped: HashMap<FindingType, Vec<String>> = HashMap::new();
        for (ft, value) in result.matches.iter() {
            grouped.entry(*ft).or_default().push(value.clone());
        }

        let mut first = true;
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
                if !first {
                    println!();
                }
                first = false;

                let (icon, color) = ft.with_symbol();
                println!(
                    "      {} {}",
                    icon.color(color).bold(),
                    ft.to_string().color(color).bold()
                );
                for value in values.iter().take(2) {
                    println!("        • {}", value);
                }
                if values.len() > 2 {
                    println!("        • +{} more", values.len() - 2);
                }
            }
        }
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

    println!("\n{}", "SEVERITY DISTRIBUTION".bright_cyan().bold());
    println!("{}", "─".repeat(70).bright_black());

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

    for (ft, count) in sorted.iter().take(12) {
        let (icon, color) = ft.with_symbol();
        println!(
            "  {} {} {}",
            icon.color(color).bold(),
            ft.to_string().color(color),
            format!("x{}", count).bright_white()
        );
    }

    if sorted.len() > 12 {
        println!("  +{} more", sorted.len() - 12);
    }
}
