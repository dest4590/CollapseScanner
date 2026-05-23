use crate::types::DetectionMode;
use std::{io, path::Path};

pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_owned()
    } else {
        let mut truncated: String = s.chars().take(max_len.saturating_sub(3)).collect();
        truncated.push_str("...");
        truncated
    }
}

pub fn path_contains_scannable_files(path: &Path) -> bool {
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Some(ext) = entry.path().extension().and_then(|e| e.to_str()) {
                if matches!(ext.to_ascii_lowercase().as_str(), "jar" | "class") {
                    return true;
                }
            }
        }
    }
    false
}

pub fn extract_domain(url_str: &str) -> String {
    let mut working_str = url_str.trim();

    if let Some(proto_end) = working_str.find("://") {
        working_str = &working_str[proto_end + 3..];
    } else if working_str.starts_with("//") {
        working_str = &working_str[2..];
    }

    if let Some(path_start) = working_str.find('/') {
        working_str = &working_str[..path_start];
    }

    if let Some(port_start) = working_str.find(':') {
        working_str = &working_str[..port_start];
    }

    if let Some(at_pos) = working_str.find('@') {
        working_str = &working_str[at_pos + 1..];
    }

    let domain = working_str.trim_start_matches("www.");

    domain.to_lowercase()
}

pub fn get_simple_name(fqn: &str) -> &str {
    let name_part = fqn.strip_suffix('/').unwrap_or(fqn);
    name_part.rsplit(['/', '.']).next().unwrap_or(name_part)
}

pub fn merge_filter_lists(
    config_values: Option<Vec<String>>,
    cli_values: Vec<String>,
) -> Vec<String> {
    let mut merged = config_values.unwrap_or_default();
    for value in cli_values {
        if !merged.iter().any(|existing| existing == &value) {
            merged.push(value);
        }
    }
    merged
}

pub fn parse_detection_mode_from_string(
    raw_mode: &str,
) -> Result<DetectionMode, Box<dyn std::error::Error>> {
    match raw_mode.trim().to_ascii_lowercase().as_str() {
        "all" => Ok(DetectionMode::All),
        "network" => Ok(DetectionMode::Network),
        "malicious" => Ok(DetectionMode::Malicious),
        "obfuscation" => Ok(DetectionMode::Obfuscation),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Unsupported mode '{}'. Expected one of: all, network, malicious, obfuscation",
                other
            ),
        )
        .into()),
    }
}

pub fn is_progress_rendering_enabled(json_mode: bool, stderr_is_terminal: bool) -> bool {
    !json_mode && stderr_is_terminal
}
