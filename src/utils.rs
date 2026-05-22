pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_owned()
    } else {
        let mut truncated: String = s.chars().take(max_len.saturating_sub(3)).collect();
        truncated.push_str("...");
        truncated
    }
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
