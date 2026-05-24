use crate::rules::{
    ATTACH_API_MARKERS, DYNAMIC_LOADING_MARKERS, JAVA_AGENT_MARKERS, NATIVE_BRIDGE_MARKERS,
    SAFE_NATIVE_CALLS, SCRIPT_ENGINE_MARKERS,
};
use crate::types::{ClassDetails, FindingType, MethodCallInfo};
use crate::utils::truncate_string;
use std::collections::HashSet;

pub struct ApiAnalyzer;

impl ApiAnalyzer {
    pub fn analyze(details: &ClassDetails, findings: &mut Vec<(FindingType, String)>) {
        let string_set: HashSet<&str> = details.strings.iter().map(String::as_str).collect();

        let process_calls: Vec<String> = details
            .method_calls
            .iter()
            .filter(|call| Self::is_process_api_call(call))
            .map(Self::format_process_call)
            .collect();

        if !process_calls.is_empty() {
            let call_summary = if process_calls.len() == 1 {
                process_calls[0].clone()
            } else {
                format!(
                    "{} (and {} more)",
                    process_calls[0],
                    process_calls.len() - 1
                )
            };
            findings.push((
                FindingType::SuspiciousApi,
                format!("Process execution API usage: {}", call_summary),
            ));
        }

        let native_calls: Vec<String> = details
            .method_calls
            .iter()
            .filter(|call| {
                NATIVE_BRIDGE_MARKERS.iter().any(|marker| {
                    if marker.ends_with('/') {
                        call.owner.starts_with(marker)
                    } else {
                        call.owner == *marker
                    }
                })
            })
            .filter(|call| {
                if call.owner.starts_with("com/sun/jna") {
                    return false;
                }
                true
            })
            .map(Self::format_native_call)
            .filter(|sig| !SAFE_NATIVE_CALLS.iter().any(|&s| sig.starts_with(s)))
            .collect();

        let mut matched_markers: Vec<&str> = details
            .strings
            .iter()
            .filter(|s| !s.starts_with('('))
            .filter_map(|s| {
                for marker in NATIVE_BRIDGE_MARKERS {
                    if marker.ends_with('/') {
                        if s.contains(marker) {
                            return Some(s.as_str());
                        }
                    } else if s == marker {
                        return Some(s.as_str());
                    }
                }
                None
            })
            .filter(|&marker_str| !Self::is_safe_reference(marker_str))
            .collect();

        matched_markers.sort_unstable();
        matched_markers.dedup();

        if !native_calls.is_empty() {
            let call_summary = if native_calls.len() == 1 {
                native_calls[0].clone()
            } else {
                format!("{} (and {} more)", native_calls[0], native_calls.len() - 1)
            };
            findings.push((
                FindingType::SuspiciousApi,
                format!("Native bridge or Unsafe API usage:\n\t{}", call_summary),
            ));
        } else if !matched_markers.is_empty() {
            let string_summary = if matched_markers.len() == 1 {
                matched_markers[0].to_string()
            } else {
                format!(
                    "{} (and {} more)",
                    matched_markers[0],
                    matched_markers.len() - 1
                )
            };
            findings.push((
                FindingType::SuspiciousApi,
                format!(
                    "Native bridge or Unsafe API usage (referenced in constant pool: {})",
                    string_summary
                ),
            ));
        }

        Self::check_marker(
            &string_set,
            DYNAMIC_LOADING_MARKERS,
            "Dynamic class loading or definition",
            findings,
        );
        Self::check_marker(
            &string_set,
            SCRIPT_ENGINE_MARKERS,
            "Script engine execution",
            findings,
        );
        Self::check_marker(
            &string_set,
            JAVA_AGENT_MARKERS,
            "Java agent instrumentation",
            findings,
        );
        Self::check_marker(
            &string_set,
            ATTACH_API_MARKERS,
            "JVM attach API usage",
            findings,
        );
    }

    fn is_safe_reference(s: &str) -> bool {
        let dot_normalized = s.replace('/', ".");
        let mut index = 0;

        while index < dot_normalized.len() {
            if let Some(pos) = dot_normalized[index..].find("com.sun.jna") {
                let absolute_pos = index + pos;
                let sub = &dot_normalized[absolute_pos..];
                if crate::rules::SAFE_NATIVE_PACKAGES
                    .iter()
                    .any(|pkg| sub == *pkg || sub.starts_with(&format!("{}.", pkg)))
                {
                    index = absolute_pos + "com.sun.jna".len();
                    continue;
                }

                let matches_safe = SAFE_NATIVE_CALLS.iter().any(|&safe| sub.starts_with(safe));
                if !matches_safe {
                    return false;
                }
                index = absolute_pos + "com.sun.jna".len();
            } else if let Some(pos) = dot_normalized[index..].find("sun.misc.Unsafe") {
                let absolute_pos = index + pos;
                let sub = &dot_normalized[absolute_pos..];
                let matches_safe = SAFE_NATIVE_CALLS.iter().any(|&safe| sub.starts_with(safe));
                if !matches_safe {
                    return false;
                }
                index = absolute_pos + "sun.misc.Unsafe".len();
            } else {
                break;
            }
        }
        true
    }

    fn check_marker(
        string_set: &HashSet<&str>,
        markers: &[&str],
        category_message: &str,
        findings: &mut Vec<(FindingType, String)>,
    ) {
        let matched: Vec<&str> = markers
            .iter()
            .filter(|&&marker| string_set.iter().any(|&s| s.contains(marker)))
            .copied()
            .collect();

        if !matched.is_empty() {
            let details = if matched.len() == 1 {
                matched[0].to_string()
            } else {
                format!("{} (and {} more)", matched[0], matched.len() - 1)
            };
            findings.push((
                FindingType::SuspiciousApi,
                format!("{}: {}", category_message, details),
            ));
        }
    }

    fn format_native_call(call: &MethodCallInfo) -> String {
        format!(
            "{}::{}{}",
            call.owner.replace('/', "."),
            call.name,
            call.descriptor
        )
    }

    fn format_process_call(call: &MethodCallInfo) -> String {
        let signature = Self::format_native_call(call);
        if let Some(command) = Self::extract_process_command(call) {
            format!("{} executed: \"{}\"", signature, command)
        } else {
            signature
        }
    }

    fn extract_process_command(call: &MethodCallInfo) -> Option<String> {
        let args: Vec<String> = call
            .arguments
            .iter()
            .filter(|value| !value.is_empty())
            .cloned()
            .collect();

        if args.is_empty() {
            return None;
        }

        Some(truncate_string(&args.join(" "), 80))
    }

    #[allow(dead_code)]
    fn guess_reflected_target(details: &ClassDetails) -> String {
        if let Some(target) = Self::guess_reflected_target_from_calls(&details.method_calls) {
            return target;
        }

        for method in &details.methods {
            if method.name == "getDeclaredMethod" || method.name == "getDeclaredField" {
                return format!("Method/Field: {}", method.name);
            }
        }
        for field in &details.fields {
            if field.name.len() > 5 && !field.name.contains('/') {
                return field.name.clone();
            }
        }
        "".to_string()
    }

    #[allow(dead_code)]
    fn guess_reflected_target_from_calls(method_calls: &[MethodCallInfo]) -> Option<String> {
        for call in method_calls {
            if call.owner == "java/lang/Class"
                && matches!(
                    call.name.as_str(),
                    "getDeclaredMethod" | "getDeclaredField" | "getMethod" | "getField"
                )
            {
                if let Some(target) = call.arguments.first() {
                    if !target.is_empty() {
                        return Some(truncate_string(target, 80));
                    }
                }
            }
        }

        None
    }

    fn is_process_api_call(call: &MethodCallInfo) -> bool {
        (call.owner == "java/lang/Runtime" && call.name == "exec")
            || (call.owner == "java/lang/ProcessBuilder" && call.name == "<init>")
            || (call.owner == "java/lang/ProcessBuilder" && call.name == "command")
    }
}
