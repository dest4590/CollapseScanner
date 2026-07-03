use crate::rules::{
    ATTACH_API_MARKERS, DYNAMIC_LOADING_MARKERS, JAVA_AGENT_MARKERS, NATIVE_BRIDGE_MARKERS,
    SAFE_NATIVE_CALLS,
};
use crate::types::{ClassDetails, FindingType, MethodCallInfo};
use crate::utils::truncate_string;
use std::collections::HashSet;

pub struct ApiAnalyzer;

impl ApiAnalyzer {
    pub fn analyze(details: &ClassDetails, findings: &mut Vec<(FindingType, String)>) {
        let string_set: HashSet<&str> = details.strings.iter().map(String::as_str).collect();

        Self::analyze_process_calls(details, findings);
        Self::analyze_native_bridge(details, findings);

        Self::check_marker(
            &string_set,
            DYNAMIC_LOADING_MARKERS,
            "Dynamic class loading or definition",
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

        let reflected_target = Self::guess_reflected_target(details);
        if !reflected_target.is_empty() {
            findings.push((
                FindingType::JavaAPI,
                format!("Reflection target: {}", reflected_target),
            ));
        }
    }

    fn summarize(first: &str, count: usize) -> String {
        if count == 1 {
            first.to_string()
        } else {
            format!("{} (and {} more)", first, count - 1)
        }
    }

    fn analyze_process_calls(details: &ClassDetails, findings: &mut Vec<(FindingType, String)>) {
        let calls: Vec<String> = details
            .method_calls
            .iter()
            .filter(|call| Self::is_process_api_call(call))
            .map(Self::format_process_call)
            .collect();

        if !calls.is_empty() {
            findings.push((
                FindingType::JavaAPI,
                format!(
                    "Process execution API usage: {}",
                    Self::summarize(&calls[0], calls.len())
                ),
            ));
        }
    }

    fn analyze_native_bridge(details: &ClassDetails, findings: &mut Vec<(FindingType, String)>) {
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
            .filter(|call| !call.owner.starts_with("com/sun/jna"))
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
            findings.push((
                FindingType::JavaAPI,
                format!(
                    "Native bridge or Unsafe API usage:\n\t{}",
                    Self::summarize(&native_calls[0], native_calls.len())
                ),
            ));
        } else if !matched_markers.is_empty() {
            findings.push((
                FindingType::JavaAPI,
                format!(
                    "Native bridge or Unsafe API usage (referenced in constant pool: {})",
                    Self::summarize(matched_markers[0], matched_markers.len()),
                ),
            ));
        }
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
                FindingType::JavaAPI,
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
            || (call.owner == "java/lang/ProcessImpl" && call.name == "start")
            || (call.owner == "javax/script/ScriptEngineManager" && call.name == "getEngineByName")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_call(owner: &str, name: &str, args: Vec<&str>) -> MethodCallInfo {
        MethodCallInfo {
            owner: owner.to_string(),
            name: name.to_string(),
            descriptor: "()V".to_string(),
            arguments: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn test_is_process_api_call_runtime_exec() {
        let call = make_call("java/lang/Runtime", "exec", vec!["cmd"]);
        assert!(ApiAnalyzer::is_process_api_call(&call));
    }

    #[test]
    fn test_is_process_api_call_processbuilder() {
        let call = make_call("java/lang/ProcessBuilder", "<init>", vec![]);
        assert!(ApiAnalyzer::is_process_api_call(&call));
    }

    #[test]
    fn test_is_process_api_call_negative() {
        let call = make_call("java/lang/String", "length", vec![]);
        assert!(!ApiAnalyzer::is_process_api_call(&call));
    }

    #[test]
    fn test_guess_reflected_target_from_calls_found() {
        let calls = vec![make_call(
            "java/lang/Class",
            "getDeclaredMethod",
            vec!["evilMethod"],
        )];
        let result = ApiAnalyzer::guess_reflected_target_from_calls(&calls);
        assert_eq!(result, Some("evilMethod".to_string()));
    }

    #[test]
    fn test_guess_reflected_target_from_calls_none() {
        let calls = vec![make_call("java/lang/String", "length", vec![])];
        let result = ApiAnalyzer::guess_reflected_target_from_calls(&calls);
        assert_eq!(result, None);
    }

    #[test]
    fn test_is_safe_reference_jna() {
        assert!(ApiAnalyzer::is_safe_reference("com.sun.jna.Native"));
        assert!(ApiAnalyzer::is_safe_reference("sun.misc.Unsafe"));
        assert!(ApiAnalyzer::is_safe_reference("no jna or unsafe here"));
        assert!(!ApiAnalyzer::is_safe_reference("com.sun.jnaevil"));
    }

    #[test]
    fn test_format_native_call() {
        let call = make_call("java/lang/Runtime", "exec", vec![]);
        let formatted = ApiAnalyzer::format_native_call(&call);
        assert_eq!(formatted, "java.lang.Runtime::exec()V");
    }
}
