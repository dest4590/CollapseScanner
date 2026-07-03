use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

mod arc_matches_serde {
    use super::FindingType;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::sync::Arc;

    pub fn serialize<S>(v: &Arc<Vec<(FindingType, String)>>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        v.as_ref().serialize(s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Arc<Vec<(FindingType, String)>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<(FindingType, String)>::deserialize(d).map(Arc::new)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub file_path: String,
    #[serde(with = "arc_matches_serde")]
    pub matches: Arc<Vec<(FindingType, String)>>,
    pub class_details: Option<ClassDetails>,
    pub resource_info: Option<ResourceInfo>,
    pub danger_score: u8,
    pub danger_explanation: Vec<String>,
}

impl ScanResult {
    pub fn to_json_report(&self) -> serde_json::Value {
        serde_json::json!({
            "file_path": self.file_path,
            "danger_score": self.danger_score,
            "danger_explanation": self.danger_explanation,
            "findings": self.matches.iter().map(|(ft, v)|
                serde_json::json!({"type": format!("{ft}"), "value": v})
            ).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct Progress {
    pub current: usize,
    pub total: usize,
    pub message: String,
    pub cancelled: bool,
    pub finished: bool,
    pub scope: ProgressScope,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressScope {
    Preparing,
    Targets,
    JarEntries,
}

impl ProgressScope {
    pub fn label(self) -> &'static str {
        match self {
            ProgressScope::Preparing => "Setup",
            ProgressScope::Targets => "Files",
            ProgressScope::JarEntries => "Items",
        }
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FindingType {
    IpAddress,
    IpV6Address,
    Url,
    SuspiciousUrl,
    DiscordWebhook,
    SuspiciousKeyword,
    JavaAPI,
    CredentialSecret,
    EncodedPayload,
    TamperedClass,
    NativeLibrary,
    ArchiveEntry,
    ObfuscationUnicode,
}

struct FindingTypeMeta {
    display: &'static str,
    symbol: &'static str,
    color: &'static str,
    base_score: u8,
    max_contribution: u8,
    order: usize,
}

const FINDING_TYPE_META: &[FindingTypeMeta] = &[
    FindingTypeMeta {
        display: "IPv4 Address",
        symbol: "[IP]",
        color: "red",
        base_score: 2,
        max_contribution: 5,
        order: 6,
    },
    FindingTypeMeta {
        display: "IPv6 Address",
        symbol: "[IP]",
        color: "red",
        base_score: 2,
        max_contribution: 5,
        order: 11,
    },
    FindingTypeMeta {
        display: "URL",
        symbol: "[URL]",
        color: "blue",
        base_score: 1,
        max_contribution: 4,
        order: 8,
    },
    FindingTypeMeta {
        display: "Network URL",
        symbol: "[NET]",
        color: "yellow",
        base_score: 5,
        max_contribution: 8,
        order: 2,
    },
    FindingTypeMeta {
        display: "Discord Webhook",
        symbol: "[WEBHOOK]",
        color: "red",
        base_score: 10,
        max_contribution: 10,
        order: 0,
    },
    FindingTypeMeta {
        display: "Sensitive Keyword",
        symbol: "[CODE]",
        color: "red",
        base_score: 3,
        max_contribution: 6,
        order: 7,
    },
    FindingTypeMeta {
        display: "Java API",
        symbol: "[API]",
        color: "yellow",
        base_score: 3,
        max_contribution: 7,
        order: 3,
    },
    FindingTypeMeta {
        display: "Credential or Token",
        symbol: "[SECRET]",
        color: "red",
        base_score: 8,
        max_contribution: 10,
        order: 4,
    },
    FindingTypeMeta {
        display: "Encoded Payload",
        symbol: "[BLOB]",
        color: "magenta",
        base_score: 2,
        max_contribution: 5,
        order: 5,
    },
    FindingTypeMeta {
        display: "Tampered Class",
        symbol: "[CLASS]",
        color: "red",
        base_score: 6,
        max_contribution: 10,
        order: 1,
    },
    FindingTypeMeta {
        display: "Native Library",
        symbol: "[NATIVE]",
        color: "yellow",
        base_score: 4,
        max_contribution: 7,
        order: 9,
    },
    FindingTypeMeta {
        display: "Archive Entry",
        symbol: "[ENTRY]",
        color: "yellow",
        base_score: 4,
        max_contribution: 8,
        order: 10,
    },
    FindingTypeMeta {
        display: "Unicode Obfuscation",
        symbol: "[OBF]",
        color: "magenta",
        base_score: 1,
        max_contribution: 3,
        order: 12,
    },
];

impl FindingType {
    fn meta(self) -> &'static FindingTypeMeta {
        &FINDING_TYPE_META[self as usize]
    }

    pub fn with_symbol(&self) -> (&'static str, &'static str) {
        (self.meta().symbol, self.meta().color)
    }

    pub fn base_score(&self) -> u8 {
        self.meta().base_score
    }

    pub fn max_contribution(&self) -> u8 {
        self.meta().max_contribution
    }

    pub fn display_order(&self) -> usize {
        self.meta().order
    }
}

impl std::fmt::Display for FindingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.meta().display)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassDetails {
    pub class_name: String,
    pub superclass_name: String,
    pub interfaces: Vec<String>,
    pub methods: Vec<MethodInfo>,
    #[serde(default)]
    pub method_calls: Vec<MethodCallInfo>,
    pub fields: Vec<FieldInfo>,
    pub strings: Vec<String>,
    pub access_flags: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodInfo {
    pub name: String,
    pub descriptor: String,
    pub access_flags: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodCallInfo {
    pub owner: String,
    pub name: String,
    pub descriptor: String,
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldInfo {
    pub name: String,
    pub descriptor: String,
    pub access_flags: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceInfo {
    pub path: String,
    pub size: u64,
    pub is_class_file: bool,
    pub is_dead_class_candidate: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize, clap::ValueEnum)]
pub enum DetectionMode {
    Network,
    Malicious,
    Obfuscation,
    All,
}

impl std::fmt::Display for DetectionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            DetectionMode::Network => "Network",
            DetectionMode::Malicious => "Malicious",
            DetectionMode::Obfuscation => "Obfuscation",
            DetectionMode::All => "All",
        };
        f.write_str(label)
    }
}

#[derive(Clone)]
pub struct ScannerOptions {
    pub mode: DetectionMode,
    pub verbose: bool,
    pub ignore_keywords_file: Option<PathBuf>,
    pub exclude_patterns: Vec<String>,
    pub find_patterns: Vec<String>,
    pub progress: Option<Arc<Mutex<Progress>>>,
    pub max_nested_archive_depth: usize,
    pub max_strings_per_class: usize,
}

impl Default for ScannerOptions {
    fn default() -> Self {
        ScannerOptions {
            mode: DetectionMode::All,
            verbose: false,
            ignore_keywords_file: None,
            exclude_patterns: Vec::new(),
            find_patterns: Vec::new(),
            progress: None,
            max_nested_archive_depth: 4,
            max_strings_per_class: 2000,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ConstantPoolEntry {
    Utf8(std::sync::Arc<str>),
    Integer,
    Float,
    Long,
    Double,
    Class(u16),
    String(u16),
    Fieldref(u16, u16),
    Methodref(u16, u16),
    InterfaceMethodref(u16, u16),
    NameAndType(u16, u16),
    MethodHandle,
    MethodType,
    Dynamic,
    InvokeDynamic,
    Module,
    Package,
    Placeholder,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finding_type_display() {
        assert_eq!(FindingType::IpAddress.to_string(), "IPv4 Address");
        assert_eq!(FindingType::DiscordWebhook.to_string(), "Discord Webhook");
        assert_eq!(FindingType::JavaAPI.to_string(), "Java API");
    }

    #[test]
    fn test_finding_type_base_score() {
        assert_eq!(FindingType::DiscordWebhook.base_score(), 10);
        assert_eq!(FindingType::IpAddress.base_score(), 2);
        assert_eq!(FindingType::SuspiciousKeyword.base_score(), 3);
        assert_eq!(FindingType::EncodedPayload.base_score(), 2);
    }

    #[test]
    fn test_finding_type_max_contribution() {
        assert_eq!(FindingType::DiscordWebhook.max_contribution(), 10);
        assert_eq!(FindingType::IpAddress.max_contribution(), 5);
        assert_eq!(FindingType::CredentialSecret.max_contribution(), 10);
    }

    #[test]
    fn test_detection_mode_display() {
        assert_eq!(DetectionMode::All.to_string(), "All");
        assert_eq!(DetectionMode::Network.to_string(), "Network");
    }

    #[test]
    fn test_scanner_options_default() {
        let opts = ScannerOptions::default();
        assert_eq!(opts.mode, DetectionMode::All);
        assert!(!opts.verbose);
        assert_eq!(opts.max_nested_archive_depth, 4);
        assert_eq!(opts.max_strings_per_class, 2000);
    }
}
