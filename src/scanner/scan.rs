use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::config::SYSTEM_CONFIG;
use crate::detection::SUSSY_DOMAINS;
use crate::errors::ScanError;
use crate::filters::GOOD_LINKS;
use crate::types::ScannerOptions;

type ResultCache = Arc<RwLock<HashMap<u64, Arc<Vec<(crate::types::FindingType, String)>>>>>;

pub struct CollapseScanner {
    pub options: ScannerOptions,
    pub found_custom_jvm_indicator: Arc<std::sync::Mutex<bool>>,
    pub good_links: std::collections::HashSet<String>,
    pub suspicious_domains: std::collections::HashSet<String>,
    pub ignored_suspicious_keywords: std::collections::HashSet<String>,
    pub exclude_patterns: Vec<String>,
    pub find_patterns: Vec<String>,
    pub result_cache: ResultCache,
}

impl CollapseScanner {
    pub fn new(options: ScannerOptions) -> Result<Self, ScanError> {
        let good_links = (*GOOD_LINKS).clone();

        let mut ignored_suspicious_keywords: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        if let Some(ref path) = options.ignore_keywords_file {
            if options.verbose {
                println!("[#] Loading keywords ignore list from: {}", path.display());
            }
            match Self::load_ignore_list_from_file(path) {
                Ok(ignored) => {
                    if options.verbose {
                        println!("[+] Loaded {} keywords to ignore", ignored.len());
                    }
                    ignored_suspicious_keywords.extend(ignored.clone());
                }
                Err(e) => {
                    eprintln!(
                        "(!) Warning: Could not load keywords ignore list from {}: {}",
                        path.display(),
                        e
                    );
                }
            }
        }

        if options.verbose {
            SYSTEM_CONFIG.log_config();
        }

        let exclude_patterns = options.exclude_patterns.clone();
        let find_patterns = options.find_patterns.clone();

        Ok(CollapseScanner {
            good_links,
            suspicious_domains: (*SUSSY_DOMAINS).clone(),
            ignored_suspicious_keywords,
            options,
            found_custom_jvm_indicator: Arc::new(std::sync::Mutex::new(false)),
            exclude_patterns,
            find_patterns,
            result_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }
}