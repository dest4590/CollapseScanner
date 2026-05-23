use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::path::Path;

use rayon::prelude::*;
use walkdir::WalkDir;

use crate::config::SYSTEM_CONFIG;
use crate::rules::{CLASS_EXTS, JAR_CLASS_EXTS, JAR_EXTS};
use crate::errors::ScanError;
use crate::scanner::scan::CollapseScanner;
use crate::types::{ProgressScope, ScanResult};

fn has_extension(path: &Path, exts: &[&str]) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| exts.iter().any(|e| ext.eq_ignore_ascii_case(e)))
}

fn glob_matches(path: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if pattern.starts_with("*") && !pattern[1..].contains('*') {
        return path.ends_with(&pattern[1..]);
    }

    if let Some(dir) = pattern.strip_suffix("/*") {
        return path.starts_with(dir) && path[dir.len()..].starts_with('/');
    }

    if let Some(dir) = pattern.strip_suffix("/**") {
        return path.starts_with(dir);
    }

    if !pattern.contains('*') && !pattern.contains('?') {
        return path.contains(pattern);
    }

    path == pattern
}

impl CollapseScanner {
    pub(crate) fn should_scan(&self, internal_path: &str) -> bool {
        if self
            .exclude_patterns
            .iter()
            .any(|pattern| glob_matches(internal_path, pattern))
        {
            if self.options.verbose {
                println!("[-] Skipping excluded file: {}", internal_path);
            }
            return false;
        }

        if !self.find_patterns.is_empty() {
            let matches = self
                .find_patterns
                .iter()
                .any(|pattern| glob_matches(internal_path, pattern));

            if !matches {
                return false;
            }
        }

        true
    }

    pub(crate) fn load_ignore_list_from_file(path: &Path) -> Result<HashSet<String>, io::Error> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut ignored_set = HashSet::new();

        for line in reader.lines() {
            let line_content = line?;
            let trimmed = line_content.trim();
            if !trimmed.is_empty() {
                ignored_set.insert(trimmed.to_lowercase());
            }
        }
        Ok(ignored_set)
    }

    pub fn scan_path(&self, path: &Path) -> Result<Vec<ScanResult>, ScanError> {
        if path.is_dir() {
            return self.scan_directory(path);
        }

        if let Ok(metadata) = fs::metadata(path) {
            let file_size_mb = metadata.len() / (1024 * 1024);
            if file_size_mb > SYSTEM_CONFIG.max_file_size as u64 {
                if self.options.verbose {
                    println!(
                        "(!) Skipping file larger than {} MB: {}",
                        SYSTEM_CONFIG.max_file_size,
                        path.display()
                    );
                }
                return Ok(Vec::new());
            }
        }

        if has_extension(path, JAR_EXTS) {
            if let Some(progress) = &self.options.progress {
                if let Ok(mut state) = progress.lock() {
                    if state.scope != ProgressScope::Targets {
                        state.scope = ProgressScope::JarEntries;
                        state.current = 0;
                        state.total = 0;
                        state.message = format!("Opening {}", path.display());
                    }
                }
            }
            self.scan_jar_file(path)
        } else if has_extension(path, CLASS_EXTS) {
            let filename = path.file_name().unwrap_or_default().to_string_lossy();
            if !self.should_scan(&filename) {
                if self.options.verbose {
                    println!("[-] Skipping filtered file: {}", filename);
                }
                return Ok(Vec::new());
            }

            if self.options.verbose {
                println!("[*] Scanning loose class file: {}", path.display());
            }

            if let Some(progress) = &self.options.progress {
                if let Ok(mut state) = progress.lock() {
                    if state.scope != ProgressScope::Targets {
                        state.scope = ProgressScope::Targets;
                        state.total = 1;
                        state.current = 0;
                    }
                    state.message = filename.to_string();
                }
            }

            let file_data = fs::read(path)?;
            let resource_info = self.analyze_resource(&filename, &file_data)?;
            let result = self
                .scan_class_file_data(&filename, file_data, Some(resource_info))
                .map(|res| vec![res]);

            if let Some(progress) = &self.options.progress {
                if let Ok(mut state) = progress.lock() {
                    state.current = state.total.max(1);
                    state.message = filename.to_string();
                }
            }

            result
        } else {
            Err(ScanError::UnsupportedFileType(
                path.extension().map(|s| s.to_os_string()),
            ))
        }
    }

    fn scan_directory(&self, directory: &Path) -> Result<Vec<ScanResult>, ScanError> {
        let mut targets = Vec::new();

        for entry in WalkDir::new(directory).follow_links(false).into_iter() {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    if self.options.verbose {
                        eprintln!("(!) Skipping unreadable directory entry: {}", error);
                    }
                    continue;
                }
            };

            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path();
            if !has_extension(path, JAR_CLASS_EXTS) {
                continue;
            }

            let display_path = path.to_string_lossy();
            if self.should_scan(&display_path) {
                targets.push(path.to_path_buf());
            }
        }

        if self.options.verbose {
            println!(
                "[*] Found {} scannable file(s) under {}",
                targets.len(),
                directory.display()
            );
        }

        if let Some(progress) = &self.options.progress {
            if let Ok(mut state) = progress.lock() {
                state.scope = ProgressScope::Targets;
                state.total = targets.len();
                state.current = 0;
                state.message = format!("Scanning {}", directory.display());
            }
        }

        let nested_results: Vec<Vec<ScanResult>> = targets
            .par_iter()
            .filter_map(|target| match self.scan_path(target) {
                Ok(results) => {
                    if let Some(progress) = &self.options.progress {
                        if let Ok(mut state) = progress.lock() {
                            state.current += 1;
                            state.message = target.display().to_string();
                        }
                    }
                    Some(results)
                }
                Err(error) => {
                    if self.options.verbose {
                        eprintln!("(!) Error scanning {}: {}", target.display(), error);
                    }
                    if let Some(progress) = &self.options.progress {
                        if let Ok(mut state) = progress.lock() {
                            state.current += 1;
                            state.message = format!("Skipped {}", target.display());
                        }
                    }
                    None
                }
            })
            .collect();

        Ok(nested_results.into_iter().flatten().collect())
    }
}
