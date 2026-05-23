use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use zip::ZipArchive;

use crate::config::SYSTEM_CONFIG;
use crate::constants::{
    EXECUTABLE_RESOURCE_EXTENSIONS, NATIVE_LIBRARY_EXTENSIONS, NESTED_ARCHIVE_EXTENSIONS,
    SCRIPT_RESOURCE_EXTENSIONS,
};
use crate::errors::ScanError;
use crate::scanner::scan::CollapseScanner;
use crate::types::{FindingType, ProgressScope, ResourceInfo, ScanResult};

const MAX_NESTED_ARCHIVE_DEPTH: usize = 2;
const HIGHLY_COMPRESSED_SIZE_THRESHOLD: u64 = 256 * 1024;
const HIGH_COMPRESSION_RATIO_THRESHOLD: f64 = 40.0;
const JAR_ENTRY_BATCH_SIZE: usize = 24;

impl CollapseScanner {
    fn get_archive_entry_name(entry_name: &str) -> String {
        entry_name.replace('\\', "/")
    }

    pub(crate) fn scan_jar_file(&self, jar_path: &Path) -> Result<Vec<ScanResult>, ScanError> {
        let start_time = Instant::now();
        let file = File::open(jar_path)?;
        let mut archive = ZipArchive::new(file)?;
        let total_files = archive.len();
        let mut skipped_count = 0;

        if self.options.verbose {
            println!("[*] Scanning JAR file: {}", jar_path.display());
        }

        let max_entry_size = SYSTEM_CONFIG.max_file_size * 1024 * 1024;

        let processed_count = Arc::new(AtomicUsize::new(0));
        if let Some(ref prog_arc) = self.options.progress {
            if let Ok(mut gp) = prog_arc.lock() {
                if gp.scope != ProgressScope::Targets {
                    gp.scope = ProgressScope::JarEntries;
                    gp.total = total_files;
                    gp.current = 0;
                }
                gp.message = format!("Scanning {}", jar_path.display());
            }
        }

        let results_arc = Arc::new(Mutex::new(Vec::with_capacity(total_files)));

        rayon::scope(|scope| {
            let mut pending_entries = Vec::with_capacity(JAR_ENTRY_BATCH_SIZE);

            for i in 0..total_files {
                let mut archive_file = match archive.by_index(i) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!(
                            "(!) Error accessing entry {} in {}: {}",
                            i,
                            jar_path.display(),
                            e
                        );
                        continue;
                    }
                };

                let original_entry_name = match archive_file.enclosed_name() {
                    Some(p) => Self::get_archive_entry_name(&p.to_string_lossy()),
                    None => Self::get_archive_entry_name(&String::from_utf8_lossy(
                        archive_file.name_raw(),
                    )),
                };

                if archive_file.is_dir() || !self.should_scan(&original_entry_name) {
                    skipped_count += 1;
                    continue;
                }

                let file_size = archive_file.size() as usize;
                if file_size > max_entry_size {
                    if let Some(result) = self
                        .create_oversized_entry_result(&original_entry_name, archive_file.size())
                    {
                        results_arc.lock().unwrap().push(result);
                    } else if self.options.verbose {
                        eprintln!(
                            "(!) Skipping oversized entry ({} bytes): {}",
                            archive_file.size(),
                            original_entry_name
                        );
                    }
                    skipped_count += 1;
                    continue;
                }

                let mut buffer = Vec::with_capacity(file_size);
                if let Err(e) = archive_file.read_to_end(&mut buffer) {
                    eprintln!(
                        "(!) Error reading content of {}: {}",
                        original_entry_name, e
                    );
                    continue;
                }

                let compressed_size = archive_file.compressed_size();
                pending_entries.push((original_entry_name, compressed_size, buffer));

                if pending_entries.len() >= JAR_ENTRY_BATCH_SIZE {
                    let entries = std::mem::replace(
                        &mut pending_entries,
                        Vec::with_capacity(JAR_ENTRY_BATCH_SIZE),
                    );
                    let processed_count_clone = processed_count.clone();
                    let results_clone = results_arc.clone();

                    scope.spawn(move |_| {
                        let mut batch_results = Vec::new();

                        for (entry_name, compressed_size, buffer) in entries {
                            if let Ok(mut entry_results) = self.process_jar_entry(
                                &entry_name,
                                &buffer,
                                compressed_size,
                                &processed_count_clone,
                            ) {
                                batch_results.append(&mut entry_results);
                            }
                        }

                        if !batch_results.is_empty() {
                            results_clone.lock().unwrap().append(&mut batch_results);
                        }
                    });
                }
            }

            if !pending_entries.is_empty() {
                let entries = pending_entries;
                let processed_count_clone = processed_count.clone();
                let results_clone = results_arc.clone();

                scope.spawn(move |_| {
                    let mut batch_results = Vec::new();

                    for (entry_name, compressed_size, buffer) in entries {
                        if let Ok(mut entry_results) = self.process_jar_entry(
                            &entry_name,
                            &buffer,
                            compressed_size,
                            &processed_count_clone,
                        ) {
                            batch_results.append(&mut entry_results);
                        }
                    }

                    if !batch_results.is_empty() {
                        results_clone.lock().unwrap().append(&mut batch_results);
                    }
                });
            }
        });

        let results = Arc::into_inner(results_arc)
            .expect("All threads should have finished")
            .into_inner()
            .unwrap();

        if self.options.verbose {
            println!(
                "[+] JAR scan completed in {:.2}s ({} skipped, {} analyzed)",
                start_time.elapsed().as_secs_f64(),
                skipped_count,
                processed_count.load(Ordering::Relaxed)
            );
        }

        if let Some(ref prog_arc) = self.options.progress {
            if let Ok(mut gp) = prog_arc.lock() {
                if gp.scope == ProgressScope::JarEntries {
                    gp.current = gp.total;
                    gp.message = format!(
                        "Finished processing {} entries",
                        processed_count.load(Ordering::Relaxed)
                    );
                }
            }
        }
        Ok(results)
    }

    pub fn process_jar_entry(
        &self,
        original_entry_name: &str,
        buffer: &[u8],
        compressed_size: u64,
        processed_count: &Arc<AtomicUsize>,
    ) -> Result<Vec<ScanResult>, ScanError> {
        let scan_results = self.scan_archive_entry_contents(
            original_entry_name,
            original_entry_name,
            buffer,
            Some(compressed_size),
            0,
        )?;

        let count = processed_count.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some(ref prog_arc) = self.options.progress {
            if let Ok(mut gp) = prog_arc.lock() {
                if gp.cancelled {
                    gp.message = "Scan cancelled".to_string();
                    return Ok(Vec::new());
                }
                if gp.scope == ProgressScope::JarEntries {
                    gp.current = count;
                    gp.message = original_entry_name.to_string();
                }
            }
        }

        Ok(scan_results)
    }

    fn scan_archive_entry_contents(
        &self,
        display_path: &str,
        resource_name: &str,
        buffer: &[u8],
        compressed_size: Option<u64>,
        archive_depth: usize,
    ) -> Result<Vec<ScanResult>, ScanError> {
        let resource_info = self.analyze_resource(display_path, buffer)?;
        let mut results = Vec::new();

        if let Some(result) = self.create_resource_result(
            display_path,
            resource_name,
            buffer,
            compressed_size,
            &resource_info,
        ) {
            results.push(result);
        }

        if resource_info.is_class_file || resource_info.is_dead_class_candidate {
            if let Some(scan_result) =
                self.scan_class_data(buffer, display_path, Some(resource_info.clone()))?
            {
                results.push(scan_result);
            }
        }

        if archive_depth < MAX_NESTED_ARCHIVE_DEPTH
            && self.should_recurse_into_archive(resource_name, buffer)
        {
            results.extend(self.scan_nested_archive_buffer(
                display_path,
                buffer,
                archive_depth + 1,
            )?);
        }

        Ok(results)
    }

    fn scan_nested_archive_buffer(
        &self,
        container_path: &str,
        buffer: &[u8],
        archive_depth: usize,
    ) -> Result<Vec<ScanResult>, ScanError> {
        let cursor = Cursor::new(buffer);
        let mut archive = match ZipArchive::new(cursor) {
            Ok(archive) => archive,
            Err(_) => return Ok(Vec::new()),
        };

        let max_entry_size = SYSTEM_CONFIG.max_file_size * 1024 * 1024;
        let mut results = Vec::new();

        for index in 0..archive.len() {
            let mut archive_file = match archive.by_index(index) {
                Ok(file) => file,
                Err(error) => {
                    if self.options.verbose {
                        eprintln!(
                            "(!) Error accessing nested entry {} in {}: {}",
                            index, container_path, error
                        );
                    }
                    continue;
                }
            };

            let relative_name = match archive_file.enclosed_name() {
                Some(path) => Self::get_archive_entry_name(&path.to_string_lossy()),
                None => {
                    Self::get_archive_entry_name(&String::from_utf8_lossy(archive_file.name_raw()))
                }
            };

            if archive_file.is_dir() || !self.should_scan(&relative_name) {
                continue;
            }

            let display_path = format!("{}!/{relative_name}", container_path);
            let file_size = archive_file.size() as usize;
            if file_size > max_entry_size {
                if let Some(result) =
                    self.create_oversized_entry_result(&display_path, archive_file.size())
                {
                    results.push(result);
                }
                continue;
            }

            let compressed_size = archive_file.compressed_size();
            let mut nested_buffer = Vec::with_capacity(file_size);
            if let Err(error) = archive_file.read_to_end(&mut nested_buffer) {
                if self.options.verbose {
                    eprintln!(
                        "(!) Error reading nested entry {} from {}: {}",
                        relative_name, container_path, error
                    );
                }
                continue;
            }

            results.extend(self.scan_archive_entry_contents(
                &display_path,
                &relative_name,
                &nested_buffer,
                Some(compressed_size),
                archive_depth,
            )?);
        }

        Ok(results)
    }

    fn create_resource_result(
        &self,
        display_path: &str,
        resource_name: &str,
        buffer: &[u8],
        compressed_size: Option<u64>,
        resource_info: &ResourceInfo,
    ) -> Option<ScanResult> {
        let mut findings = self.collect_resource_findings(resource_name, buffer, compressed_size);
        if findings.is_empty() {
            return None;
        }

        self.normalize_findings(&mut findings);
        let danger_score = self.calculate_danger_score(&findings, Some(resource_info));
        let danger_explanation =
            self.generate_danger_explanation(danger_score, &findings, Some(resource_info));

        Some(ScanResult {
            file_path: display_path.to_string(),
            matches: Arc::new(findings),
            class_details: None,
            resource_info: Some(resource_info.clone()),
            danger_score,
            danger_explanation,
        })
    }

    fn create_oversized_entry_result(&self, entry_name: &str, size: u64) -> Option<ScanResult> {
        let ends_with_ignore_case = |s: &str, suffix: &str| {
            s.len() >= suffix.len() && a_ends_with_b_case_insensitive(s, suffix)
        };
        let is_class_candidate = ends_with_ignore_case(entry_name, ".class")
            || ends_with_ignore_case(entry_name, ".class/");
        let is_interesting_resource = is_class_candidate
            || self.has_extension(entry_name, NESTED_ARCHIVE_EXTENSIONS)
            || self.has_extension(entry_name, SCRIPT_RESOURCE_EXTENSIONS)
            || self.has_extension(entry_name, EXECUTABLE_RESOURCE_EXTENSIONS)
            || self.has_extension(entry_name, NATIVE_LIBRARY_EXTENSIONS);

        if !is_interesting_resource {
            return None;
        }

        let mut findings = vec![(
            FindingType::SuspiciousArchiveEntry,
            format!(
                "Oversized entry was not fully inspected ({} bytes exceeds {} MB limit)",
                size, SYSTEM_CONFIG.max_file_size
            ),
        )];

        if self.has_extension(entry_name, NATIVE_LIBRARY_EXTENSIONS) {
            findings.push((
                FindingType::NativeLibrary,
                format!("Oversized native library resource: {}", entry_name),
            ));
        }

        self.normalize_findings(&mut findings);

        let resource_info = ResourceInfo {
            path: entry_name.to_string(),
            size,
            is_class_file: is_class_candidate,
            is_dead_class_candidate: false,
        };
        let danger_score = self.calculate_danger_score(&findings, Some(&resource_info));
        let danger_explanation =
            self.generate_danger_explanation(danger_score, &findings, Some(&resource_info));

        Some(ScanResult {
            file_path: entry_name.to_string(),
            matches: Arc::new(findings),
            class_details: None,
            resource_info: Some(resource_info),
            danger_score,
            danger_explanation,
        })
    }

    fn collect_resource_findings(
        &self,
        resource_name: &str,
        buffer: &[u8],
        compressed_size: Option<u64>,
    ) -> Vec<(FindingType, String)> {
        let mut findings = Vec::new();

        if self.has_extension(resource_name, SCRIPT_RESOURCE_EXTENSIONS) {
            findings.push((
                FindingType::SuspiciousArchiveEntry,
                format!("Embedded script resource: {}", resource_name),
            ));
        }

        if self.has_extension(resource_name, EXECUTABLE_RESOURCE_EXTENSIONS) {
            findings.push((
                FindingType::SuspiciousArchiveEntry,
                format!("Embedded executable resource: {}", resource_name),
            ));
        }

        if self.has_extension(resource_name, NATIVE_LIBRARY_EXTENSIONS) {
            findings.push((
                FindingType::NativeLibrary,
                format!("Embedded native library: {}", resource_name),
            ));
        }

        if let Some(binary_kind) = Self::detect_binary_magic(buffer) {
            let finding_type = if self.has_extension(resource_name, NATIVE_LIBRARY_EXTENSIONS) {
                FindingType::NativeLibrary
            } else {
                FindingType::SuspiciousArchiveEntry
            };

            findings.push((
                finding_type,
                format!(
                    "Embedded binary payload header ({binary_kind}) in {}",
                    resource_name
                ),
            ));
        }

        if resource_name.eq_ignore_ascii_case("meta-inf/manifest.mf") {
            self.inspect_manifest(resource_name, buffer, &mut findings);
        }

        if let Some(compressed_size) = compressed_size.filter(|size| *size > 0) {
            let uncompressed_size = buffer.len() as u64;
            let ratio = uncompressed_size as f64 / compressed_size as f64;
            if uncompressed_size >= HIGHLY_COMPRESSED_SIZE_THRESHOLD
                && ratio >= HIGH_COMPRESSION_RATIO_THRESHOLD
            {
                findings.push((
                    FindingType::SuspiciousArchiveEntry,
                    format!(
                        "Highly compressed resource ({ratio:.1}x ratio): {}",
                        resource_name
                    ),
                ));
            }
        }

        findings
    }

    fn inspect_manifest(
        &self,
        resource_name: &str,
        buffer: &[u8],
        findings: &mut Vec<(FindingType, String)>,
    ) {
        let manifest = String::from_utf8_lossy(buffer);
        let mut matched_headers = Vec::new();

        for header in [
            "Premain-Class",
            "Agent-Class",
            "Launcher-Agent-Class",
            "Can-Redefine-Classes",
            "Can-Retransform-Classes",
            "Permissions: all-permissions",
        ] {
            if manifest.contains(header) {
                matched_headers.push(header);
            }
        }

        if !matched_headers.is_empty() {
            findings.push((
                FindingType::SuspiciousArchiveEntry,
                format!(
                    "Manifest requests instrumentation or elevated permissions ({}) in {}",
                    matched_headers.join(", "),
                    resource_name
                ),
            ));
        }
    }

    fn should_recurse_into_archive(&self, resource_name: &str, buffer: &[u8]) -> bool {
        self.has_extension(resource_name, NESTED_ARCHIVE_EXTENSIONS) || Self::has_zip_magic(buffer)
    }

    fn has_extension(&self, resource_name: &str, extensions: &[&str]) -> bool {
        Path::new(resource_name)
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| {
                extensions
                    .iter()
                    .any(|candidate| ext.eq_ignore_ascii_case(candidate))
            })
    }

    fn has_zip_magic(buffer: &[u8]) -> bool {
        buffer.len() >= 4
            && buffer[0] == b'P'
            && buffer[1] == b'K'
            && matches!(buffer[2], b'\x03' | b'\x05' | b'\x07')
    }

    fn detect_binary_magic(buffer: &[u8]) -> Option<&'static str> {
        if buffer.starts_with(b"MZ") {
            Some("PE")
        } else if buffer.starts_with(b"\x7FELF") {
            Some("ELF")
        } else if buffer.starts_with(&[0xCF, 0xFA, 0xED, 0xFE])
            || buffer.starts_with(&[0xCE, 0xFA, 0xED, 0xFE])
            || buffer.starts_with(&[0xFE, 0xED, 0xFA, 0xCF])
            || buffer.starts_with(&[0xFE, 0xED, 0xFA, 0xCE])
        {
            Some("Mach-O")
        } else {
            None
        }
    }

    pub fn analyze_resource(
        &self,
        original_path_str: &str,
        data: &[u8],
    ) -> Result<ResourceInfo, ScanError> {
        let is_class_name_candidate =
            original_path_str.ends_with(".class") || original_path_str.ends_with(".class/");

        let is_standard_class_file =
            is_class_name_candidate && data.starts_with(b"\xCA\xFE\xBA\xBE");

        let is_dead_class_candidate = is_class_name_candidate && !is_standard_class_file;

        Ok(ResourceInfo {
            path: original_path_str.to_string(),
            size: data.len() as u64,
            is_class_file: is_standard_class_file,
            is_dead_class_candidate,
        })
    }
}

fn a_ends_with_b_case_insensitive(a: &str, b: &str) -> bool {
    a.len() >= b.len() && a[a.len() - b.len()..].eq_ignore_ascii_case(b)
}
