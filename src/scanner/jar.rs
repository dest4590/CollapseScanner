use std::io::{Cursor, Read};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use rayon::prelude::*;
use zip::ZipArchive;

use crate::errors::ScanError;
use crate::rules::{
    EXECUTABLE_RESOURCE_EXTENSIONS, NATIVE_LIBRARY_EXTENSIONS, NESTED_ARCHIVE_EXTENSIONS,
    SCRIPT_RESOURCE_EXTENSIONS,
};
use crate::scanner::scan::CollapseScanner;
use crate::types::{FindingType, ProgressScope, ResourceInfo, ScanResult};

const HIGHLY_COMPRESSED_SIZE_THRESHOLD: u64 = 256 * 1024;
const HIGH_COMPRESSION_RATIO_THRESHOLD: f64 = 40.0;

fn get_archive_entry_name(entry_name: &str) -> String {
    entry_name.replace('\\', "/")
}

impl CollapseScanner {
    pub(crate) fn scan_jar_file(&self, jar_path: &Path) -> Result<Vec<ScanResult>, ScanError> {
        let start_time = Instant::now();

        if let Some(ref prog_arc) = self.options.progress {
            if let Ok(mut gp) = prog_arc.lock() {
                gp.message = format!("Reading {}", jar_path.display());
            }
        }

        let file_data = std::fs::read(jar_path)?;

        let indices_to_scan: Vec<usize> = {
            let mut archive = ZipArchive::new(Cursor::new(&file_data[..]))?;
            let mut indices = Vec::new();
            let mut skipped = 0;

            for i in 0..archive.len() {
                let entry = match archive.by_index(i) {
                    Ok(f) => f,
                    Err(_) => {
                        skipped += 1;
                        continue;
                    }
                };
                let name = match entry.enclosed_name() {
                    Some(p) => get_archive_entry_name(&p.to_string_lossy()),
                    None => get_archive_entry_name(&String::from_utf8_lossy(entry.name_raw())),
                };
                if !entry.is_dir() && self.should_scan(&name) {
                    indices.push(i);
                } else {
                    skipped += 1;
                }
            }

            if self.options.verbose {
                println!(
                    "[+] JAR indexed: {} entries ({} skipped)",
                    archive.len(),
                    skipped
                );
            }
            indices
        };

        let total_files = indices_to_scan.len();
        let processed_count = Arc::new(AtomicUsize::new(0));

        if let Some(ref prog_arc) = self.options.progress {
            if let Ok(mut gp) = prog_arc.lock() {
                gp.scope = ProgressScope::JarEntries;
                gp.total = total_files;
                gp.current = 0;
                gp.message = format!("Scanning {}", jar_path.display());
            }
        }

        let results: Vec<ScanResult> = indices_to_scan
            .par_iter()
            .flat_map(|&i| {
                let mut archive = match ZipArchive::new(Cursor::new(&file_data[..])) {
                    Ok(a) => a,
                    Err(_) => return Vec::new(),
                };
                let mut entry = match archive.by_index(i) {
                    Ok(f) => f,
                    Err(_) => return Vec::new(),
                };
                let entry_name = match entry.enclosed_name() {
                    Some(p) => get_archive_entry_name(&p.to_string_lossy()),
                    None => get_archive_entry_name(&String::from_utf8_lossy(entry.name_raw())),
                };
                let file_size = entry.size() as usize;
                let mut buffer = Vec::with_capacity(file_size);
                if entry.read_to_end(&mut buffer).is_err() {
                    processed_count.fetch_add(1, Ordering::Relaxed);
                    return Vec::new();
                }
                let compressed_size = entry.compressed_size();

                let progress_name = entry_name.clone();
                if let Some(ref prog_arc) = self.options.progress {
                    if let Ok(mut gp) = prog_arc.lock() {
                        if gp.scope == ProgressScope::JarEntries {
                            gp.current = gp.current.saturating_add(1).min(gp.total.max(1));
                            gp.message = progress_name;
                        }
                    }
                }

                match self.process_jar_entry(
                    &entry_name,
                    &buffer,
                    compressed_size,
                    &processed_count,
                ) {
                    Ok(r) => r,
                    Err(_) => {
                        processed_count.fetch_add(1, Ordering::Relaxed);
                        Vec::new()
                    }
                }
            })
            .collect();

        if self.options.verbose {
            println!(
                "[+] JAR scan completed in {:.2}s ({} analyzed)",
                start_time.elapsed().as_secs_f64(),
                processed_count.load(Ordering::Relaxed)
            );
        }

        if let Some(ref prog_arc) = self.options.progress {
            if let Ok(mut gp) = prog_arc.lock() {
                if gp.scope == ProgressScope::JarEntries {
                    gp.current = gp.total;
                    gp.message = "Finished scanning JAR".to_string();
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

        processed_count.fetch_add(1, Ordering::Relaxed);
        if let Some(ref prog_arc) = self.options.progress {
            if let Ok(mut gp) = prog_arc.lock() {
                if gp.cancelled {
                    gp.message = "Scan cancelled".to_string();
                    return Ok(Vec::new());
                }
                if gp.scope == ProgressScope::JarEntries || gp.total <= 1 {
                    gp.message = original_entry_name.to_string();
                } else {
                    gp.message = format!("{} (inside JAR)", original_entry_name);
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

        if archive_depth < self.options.max_nested_archive_depth
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
                Some(path) => get_archive_entry_name(&path.to_string_lossy()),
                None => get_archive_entry_name(&String::from_utf8_lossy(archive_file.name_raw())),
            };

            if archive_file.is_dir() || !self.should_scan(&relative_name) {
                continue;
            }

            let display_path = format!("{}!/{relative_name}", container_path);
            let file_size = archive_file.size() as usize;

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

    fn collect_resource_findings(
        &self,
        resource_name: &str,
        buffer: &[u8],
        compressed_size: Option<u64>,
    ) -> Vec<(FindingType, String)> {
        let mut findings = Vec::new();

        if self.has_extension(resource_name, SCRIPT_RESOURCE_EXTENSIONS) {
            findings.push((
                FindingType::ArchiveEntry,
                format!("Embedded script resource: {}", resource_name),
            ));
        }

        if self.has_extension(resource_name, EXECUTABLE_RESOURCE_EXTENSIONS) {
            findings.push((
                FindingType::ArchiveEntry,
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
                FindingType::ArchiveEntry
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
                    FindingType::ArchiveEntry,
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
                FindingType::ArchiveEntry,
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
