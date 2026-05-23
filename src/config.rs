use once_cell::sync::Lazy;
use std::env;

const DEFAULT_RESULT_CACHE_SIZE: usize = 4096;
const DEFAULT_BUFFER_SIZE: usize = 512 * 1024;
const DEFAULT_SAFE_STRING_CACHE_CAPACITY: usize = 4000;

const LOW_MEMORY_THRESHOLD: u64 = 4 * 1024 * 1024 * 1024;
const MEDIUM_MEMORY_THRESHOLD: u64 = 8 * 1024 * 1024 * 1024;
const HIGH_MEMORY_THRESHOLD: u64 = 16 * 1024 * 1024 * 1024;

pub struct SystemConfig {
    pub result_cache_size: usize,
    pub buffer_size: usize,
    pub safe_string_cache_capacity: usize,
    pub max_file_size: usize,
}

fn parse_env_usize(key: &str) -> Option<usize> {
    env::var(key).ok()?.parse::<usize>().ok()
}

fn get_available_memory() -> u64 {
    env::var("COLLAPSE_AVAILABLE_MEMORY_MB")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|mb| mb * 1024 * 1024)
        .unwrap_or(8 * 1024 * 1024 * 1024)
}

impl SystemConfig {
    pub fn new() -> Self {
        let available_memory = get_available_memory();

        let result_cache_size =
            parse_env_usize("COLLAPSE_RESULT_CACHE_SIZE").unwrap_or(match available_memory {
                m if m < LOW_MEMORY_THRESHOLD => DEFAULT_RESULT_CACHE_SIZE,
                m if m < MEDIUM_MEMORY_THRESHOLD => 16_384,
                m if m < HIGH_MEMORY_THRESHOLD => 65_536,
                _ => 131_072,
            });

        let buffer_size = parse_env_usize("COLLAPSE_BUFFER_SIZE_MB")
            .map(|mb| mb * 1024 * 1024)
            .unwrap_or_else(|| match available_memory {
                m if m < LOW_MEMORY_THRESHOLD => DEFAULT_BUFFER_SIZE,
                m if m < MEDIUM_MEMORY_THRESHOLD => 2 * 1024 * 1024,
                m if m < HIGH_MEMORY_THRESHOLD => 8 * 1024 * 1024,
                _ => 16 * 1024 * 1024,
            });

        let safe_string_cache_capacity = parse_env_usize("COLLAPSE_STRING_CACHE_CAPACITY")
            .unwrap_or(match available_memory {
                m if m < LOW_MEMORY_THRESHOLD => DEFAULT_SAFE_STRING_CACHE_CAPACITY,
                m if m < MEDIUM_MEMORY_THRESHOLD => 20_000,
                m if m < HIGH_MEMORY_THRESHOLD => 80_000,
                _ => 2_000_000,
            });

        let max_file_size = match available_memory {
            m if m < LOW_MEMORY_THRESHOLD => 100,
            m if m < MEDIUM_MEMORY_THRESHOLD => 250,
            m if m < HIGH_MEMORY_THRESHOLD => 500,
            _ => 1000,
        };

        SystemConfig {
            result_cache_size,
            buffer_size,
            safe_string_cache_capacity,
            max_file_size,
        }
    }

    pub fn log_config(&self) {
        println!("[*] System Configuration:");
        println!(
            "   [c] Result Cache Size: {} entries",
            self.result_cache_size
        );
        println!(
            "   [b] Buffer Size: {} MB",
            self.buffer_size / (1024 * 1024)
        );
        println!(
            "   [s] String Cache Capacity: {} entries",
            self.safe_string_cache_capacity
        );
        println!("   [f] Max File Size: {} MB", self.max_file_size);

        println!("   [i] You can override these settings with environment variables:");
        println!("       COLLAPSE_RESULT_CACHE_SIZE (usize)");
        println!("       COLLAPSE_BUFFER_SIZE_MB (usize)");
        println!("       COLLAPSE_STRING_CACHE_CAPACITY (usize)");
        println!("       COLLAPSE_AVAILABLE_MEMORY_MB (u64)");
    }
}

pub static SYSTEM_CONFIG: Lazy<SystemConfig> = Lazy::new(SystemConfig::new);
