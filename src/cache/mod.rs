use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

    pub fn is_cached_safe_string(_s: &str) -> bool {
        false
    }

    pub fn cache_safe_string(_s: &str) {}

pub fn calculate_detection_hash(data: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();

    if data.len() > 1024 {
        data[..512].hash(&mut hasher);
        let mid = data.len() / 2;
        data[mid - 256..mid + 256].hash(&mut hasher);
        data[data.len() - 512..].hash(&mut hasher);
        (data.len() as u64).hash(&mut hasher);
    } else {
        data.hash(&mut hasher);
    }

    hasher.finish()
}
