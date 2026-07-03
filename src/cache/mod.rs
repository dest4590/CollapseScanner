use std::collections::{hash_map::DefaultHasher, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, LazyLock, RwLock};

pub static SAFE_STRING_CACHE: LazyLock<Arc<RwLock<HashSet<String>>>> =
    LazyLock::new(|| Arc::new(RwLock::new(HashSet::new())));

pub fn is_cached_safe_string(s: &str) -> bool {
    if let Ok(cache) = SAFE_STRING_CACHE.read() {
        cache.contains(s)
    } else {
        false
    }
}

pub fn cache_safe_string(s: &str) {
    if let Ok(mut cache) = SAFE_STRING_CACHE.write() {
        cache.insert(s.to_string());
    }
}

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
