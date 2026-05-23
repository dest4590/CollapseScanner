pub mod system;

pub use system::SystemConfig;

use once_cell::sync::Lazy;

pub static SYSTEM_CONFIG: Lazy<SystemConfig> = Lazy::new(SystemConfig::new);
