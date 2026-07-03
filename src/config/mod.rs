pub mod system;

pub use system::SystemConfig;

use std::sync::LazyLock;

pub static SYSTEM_CONFIG: LazyLock<SystemConfig> = LazyLock::new(SystemConfig::new);
