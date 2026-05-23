use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;
use std::net::IpAddr;

// ============================================================================
// File Type Extensions
// ============================================================================

pub const JAR_EXTS: &[&str] = &["jar"];
pub const CLASS_EXTS: &[&str] = &["class"];
pub const JAR_CLASS_EXTS: &[&str] = &["jar", "class"];

pub const NESTED_ARCHIVE_EXTENSIONS: &[&str] = &["jar", "zip", "jmod"];
pub const SCRIPT_RESOURCE_EXTENSIONS: &[&str] =
    &["bat", "cmd", "ps1", "vbs", "js", "hta", "wsf", "sh"];
pub const EXECUTABLE_RESOURCE_EXTENSIONS: &[&str] = &["exe", "scr", "com", "msi"];
pub const NATIVE_LIBRARY_EXTENSIONS: &[&str] = &["dll", "so", "dylib", "jnilib"];

// ============================================================================
// Suspicious Domains and Hosts
// ============================================================================

pub static SUSSY_DOMAINS: Lazy<HashSet<String>> = Lazy::new(|| {
    [
        "discord.com",
        "discordapp.com",
        "discord.gg",
        "cdn.discordapp.com",
        "pastebin.com",
        "hastebin.com",
        "ghostbin.co",
        "gofile.io",
        "transfer.sh",
        "webhook.site",
        "requestbin.net",
        "ngrok.io",
        "ngrok-free.app",
        "localtunnel.me",
        "serveo.net",
        "grabify.link",
        "iplogger.org",
        "ipify.org",
        "ifconfig.me",
        "bit.ly",
        "tinyurl.com",
    ]
    .iter()
    .map(|&s| s.to_lowercase())
    .collect()
});

// ============================================================================
// Dynamic Code Execution Markers
// ============================================================================

pub const DYNAMIC_LOADING_MARKERS: &[&str] =
    &["defineClass", "URLClassLoader", "Lookup.defineClass"];

pub const SCRIPT_ENGINE_MARKERS: &[&str] = &[
    "javax/script/ScriptEngineManager",
    "javax/script/ScriptEngine",
];

pub const JAVA_AGENT_MARKERS: &[&str] = &[
    "java/lang/instrument/Instrumentation",
    "Premain-Class",
    "Agent-Class",
    "Launcher-Agent-Class",
];

pub const ATTACH_API_MARKERS: &[&str] = &[
    "com/sun/tools/attach/VirtualMachine",
    "sun/tools/attach/HotSpotVirtualMachine",
];

pub const NATIVE_BRIDGE_MARKERS: &[&str] = &["com/sun/jna/", "sun/misc/Unsafe"];

pub const SAFE_NATIVE_CALLS: &[&str] = &[
    "com.sun.jna.Native::getLastError()I",
    "com.sun.jna.Native::toString",
    "com.sun.jna.Native::load",
    "com.sun.jna.Native::getNativeSize",
    "com.sun.jna.Platform",
    "com.sun.jna.Memory",
    "com.sun.jna.Structure",
    "com.sun.jna.Pointer",
    "com.sun.jna.NativeLong",
    "com.sun.jna.Callback",
    "com.sun.jna.Library",
    "com.sun.jna.TypeMapper",
    "com.sun.jna.Union",
    "com.sun.jna.ptr",
    "com.sun.jna.win32",
    "com.sun.jna.platform",
    "sun.misc.Unsafe",
    "com/sun/jna/Native",
    "sun/misc/Unsafe",
];

// ============================================================================
// Pattern Matching Regex Objects
// ============================================================================

pub static IP_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap()
});

pub static IPV6_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b").unwrap());

pub static URL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:https?://|ftp://|www\.)(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?::[0-9]{1,5})?(?:/[^\s]*)?"#).unwrap()
});

pub static MALICIOUS_PATTERN_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(powershell|cmd(?:\.exe)?|/bin/(?:ba)?sh|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|loadLibrary|System\.load|defineClass|VirtualMachine\.attach|keylogger|clipboard|appdata|\\.minecraft|webhook|readFile|writeFile|decrypt|encrypt)\b").unwrap()
});

pub static SECRET_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?x)
        (?i)\b(?:mfa\.[A-Za-z0-9_-]{20,}|[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})\b
        |
        \beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b
        |
        (?i)\b(?:AKIA[0-9A-Z]{16}|aws[_-]?(?:access[_-]?key|secret))\b
        |
        (?i)\b(?:gh[pousr]_[A-Za-z0-9_]{36,255})\b
        |
        (?i)\b(?:api[_-]?key|secret|token|password|passwd|pwd|api[_-]?secret)\s*[:=]\s*['"]?[A-Za-z0-9_./+=:-]{16,}
        |
        (?i)\b(?:webhook|slack|discord)[_-]?(?:url|token|hook)\s*[:=]\s*['"]?https?://[^'"\s]+
    "#).unwrap()
});

// ============================================================================
// Known Good Links and IPs (Whitelist)
// ============================================================================

pub static GOOD_LINKS: Lazy<HashSet<String>> = Lazy::new(|| {
    [
        "aka.ms",
        "apache.org",
        "ci.viaversion.com",
        "dominos.com",
        "dump.viaversion.com",
        "eclipse.org",
        "java.sun.org",
        "logging.apache.org",
        "login.live.com",
        "lwjgl.org",
        "minecraft.net",
        "minecraft.org",
        "minotar.net",
        "mojang.com",
        "netty.io",
        "optifine.net",
        "s.optifine.net",
        "snoop.minecraft.net",
        "tools.ietf.org",
        "viaversion.com",
        "www.openssl.org",
        "www.rfc-editor.org",
        "www.slf4j.org",
        "www.w3.org",
        "yaml.org",
        "openssl.org",
        "yggdrasil-auth-session-staging.mojang.zone",
        "slf4j.org",
        "xboxlive.com",
        "minecraftservices.com",
        "playfabapi.com",
        "microsoft.com",
        "live.com",
        "w3.org",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
});

pub static GOOD_IPS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "0.0.0.0",
        "::",
        "127.0.0.1",
        "::1",
        "255.255.255.255",
        "169.254.0.0/16",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.2.60",
        "8.8.8.8",
        "8.8.4.4",
        "1.1.1.1",
        "9.9.9.9",
        // just trash
        "1.3.6.1",
        "123.123.123.123",
    ]
    .into_iter()
    .collect()
});

// ============================================================================
// IP Address Utilities
// ============================================================================

fn parse_ip_range(range_str: &str) -> Option<(u32, u32)> {
    if !range_str.contains('/') {
        return None;
    }
    let parts: Vec<&str> = range_str.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let ip_parts: Vec<u32> = parts[0]
        .split('.')
        .map(|p| p.parse::<u32>().unwrap_or(0))
        .collect();
    if ip_parts.len() != 4 {
        return None;
    }
    let ip = (ip_parts[0] << 24) | (ip_parts[1] << 16) | (ip_parts[2] << 8) | ip_parts[3];
    let prefix = parts[1].parse::<u32>().ok()?;
    if prefix > 32 {
        return None;
    }
    let mask = if prefix == 0 {
        0
    } else {
        0xffffffff << (32 - prefix)
    };
    Some((ip & mask, mask))
}

fn ip_in_range(ip_str: &str, range_str: &str) -> bool {
    if let Ok(addr) = ip_str.parse::<IpAddr>() {
        if let IpAddr::V4(v4) = addr {
            let octets = v4.octets();
            let ip = (octets[0] as u32) << 24
                | (octets[1] as u32) << 16
                | (octets[2] as u32) << 8
                | octets[3] as u32;
            if let Some((range_ip, mask)) = parse_ip_range(range_str) {
                return (ip & mask) == range_ip;
            }
        }
    }
    false
}

pub fn is_known_good_ip(ip: &str) -> bool {
    if GOOD_IPS.contains(ip) {
        return true;
    }
    for good_ip in GOOD_IPS.iter() {
        if good_ip.contains('/') && ip_in_range(ip, good_ip) {
            return true;
        }
    }
    false
}

pub fn is_public_routable_ip(ip: &str) -> bool {
    let addr = match ip.parse::<IpAddr>() {
        Ok(a) => a,
        Err(_) => return false,
    };

    if is_known_good_ip(ip) {
        return false;
    }

    match addr {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || v4.is_unspecified())
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            let is_site_local = (segments[0] & 0xffc0) == 0xfec0;
            let is_documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;

            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || is_site_local
                || is_documentation
                || v6.is_multicast())
        }
    }
}
