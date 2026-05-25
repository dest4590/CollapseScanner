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

pub static SUSPICIOUS_DOMAINS: Lazy<HashSet<String>> = Lazy::new(|| {
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

pub const SAFE_NATIVE_CALLS: &[&str] = &["sun.misc.Unsafe"];

pub const SAFE_NATIVE_PACKAGES: &[&str] =
    &["com.sun.jna", "com.sun.jna.platform", "com.sun.jna.Native"];

// ============================================================================
// Pattern Matching Regex Objects
// ============================================================================

pub static IP_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap()
});

pub static IPV6_REGEX: Lazy<Regex> = Lazy::new(|| {
    // IPv6 pattern: requires at least 3 hex groups (more strict than before)
    Regex::new(r"(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b").unwrap()
});

pub static URL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:https?://|ftp://|www\.)(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?::[0-9]{1,5})?(?:/[^\s]*)?"#).unwrap()
});

pub static MALICIOUS_PATTERN_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(powershell|cmd(?:\.exe)?|/bin/(?:ba)?sh|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|loadLibrary|System\.load|defineClass|VirtualMachine\.attach|keylogger|clipboard|appdata|\\.minecraft|webhook|readFile|writeFile|decrypt|encrypt)\b").unwrap()
});

pub static SECRET_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
        # JWT tokens (most reliable format: three parts with dots)
        \beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b
        |
        # AWS Access Keys (strict format: AKIA prefix + 16 hex chars)
        \bAKIA[0-9A-Z]{16}\b
        |
        # GitHub Personal Access Tokens (prefix patterns)
        \bgh[pousr]_[A-Za-z0-9_]{36,255}\b
        |
        # MFA tokens (strict format with dot separators)
        \bmfa\.[A-Za-z0-9_-]{20,}\b
        |
        # Discord bot tokens (strict format)
        \b[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b
        |
        # API/Database URLs with credentials (strict format)
        (?i)(?:mongodb|mysql|postgresql|jdbc)://[^:]+:[^@]+@[^\s]{5,}
        |
        # AWS-style secret keys (only in key=value context with >= 40 chars)
        (?i)aws[_-]?secret[_-]?(?:access[_-])?key\s*[:=]\s*[A-Za-z0-9/+]{40,}
        |
        # Discord webhook URLs (strict format)
        (?i)https?://(?:discord|discordapp)\.com/api/webhooks/[0-9]{18,}/[A-Za-z0-9_-]+
    "#,
    )
    .unwrap()
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
        "shader-tutorial.dev",
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

fn parse_cidr(cidr: &str) -> Option<(u32, u32)> {
    let mut parts = cidr.split('/');
    let ip_str = parts.next()?;
    let prefix_len = parts.next()?.parse::<u32>().ok()?;

    if prefix_len > 32 {
        return None;
    }

    let addr = match ip_str.parse::<std::net::Ipv4Addr>() {
        Ok(a) => u32::from(a),
        Err(_) => return None,
    };

    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };

    Some((addr & mask, mask))
}

fn is_ip_in_cidr(ip_str: &str, cidr: &str) -> bool {
    let addr = match ip_str.parse::<std::net::Ipv4Addr>() {
        Ok(a) => u32::from(a),
        Err(_) => return false,
    };

    if let Some((network, mask)) = parse_cidr(cidr) {
        return (addr & mask) == network;
    }

    false
}

pub fn is_known_good_ip(ip: &str) -> bool {
    if GOOD_IPS.contains(ip) {
        return true;
    }

    // Check CIDR ranges in the whitelist
    GOOD_IPS
        .iter()
        .filter(|&&entry| entry.contains('/'))
        .any(|&cidr| is_ip_in_cidr(ip, cidr))
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
            // Check for site-local and documentation which might not be covered by standard is_ methods
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
