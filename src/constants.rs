use once_cell::sync::Lazy;
use std::collections::HashSet;

pub const JAR_EXTS: &[&str] = &["jar"];
pub const CLASS_EXTS: &[&str] = &["class"];
pub const JAR_CLASS_EXTS: &[&str] = &["jar", "class"];

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
];

pub const NESTED_ARCHIVE_EXTENSIONS: &[&str] = &["jar", "zip", "jmod"];
pub const SCRIPT_RESOURCE_EXTENSIONS: &[&str] =
    &["bat", "cmd", "ps1", "vbs", "js", "hta", "wsf", "sh"];
pub const EXECUTABLE_RESOURCE_EXTENSIONS: &[&str] = &["exe", "scr", "com", "msi"];
pub const NATIVE_LIBRARY_EXTENSIONS: &[&str] = &["dll", "so", "dylib", "jnilib"];
