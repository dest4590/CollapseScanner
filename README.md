# CollapseScanner

CollapseScanner is a fast, static scanner for Java bytecode. Point it at a `.jar`, a `.class` file, or a directory, and it will analyze class structure, bytecode patterns, and archive contents to give you a risk-focused report.

It does not run the sample. It does not decompile everything into source. It reads class bytecode, extracts method calls and string constants, then gives you a short report highlighting what matters most.

## What it looks for

CollapseScanner detects:

- **Risky APIs**: Process execution (`Runtime.exec`, `ProcessBuilder`), reflection, dynamic class loading, JNI, `Unsafe`, Java agents, attach APIs
- **Network infrastructure**: IPv4 and IPv6 addresses, URLs, suspicious domains, Discord webhooks, C2 indicators
- **Secrets**: Token-like strings, hardcoded credentials, API keys, database URLs
- **Obfuscation**: Unicode-based name tricks, tampered class files, suspicious compressions
- **Native payloads**: Embedded binaries, native libraries (`.dll`, `.so`), script engines
- **Archive anomalies**: Nested archives, suspicious compression ratios, malformed entries

The goal is triage. If a file is reaching out to strange infrastructure, using dangerous APIs, or looks obfuscated, CollapseScanner should flag it quickly.

## Install

You need Rust 1.70+.

```bash
git clone https://github.com/dest4590/CollapseScanner.git
cd CollapseScanner
cargo build --release
```

The binary will be at `target/release/collapsescanner`.

## Usage

```bash
# Scan a JAR, class file, or directory
collapsescanner <path>

# Scan only network indicators
collapsescanner <path> --mode network

# Scan only malicious APIs and secrets
collapsescanner <path> --mode malicious

# Scan only obfuscation signals
collapsescanner <path> --mode obfuscation

# Write JSON output to a file
collapsescanner <path> --json --output report.json

# Scan only matching entries
collapsescanner mods/ --find "*.class" --exclude "META-INF/*"

# Use a fixed worker thread count
collapsescanner sample.jar --threads 8

# Load repeatable settings from a TOML config
collapsescanner sample.jar --config scanner.toml

# Suppress false positives with a keyword list
collapsescanner <path> --ignore_keywords keywords.txt
```

Example `scanner.toml`:

```toml
mode = "all"
threads = 0
exclude = ["META-INF/*", "**/test/**"]
find = ["*.jar", "*.class"]
ignore_keywords = "keywords.txt"
```

## Output

The default terminal report includes:

- **Risk score** (0-10)
- **Summary**: total findings and affected files
- **Severity distribution**: count of Critical, High, Medium, Low items
- **Files to inspect**: top targets by danger score
- **Detailed findings**: per-file results grouped by finding type

Example:

```text
Risk: MODERATE RISK (6/10)
Findings: 18 across 7 file(s)
Scanned: 240 file(s) in 1.42s (169.0 files/sec)

SEVERITY DISTRIBUTION
  2 CRITICAL │  4 HIGH │  8 MEDIUM │  4 LOW

ALL FINDINGS
  com/example/Loader.class · HIGH · 4 findings
    🔴 SuspiciousApi: Process execution API usage: Runtime.exec()
    🟠 IpAddress: 192.168.1.100
    🟡 CredentialSecret: Potential embedded token
```

Use `--json` to get stable machine-readable output. Use `--output` with or without `--json` to save results to disk.

The tool shows a live progress bar during interactive terminal scans, disabled for JSON output.

## Detection Modes

**all** (default)  
Runs every detector. Use when you have time and want complete coverage.

**network**  
Focuses on infrastructure: URLs, IPs, domains, webhooks, C2 indicators.

**malicious**  
Focuses on dangerous code: risky APIs, native calls, reflection, secrets, keywords.

**obfuscation**  
Focuses on anti-analysis tricks: Unicode tricks, class file tampering, high-entropy blobs.

## Architecture

The codebase is organized into focused modules:

- **rules.rs**: Consolidated detection patterns, domains, API markers, regex definitions
- **parsers/**: Java class bytecode parser (constant pool, methods, strings)
- **scanner/**: Main scanning orchestration (file discovery, JAR extraction, class analysis)
- **cache/**: Safe string caching to optimize repeated scanning
- **config/**: System resource detection (memory-based cache tuning)
- **output/**: Terminal and JSON formatting
- **types.rs**: Shared data structures and enums
- **errors.rs**: Error handling
- **utils.rs**: Utility functions

## Notes

CollapseScanner is static analysis. It will not see behavior that only appears at runtime, and it will not prove that a file is malicious. Treat the score as a triage hint, not a verdict.

It is usually a good first pass before opening a decompiler or running a sample in a sandbox.

CLI flags override values from `--config`, so the config file works as a baseline and one-off options can narrow or expand a scan.

## Performance

CollapseScanner uses multi-threaded scanning via Rayon. By default it uses all available cores. Typical performance:

- Small JAR (< 1 MB): 50-200 ms
- Medium JAR (1-10 MB): 200 ms - 1 s
- Large JAR (10-100 MB): 1-5 s
- Entire directory: scales linearly with core count
