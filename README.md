# CollapseScanner

Static security triage for Java JARs, class files, and nested archives.

Inspects Java bytecode without execution. Detects risky APIs, hardcoded infrastructure, secrets, obfuscation, native payloads, and archive anomalies.

## Usage

```sh
collapsescanner [OPTIONS] [PATH]
```

### Arguments

| Argument | Description                           |
| -------- | ------------------------------------- |
| `PATH`   | JAR, class file, or directory to scan |

### Options

| Flag                       | Description                                                   | Default |
| -------------------------- | ------------------------------------------------------------- | ------- |
| `--config <FILE>`          | Load settings from TOML config file                           | -       |
| `-v`, `--verbose`          | Print parser and scanning details                             | false   |
| `--json`                   | Output machine-readable JSON                                  | false   |
| `--output <FILE>`          | Write JSON report to path                                     | -       |
| `--mode <MODE>`            | Detection group: `all`, `network`, `malicious`, `obfuscation` | `all`   |
| `--ignore-keywords <FILE>` | File with suspicious keywords to suppress                     | -       |
| `--exclude <PATTERN>`      | Skip paths matching wildcard (repeatable)                     | -       |
| `--find <PATTERN>`         | Only scan paths matching wildcard (repeatable)                | -       |
| `--threads <N>`            | Worker threads (0 = Rayon default)                            | 0       |
| `--max-depth <N>`          | Max nested archive depth                                      | 4       |
| `--max-strings <N>`        | Max strings to scan per class                                 | 2000    |

### Config File (TOML)

```toml
path = "mods/"
mode = "all"
verbose = false
json = false
output = "report.json"
exclude = ["*/META-INF/**"]
find = ["*.jar"]
threads = 4
max_depth = 4
max_strings = 5000
```

### Modes

- **all** - Full scan: network, malicious, secrets, encoded payloads, obfuscation, archive analysis
- **network** - IP addresses, URLs, suspicious domains, Discord webhooks
- **malicious** - Suspicious keywords, secrets/tokens, encoded payloads, Java API abuse
- **obfuscation** - Unicode-based name obfuscation only

### Examples

```sh
# Scan a single JAR file with default rules
collapsescanner sample.jar

# Scan a directory targeting network indicators only
collapsescanner mods/ --mode network

# Load configuration settings from a custom TOML config file
collapsescanner sample.jar --config scanner.toml

# Scan a directory and write output to a JSON report file
collapsescanner mods/ --json --output report.json

# Scan with custom nested depth and string limits
collapsescanner --max-depth 5 --max-strings 5000 mods/
```

## Detection Categories

- **IPv4/IPv6 Address** - Hardcoded public-routable IPs (excluding loopbacks and whitelisted ranges).
- **URL** - External connection paths parsed from class files.
- **Suspicious URL** - URLs pointing to domains commonly used for staging payloads or exfiltration (e.g. `api.telegram.org`, `raw.githubusercontent.com`).
- **Discord Webhook** - Discord API webhooks used for channel log exfiltration.
- **Suspicious Keyword** - High-confidence malicious strings like `powershell`, `keylogger`, or `.minecraft`.
- **Java API** - Risky API markers (e.g., `ProcessImpl::start`, `ScriptEngineManager`, JNI, class loading, reflection).
- **Credential/Secret** - Embedded keys, passwords, database URLs, AWS credentials (`AKIA`/`ASIA`), and GitHub PATs.
- **Encoded Payload** - Entropy analysis targeting hidden Base64 or hex blobs.
- **Tampered Class** - Bytecode tampering tricks (e.g., custom `0xDEAD` magic bytes).
- **Native Library** - Embedded executables (`.dll`, `.so`, `.dylib`) within the JAR structure.
- **Archive Entry** - Risky embedded scripts, PE/ELF executables, or manifest permission requests.
- **Unicode Obfuscation** - Non-ASCII character mappings used to obfuscate class, field, or method names.

## Build

```sh
cargo build --release
```
