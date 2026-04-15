# StegoGuard CLI Features

Advanced command-line interface documentation for StegoGuard v2.7.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Command Structure](#command-structure)
- [Core Commands](#core-commands)
  - [scan](#scan---full-analysis)
  - [quick](#quick---fast-triage)
  - [batch](#batch---multiple-images)
  - [watch](#watch---directory-monitoring)
  - [intel](#intel---threat-intelligence)
  - [dashboard](#dashboard---web-interface)
- [Global Options](#global-options)
- [Output Formats](#output-formats)
- [Advanced Usage](#advanced-usage)
- [Automation Examples](#automation-examples)

---

## 🎯 Overview

The StegoGuard CLI provides professional-grade command-line access to all detection, decryption, and analysis features with rich colored output and detailed progress tracking.

**Key Features:**
- Rich colored output with professional formatting
- Real-time progress tracking
- Multiple output formats (JSON, text, both)
- Batch processing with concurrent analysis
- Directory monitoring for continuous scanning
- Forensic report generation
- SHA256 verification and audit trails

---

## 📐 Command Structure

```
python3 stegoguard_pro.py <COMMAND> [TARGET] [OPTIONS]
```

**Basic Pattern:**
```bash
stegoguard <command> <target> --option value
```

---

## 🔍 Core Commands

### scan - Full Analysis

Full steganography analysis with 12+ detection modules and 18-probe decryption engine.

**Syntax:**
```bash
python3 stegoguard_pro.py scan <IMAGE> [OPTIONS]
```

**Options:**
```
-o, --output <DIR>          Output directory for reports (default: ./reports)
-f, --format <FORMAT>       Output format: json|text|both (default: text)
-v, --verbose               Increase verbosity
--no-decrypt                Disable decryption engine
--min-confidence <NUM>      Minimum confidence threshold (0-100)
--hash-verify               Enable SHA256 verification
```

**Examples:**
```bash
# Basic full scan
python3 stegoguard_pro.py scan image.jpg

# Custom output directory
python3 stegoguard_pro.py scan image.jpg --output ./case_files

# JSON output only
python3 stegoguard_pro.py scan image.jpg --format json

# Both formats
python3 stegoguard_pro.py scan image.jpg --format both

# Verbose mode with hash verification
python3 stegoguard_pro.py scan evidence.jpg --verbose --hash-verify

# Detection only (no decryption)
python3 stegoguard_pro.py scan image.jpg --no-decrypt
```

**Output Example:**
```
════════════════════════════════════════════════════════════════════════
StegoGuard Full Analysis - v2.7
════════════════════════════════════════════════════════════════════════
File: suspicious_image.jpg
SHA256: 4a9f2b3e7d8c9e2b1f5a8d3c6e9b2a5f...
Size: 2.4 MB | 1920×1080 | JPEG
Analysis Started: 2026-04-15 14:32:18 UTC

[Detection Phase - 12 Modules]
 ✓ LSB Scanner .......................... 94% entropy spike [HIGH]
 ✓ DCT Analyzer ........................ 89% coefficient anomalies [HIGH]
 ✓ GAN Detector ........................ 91% synthetic content [HIGH]
 ✓ Pattern Recognition ................. Steghide v0.5.1 signature [MEDIUM]
 ✓ Metadata Channel .................... 87% EXIF entropy [MEDIUM]
 ○ Palette Inspector ................... No anomalies [CLEAN]
 ○ Wavelet Transform ................... No anomalies [CLEAN]
 ○ QR-Code Checker ..................... No anomalies [CLEAN]
 ○ Spread-Spectrum ..................... No anomalies [CLEAN]
 ○ Statistical Tests ................... Passed [CLEAN]
 ○ PQC Lattice ......................... No anomalies [CLEAN]
 ○ Blockchain Scanner .................. No anomalies [CLEAN]

Detection Complete: 5/12 modules triggered (18.2s)

[Analysis Results]
 Threat Level: HIGH
 Confidence: 92%
 Suspected Technique: Hybrid DCT + LSB + AES wrapper
 APT Attribution: APT29 (Cozy Bear) - 89% confidence
 False Positive Risk: VERY LOW (2.1%)

[Hardened Decryption Engine - Auto-triggered]
 ✓ Probe 1: Metadata Keys .............. EXIF timestamp seed found
 ✓ Probe 2: Tool Exploits .............. Steghide default bypass success
 ✓ Probe 3: AI Predictor ............... Pattern identified (75% faster)
 ✓ Probe 4: Partial Decryption ......... 72% payload extracted
 ○ Probe 5-18: Remaining locked

Decryption Complete: PARTIAL (72% recovered, 16.4s)

[Extracted Payload]
"target acquired // exfil complete // phase 2 begins 0400Z"

[Report Generated]
Format: text
Location: ./reports/SG-A4F2B3E7-2026-04-15_14-32.txt
SHA256: 7c3e9b2a5f8d1c4e6b9a3d2f5c8e1b4a...

Total Analysis Time: 34.6 seconds
════════════════════════════════════════════════════════════════════════
```

---

### quick - Fast Triage

Quick detection-only scan (no decryption) for rapid triage.

**Syntax:**
```bash
python3 stegoguard_pro.py quick <IMAGE> [OPTIONS]
```

**Options:**
```
--format <FORMAT>       Output format: json|text (default: text)
--threshold <NUM>       Anomaly threshold (default: 3)
```

**Examples:**
```bash
# Quick scan
python3 stegoguard_pro.py quick image.jpg

# JSON output
python3 stegoguard_pro.py quick image.jpg --format json

# Custom threshold
python3 stegoguard_pro.py quick image.jpg --threshold 5
```

**Output Example:**
```
════════════════════════════════════════════════════════
StegoGuard Quick Scan - v2.7
════════════════════════════════════════════════════════
File: test_image.jpg
Size: 1.2 MB | 1024×768 | JPEG

Threat Level: SUSPICIOUS (Confidence: 76%)
Anomalies: 3/12 modules triggered
  ✓ LSB Scanner: 82% entropy spike
  ✓ DCT Analyzer: 74% coefficient anomalies
  ✓ Pattern Recognition: Possible steghide signature

Recommendation: Run full scan with decryption
Command: python3 stegoguard_pro.py scan test_image.jpg

Analysis Time: 4.2 seconds
════════════════════════════════════════════════════════
```

---

### batch - Multiple Images

Process multiple images in batch mode with concurrent analysis.

**Syntax:**
```bash
python3 stegoguard_pro.py batch <DIRECTORY> [OPTIONS]
```

**Options:**
```
-o, --output <DIR>          Output directory (default: ./reports)
-r, --recursive             Scan subdirectories
-f, --format <FORMAT>       Output format: json|text|both
--min-confidence <NUM>      Only report above threshold
--threads <NUM>             Concurrent threads (default: 4)
--continue-on-error         Continue if individual scans fail
```

**Examples:**
```bash
# Basic batch scan
python3 stegoguard_pro.py batch /images

# Recursive scan
python3 stegoguard_pro.py batch /images --recursive

# Custom threads and output
python3 stegoguard_pro.py batch /images --threads 8 --output ./batch_reports

# High-confidence only
python3 stegoguard_pro.py batch /images --min-confidence 80

# Full options
python3 stegoguard_pro.py batch /images \
    --recursive \
    --threads 8 \
    --format both \
    --min-confidence 70 \
    --output ./batch_results \
    --continue-on-error
```

**Output Example:**
```
════════════════════════════════════════════════════════════════════════
StegoGuard Batch Processing - v2.7
════════════════════════════════════════════════════════════════════════
Directory: /images
Mode: Recursive
Threads: 8
Output: ./reports/batch_2026-04-15_14-45/

[Scanning Images]
 [1/50] image001.jpg ..................... CLEAN (34%) ✓
 [2/50] image002.jpg ..................... SUSPICIOUS (76%) ⚠
 [3/50] image003.jpg ..................... HIGH THREAT (94%) ✗
 [4/50] image004.jpg ..................... CLEAN (28%) ✓
 ...
 [50/50] image050.jpg .................... CLEAN (31%) ✓

[Summary Statistics]
Total Images: 50
Processed: 50 (100%)
Failed: 0 (0%)

Threat Distribution:
  CLEAN: 42 images (84%)
  SUSPICIOUS: 6 images (12%)
  HIGH THREAT: 2 images (4%)

Average Confidence: 45.2%
Average Analysis Time: 18.6s per image
Total Processing Time: 15m 32s

[High-Threat Images]
1. image003.jpg - CRITICAL (94% confidence)
   APT Attribution: APT29 (Cozy Bear)
   Report: ./reports/batch_2026-04-15_14-45/image003_report.json

2. image017.jpg - HIGH (87% confidence)
   APT Attribution: Lazarus Group
   Report: ./reports/batch_2026-04-15_14-45/image017_report.json

[Reports Generated]
Summary: ./reports/batch_2026-04-15_14-45/summary.json
Individual Reports: 50 files
Total Size: 12.4 MB
════════════════════════════════════════════════════════════════════════
```

---

### watch - Directory Monitoring

Continuously monitor directory for new images and auto-analyze.

**Syntax:**
```bash
python3 stegoguard_pro.py watch <DIRECTORY> [OPTIONS]
```

**Options:**
```
-o, --output <DIR>          Output directory
--interval <SECONDS>        Check interval (default: 5)
--recursive                 Monitor subdirectories
--min-confidence <NUM>      Alert threshold
```

**Examples:**
```bash
# Watch directory
python3 stegoguard_pro.py watch /incoming

# Custom interval
python3 stegoguard_pro.py watch /incoming --interval 10

# Recursive with alerts
python3 stegoguard_pro.py watch /incoming \
    --recursive \
    --min-confidence 80 \
    --output ./alerts
```

**Output Example:**
```
════════════════════════════════════════════════════════
StegoGuard Directory Monitoring - v2.7
════════════════════════════════════════════════════════
Directory: /incoming
Interval: 5 seconds
Mode: Recursive
Alert Threshold: 80%

[Monitoring Started: 2026-04-15 14:50:00]
Press Ctrl+C to stop

[14:50:05] Scanning... 0 new files
[14:50:10] Scanning... 0 new files
[14:50:15] NEW FILE DETECTED: /incoming/suspicious.jpg
           Analyzing... CRITICAL THREAT (94%)
           ⚠ ALERT: High-confidence detection!
           Report: ./alerts/suspicious_20260415_145015.json
[14:50:20] Scanning... 0 new files
...
```

---

### intel - Threat Intelligence

Enhanced threat intelligence analysis with APT attribution.

**Syntax:**
```bash
python3 stegoguard_pro.py intel <IMAGE> [OPTIONS]
```

**Options:**
```
--correlation               Enable correlation with threat feeds
--verbose                   Detailed APT analysis
```

**Examples:**
```bash
# Threat intelligence analysis
python3 stegoguard_pro.py intel suspicious.jpg

# With correlation
python3 stegoguard_pro.py intel suspicious.jpg --correlation --verbose
```

**Output Example:**
```
════════════════════════════════════════════════════════
StegoGuard Threat Intelligence - v2.7
════════════════════════════════════════════════════════
File: suspicious.jpg

[Technique Analysis]
Detected: Hybrid DCT + LSB + AES wrapper
Sophistication: HIGH
First Seen: 2024-Q3
Prevalence: 12% of APT steganography

[APT Attribution]
Primary: APT29 (Cozy Bear) - 89% confidence
  Origin: Russian SVR
  Active Since: 2008
  Known Techniques:
    - Hybrid DCT + LSB (primary signature)
    - GAN-generated covers
    - Multi-layer encryption
  Recent Activity: High (2026-Q1)

Secondary Matches:
  - APT28 (Fancy Bear) - 34% confidence
  - Turla - 21% confidence

[Indicators of Compromise]
Payload Signature: 7c3e9b2a...
Encryption Pattern: AES-256 + Lattice suspected
Metadata Anomalies: EXIF timestamp manipulation
Tool Signatures: Steghide v0.5.1 + custom wrapper

[Recommendations]
1. Escalate to incident response team
2. Analyze related images from same source
3. Correlate with network traffic logs
4. Check for lateral movement indicators
5. Review system logs for anomalous activity
════════════════════════════════════════════════════════
```

---

### dashboard - Web Interface

Launch web dashboard on localhost.

**Syntax:**
```bash
python3 stegoguard_pro.py dashboard [OPTIONS]
```

**Options:**
```
--host <IP>                 Bind address (default: 127.0.0.1)
--port <PORT>               Port number (default: 5000)
--debug                     Enable debug mode (development only)
```

**Examples:**
```bash
# Default (localhost:5000)
python3 stegoguard_pro.py dashboard

# Custom port
python3 stegoguard_pro.py dashboard --port 8080

# Bind to all interfaces (use with caution)
python3 stegoguard_pro.py dashboard --host 0.0.0.0 --port 5000

# Debug mode
python3 stegoguard_pro.py dashboard --debug
```

---

## ⚙️ Global Options

Available for all commands:

```
--help, -h                  Show help message
--version                   Show version number
--config <FILE>             Custom configuration file
--log-level <LEVEL>         Logging level: DEBUG|INFO|WARNING|ERROR
--no-color                  Disable colored output
--quiet                     Suppress progress output
```

**Examples:**
```bash
# Show help
python3 stegoguard_pro.py --help
python3 stegoguard_pro.py scan --help

# Check version
python3 stegoguard_pro.py --version

# Custom logging
python3 stegoguard_pro.py scan image.jpg --log-level DEBUG

# No colors (for piping)
python3 stegoguard_pro.py scan image.jpg --no-color > result.txt
```

---

## 📄 Output Formats

### JSON Format

```json
{
  "report_id": "SG-A4F2B3E7",
  "timestamp": "2026-04-15T14:32:18Z",
  "version": "2.7",
  "file": {
    "name": "suspicious.jpg",
    "path": "/path/to/suspicious.jpg",
    "size": 2457600,
    "sha256": "4a9f2b3e7d8c9e2b1f5a8d3c6e9b2a5f...",
    "format": "JPEG",
    "dimensions": "1920x1080"
  },
  "detection": {
    "threat_level": "HIGH",
    "confidence": 92,
    "anomalies_detected": 5,
    "modules_triggered": ["LSB Scanner", "DCT Analyzer", "GAN Detector"],
    "analysis_time": 18.2
  },
  "decryption": {
    "status": "PARTIAL",
    "success_rate": 72,
    "payload": "target acquired // exfil complete...",
    "probes_used": ["Metadata Keys", "Tool Exploits", "AI Predictor"],
    "time": 16.4
  },
  "apt_attribution": {
    "group": "APT29 (Cozy Bear)",
    "confidence": 89,
    "techniques_matched": ["Hybrid DCT+LSB", "GAN Cover"]
  }
}
```

### Text Format

Professional human-readable report (see examples above).

---

## 🔧 Advanced Usage

### Pipeline Mode

Chain multiple operations:

```bash
# Scan → Filter → Export
python3 stegoguard_pro.py batch /images --format json | \
    jq '.[] | select(.detection.confidence > 80)' | \
    python3 generate_report.py
```

### Integration with Other Tools

```bash
# Find suspicious files, then analyze
find /data -name "*.jpg" -type f | while read img; do
    python3 stegoguard_pro.py quick "$img" --format json >> results.jsonl
done

# Analyze and extract high-threat images
python3 stegoguard_pro.py batch /images --format json | \
    jq -r 'select(.detection.threat_level == "HIGH") | .file.path' | \
    xargs -I {} cp {} /high_threat/
```

### Automation with Cron

```bash
# Add to crontab
crontab -e

# Scan incoming directory every hour
0 * * * * /usr/bin/python3 /path/to/stegoguard_pro.py batch /incoming --output /reports/hourly

# Daily full scan
0 2 * * * /usr/bin/python3 /path/to/stegoguard_pro.py batch /archive --recursive --output /reports/daily
```

---

## 🤖 Automation Examples

### Incident Response Workflow

```bash
#!/bin/bash
# ir_workflow.sh

CASE_ID="IR-2026-042"
EVIDENCE_DIR="/evidence/$CASE_ID"
REPORT_DIR="/reports/$CASE_ID"

# 1. Quick triage
echo "Starting triage..."
python3 stegoguard_pro.py batch "$EVIDENCE_DIR" \
    --format json \
    --output "$REPORT_DIR/triage" | \
    jq -r 'select(.detection.confidence > 70) | .file.path' > suspicious_files.txt

# 2. Full analysis of suspicious files
echo "Analyzing suspicious files..."
while read -r file; do
    python3 stegoguard_pro.py scan "$file" \
        --format both \
        --output "$REPORT_DIR/detailed" \
        --hash-verify \
        --verbose
done < suspicious_files.txt

# 3. Generate summary report
echo "Generating summary..."
python3 generate_summary.py "$REPORT_DIR" > "$REPORT_DIR/summary.txt"

echo "Workflow complete. Reports in: $REPORT_DIR"
```

### SOC Integration

```bash
#!/bin/bash
# soc_monitor.sh

WATCH_DIR="/soc/incoming"
ALERT_THRESHOLD=80

# Monitor and alert
python3 stegoguard_pro.py watch "$WATCH_DIR" \
    --min-confidence $ALERT_THRESHOLD \
    --output /soc/alerts \
    --recursive | while read -r line; do

    if [[ "$line" == *"ALERT"* ]]; then
        # Send alert to SIEM
        curl -X POST https://siem.local/api/alert \
            -H "Content-Type: application/json" \
            -d "{\"message\": \"$line\", \"source\": \"StegoGuard\"}"
    fi
done
```

---

## 📊 Performance Tuning

### Optimize Batch Processing

```bash
# Increase threads for faster processing
python3 stegoguard_pro.py batch /images --threads 16

# Quick scan only for large batches
python3 stegoguard_pro.py batch /images --quick-only

# Limit analysis to high-confidence only
python3 stegoguard_pro.py batch /images --min-confidence 90
```

---

## 📞 Help & Support

```bash
# General help
python3 stegoguard_pro.py --help

# Command-specific help
python3 stegoguard_pro.py scan --help
python3 stegoguard_pro.py batch --help

# List supported formats
python3 stegoguard_pro.py --formats

# Show configuration
python3 stegoguard_pro.py --show-config
```

---

**For complete documentation, see [README.md](README.md)**
