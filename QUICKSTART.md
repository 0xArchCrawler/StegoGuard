# StegoGuard Quick Start Guide

Get up and running with StegoGuard in **5 minutes**.

---

## ⚡ Installation (2 minutes)

```bash
# Clone the repository
git clone https://github.com/YOUR-USERNAME/StegoGuard.git
cd StegoGuard/StegoGuard_Pro

# Option 1: Use the self-contained launcher (easiest)
./start.sh
# Dependencies auto-install, then select your mode

# Option 2: Manual installation
pip3 install -r requirements.txt
python3 stegoguard_pro.py --help
```

**System Requirements:**
- Python 3.8+ (3.10+ recommended)
- 4GB RAM minimum
- Linux, macOS, or Windows

---

## 🚀 Your First Scan (1 minute)

### Option A: Quick Scan (Fastest)

```bash
# Scan a single image (no decryption)
python3 stegoguard_pro.py quick /path/to/image.jpg
```

**Output:**
```
════════════════════════════════════════════════════════
StegoGuard Quick Scan - v2.7
════════════════════════════════════════════════════════
File: suspicious_image.jpg
Size: 2.4 MB | 1920×1080 | JPEG

Threat Level: HIGH (Confidence: 92%)
Anomalies: 5/12 modules triggered
  ✓ LSB Scanner: 94% entropy spike
  ✓ DCT Analyzer: 89% coefficient anomalies
  ✓ GAN Detector: 91% synthetic content

Recommendation: Run full scan with decryption
════════════════════════════════════════════════════════
```

### Option B: Full Scan (with Decryption)

```bash
# Full analysis with 18-probe decryption engine
python3 stegoguard_pro.py scan /path/to/image.jpg
```

**Output:**
```
════════════════════════════════════════════════════════
StegoGuard Full Analysis - v2.7
════════════════════════════════════════════════════════
[Detection Phase]
Modules: 12/12 completed (18.2s)
Anomalies: 5 detected
Threat Level: HIGH (92% confidence)

[Decryption Phase - Auto-triggered]
Probes: 18/18 executed (16.4s)
Success: PARTIAL (72% payload recovered)

Extracted: "target acquired // exfil complete..."

[Report Generated]
Location: ./reports/SG-A4F2B3E7-2026-04-15_14-32.json
════════════════════════════════════════════════════════
```

---

## 🌐 Web Dashboard (1 minute)

### Launch Dashboard

```bash
# Start web interface
./start.sh
# Select option: 2) Web Dashboard

# Or directly:
python3 stegoguard_pro.py dashboard
```

**Access at:** http://localhost:5000

### Using the Dashboard

1. **Upload Image:**
   - Drag & drop image (up to 100MB)
   - Or click "Select File"
   - Supports: JPEG, PNG, GIF, WebP, BMP, TIFF

2. **Watch Real-Time Analysis:**
   - Loading (10%) → Analyzing (30%) → Processing (80%) → Complete (100%)
   - Live progress updates via WebSocket

3. **View Results:**
   - Threat level and confidence score
   - Module-by-module detection results
   - Decryption results (if triggered)
   - APT attribution (if matched)

4. **Export Report:**
   - Click "Export PDF" or "Export JSON"
   - Professional forensic report generated

### Switch Themes

Click **Settings** → **Theme** → Choose:
1. Dark Ops (Default) - SOC/SIEM style
2. Cyber Blue - IBM QRadar inspired
3. Threat Red - Incident response
4. Stealth Green - Military/tactical
5. Quantum Purple - Advanced threat analysis

---

## 📂 Batch Processing (1 minute)

### Scan Multiple Images

```bash
# Scan entire directory
python3 stegoguard_pro.py batch /path/to/images --output ./reports

# Recursive scan (includes subdirectories)
python3 stegoguard_pro.py batch /path/to/images --recursive

# With specific options
python3 stegoguard_pro.py batch /path/to/images \
    --recursive \
    --format json \
    --output ./batch_reports
```

**Output:**
```
Batch Processing: /images
════════════════════════════════════════════════════════
[1/50] image001.jpg ... CLEAN (34% confidence)
[2/50] image002.jpg ... SUSPICIOUS (76% confidence)
[3/50] image003.jpg ... HIGH THREAT (94% confidence)
...
[50/50] image050.jpg ... CLEAN (28% confidence)

Summary:
  Total: 50 images
  Clean: 42 (84%)
  Suspicious: 6 (12%)
  High Threat: 2 (4%)

Reports: ./reports/batch_2026-04-15_14-45/
════════════════════════════════════════════════════════
```

---

## 🎯 Common Use Cases

### 1. Incident Response

```bash
# Quick triage of suspicious image
python3 stegoguard_pro.py quick evidence.jpg

# If suspicious, run full analysis
python3 stegoguard_pro.py scan evidence.jpg --output ./case_IR-2026-042

# Generate forensic report
python3 stegoguard_pro.py scan evidence.jpg --format both
```

### 2. Threat Hunting

```bash
# Scan entire email attachment directory
python3 stegoguard_pro.py batch /email_attachments --recursive

# Filter by threat level
python3 stegoguard_pro.py batch /attachments --min-confidence 70
```

### 3. CTF Competition

```bash
# Quick analysis
python3 stegoguard_pro.py scan ctf_challenge.png

# Check decryption results
cat reports/SG-*.json | jq '.decryption_results'
```

### 4. Digital Forensics

```bash
# Full forensic analysis with chain of custody
python3 stegoguard_pro.py scan evidence.jpg \
    --output ./case_files \
    --format json \
    --hash-verify
```

---

## 📊 Understanding Results

### Threat Levels

| Level | Confidence | Meaning |
|-------|-----------|---------|
| **CLEAN** | 0-30% | No steganography detected |
| **SUSPICIOUS** | 31-69% | Possible steganography, low confidence |
| **HIGH** | 70-89% | Likely steganography, high confidence |
| **CRITICAL** | 90-100% | Confirmed steganography, very high confidence |

### Detection Modules

**12 Core Modules:**
- LSB Bit-Level Scanner
- DCT Frequency Analyzer
- Palette Index Inspector
- Wavelet Transform Probe
- GAN/Deepfake Detector
- QR-Code Pixel Shift Checker
- Spread-Spectrum Noise Map
- Metadata Channel Detector
- Statistical Anomaly Detector
- PQC Lattice Detector
- Blockchain Address Scanner
- AI-Stego Pattern Recognizer

**Interpretation:**
- 1-2 modules: Likely false positive
- 3-4 modules: Possible steganography
- 5+ modules: Confirmed steganography

### Decryption Results

**Success Levels:**
- **Full (100%):** Complete payload extracted
- **Partial (40-99%):** Partial payload recovered
- **Failed (0-39%):** Unable to decrypt

---

## 🔍 Advanced Options

### CLI Options

```bash
# Scan with custom output format
python3 stegoguard_pro.py scan image.jpg --format json

# Generate both JSON and text reports
python3 stegoguard_pro.py scan image.jpg --format both

# Specify output directory
python3 stegoguard_pro.py scan image.jpg --output ./custom_reports

# Increase verbosity
python3 stegoguard_pro.py scan image.jpg --verbose

# Disable decryption (detection only)
python3 stegoguard_pro.py scan image.jpg --no-decrypt
```

### Web Dashboard Options

```bash
# Custom port
python3 stegoguard_pro.py dashboard --port 8080

# Enable debug mode (development only)
python3 stegoguard_pro.py dashboard --debug

# Bind to specific interface
python3 stegoguard_pro.py dashboard --host 0.0.0.0
```

---

## 📁 Output Files

### Report Structure

```
reports/
├── SG-A4F2B3E7-2026-04-15_14-32.json   # Full JSON report
├── SG-A4F2B3E7-2026-04-15_14-32.txt    # Human-readable text
└── batch_2026-04-15_14-45/             # Batch results
    ├── summary.json
    ├── image001_report.json
    ├── image002_report.json
    └── ...
```

### JSON Report Example

```json
{
  "report_id": "SG-A4F2B3E7",
  "timestamp": "2026-04-15T14:32:18Z",
  "file": {
    "name": "suspicious.jpg",
    "size": 2457600,
    "sha256": "4a9f2b3e7d8c9e2b...",
    "format": "JPEG"
  },
  "detection": {
    "threat_level": "HIGH",
    "confidence": 92,
    "anomalies_detected": 5,
    "modules_triggered": [
      "LSB Scanner",
      "DCT Analyzer",
      "GAN Detector",
      "Pattern Recognition",
      "Metadata Channel"
    ]
  },
  "decryption": {
    "status": "PARTIAL",
    "success_rate": 72,
    "payload": "target acquired // exfil complete...",
    "probes_used": ["Metadata Keys", "AI Predictor", "Partial Reveal"]
  },
  "apt_attribution": {
    "group": "APT29 (Cozy Bear)",
    "confidence": 89,
    "techniques_matched": ["Hybrid DCT+LSB", "GAN Cover"]
  }
}
```

---

## 🛠️ Troubleshooting

### Common Issues

**1. Dependencies Missing:**
```bash
# Reinstall dependencies
pip3 install -r requirements.txt
```

**2. Permission Denied:**
```bash
# Make start.sh executable
chmod +x start.sh
```

**3. Port Already in Use:**
```bash
# Use different port
python3 stegoguard_pro.py dashboard --port 8080
```

**4. Image Not Supported:**
```bash
# Check supported formats
python3 stegoguard_pro.py --formats
# Output: JPEG, PNG, GIF, WebP, BMP, TIFF
```

**5. Out of Memory:**
```bash
# Reduce file size or use quick scan
python3 stegoguard_pro.py quick large_image.jpg
```

---

## 📚 Next Steps

### Learn More

- **[README.md](README.md)** - Complete documentation
- **[INSTALL.md](INSTALL.md)** - Detailed installation guide
- **[CLI_FEATURES.md](CLI_FEATURES.md)** - Advanced CLI usage
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - How to contribute

### Advanced Features

- **Watch Mode:** Monitor directory for new images
- **Custom Themes:** Create your own dashboard theme
- **API Integration:** Use StegoGuard as a library
- **Batch Automation:** Automate with cron jobs

### Get Help

- **GitHub Issues:** https://github.com/YOUR-USERNAME/StegoGuard/issues
- **Discussions:** https://github.com/YOUR-USERNAME/StegoGuard/discussions
- **Documentation:** Check docs/ directory

---

## ✅ Quick Reference

```bash
# Installation
./start.sh                                    # Auto-install & launch

# CLI
python3 stegoguard_pro.py quick image.jpg     # Quick scan
python3 stegoguard_pro.py scan image.jpg      # Full scan
python3 stegoguard_pro.py batch /images       # Batch scan

# Web Dashboard
python3 stegoguard_pro.py dashboard           # Launch at localhost:5000

# Help
python3 stegoguard_pro.py --help              # Show all commands
python3 stegoguard_pro.py scan --help         # Command-specific help
```

---

**You're now ready to use StegoGuard!** 🎉

For detailed documentation, see [README.md](README.md).
