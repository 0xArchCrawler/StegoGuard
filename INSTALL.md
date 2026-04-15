# StegoGuard Installation Guide

Complete installation instructions for all platforms.

---

## 📋 Table of Contents

- [System Requirements](#system-requirements)
- [Quick Installation](#quick-installation)
- [Platform-Specific Instructions](#platform-specific-instructions)
  - [Linux (Debian/Ubuntu/Kali)](#linux-debianubuntukali)
  - [Linux (Arch/Manjaro)](#linux-archmanjaro)
  - [macOS](#macos)
  - [Windows](#windows)
- [Docker Installation](#docker-installation)
- [Virtual Environment Setup](#virtual-environment-setup)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

---

## 💻 System Requirements

### Minimum Requirements

- **Python:** 3.8 or higher
- **RAM:** 4GB minimum
- **Storage:** 500MB for application + reports
- **OS:** Linux, macOS, or Windows

### Recommended Requirements

- **Python:** 3.10 or higher
- **RAM:** 8GB or more
- **Storage:** 2GB for application + test images + reports
- **OS:** Linux (Kali/Ubuntu) or macOS

### Supported Platforms

| Platform | Status | Notes |
|----------|--------|-------|
| Kali Linux 2024+ | ✅ Fully Supported | Recommended |
| Ubuntu 20.04+ | ✅ Fully Supported | LTS recommended |
| Debian 11+ | ✅ Fully Supported | Stable |
| Arch Linux | ✅ Fully Supported | Rolling release |
| macOS 11+ | ✅ Fully Supported | Big Sur or later |
| Windows 10/11 | ⚠️ Partially Supported | WSL2 recommended |
| Docker | ✅ Fully Supported | Cross-platform |

---

## ⚡ Quick Installation

### One-Line Install (Linux/macOS)

```bash
git clone https://github.com/YOUR-USERNAME/StegoGuard.git && cd StegoGuard/StegoGuard_Pro && ./start.sh
```

The `start.sh` script will:
1. Check Python installation
2. Auto-install all dependencies
3. Launch interactive menu
4. Guide you through first use

---

## 🐧 Platform-Specific Instructions

### Linux (Debian/Ubuntu/Kali)

#### Step 1: Update System

```bash
sudo apt update && sudo apt upgrade -y
```

#### Step 2: Install Python 3 and pip

```bash
# Install Python 3.10+ and pip
sudo apt install python3 python3-pip python3-venv -y

# Verify installation
python3 --version  # Should show 3.8+ (3.10+ recommended)
pip3 --version
```

#### Step 3: Install Optional System Tools

```bash
# Enhanced forensic capabilities
sudo apt install exiftool binwalk foremost -y

# Image processing libraries (optional)
sudo apt install libimage-exiftool-perl dcraw -y
```

#### Step 4: Clone Repository

```bash
cd ~
git clone https://github.com/YOUR-USERNAME/StegoGuard.git
cd StegoGuard/StegoGuard_Pro
```

#### Step 5: Install Python Dependencies

```bash
# Option A: Use start.sh (automatic)
./start.sh

# Option B: Manual installation
pip3 install -r requirements.txt

# Option C: With optional AI/ML packages
pip3 install -r requirements.txt
pip3 install -r requirements-optional.txt
```

#### Step 6: Verify Installation

```bash
python3 stegoguard_pro.py --help
```

---

### Linux (Arch/Manjaro)

#### Step 1: Update System

```bash
sudo pacman -Syu
```

#### Step 2: Install Python and Tools

```bash
# Install Python 3 and pip
sudo pacman -S python python-pip

# Install system tools
sudo pacman -S perl-image-exiftool binwalk foremost dcraw

# Verify
python3 --version
```

#### Step 3: Clone and Install

```bash
cd ~
git clone https://github.com/YOUR-USERNAME/StegoGuard.git
cd StegoGuard/StegoGuard_Pro

# Install dependencies
pip3 install -r requirements.txt

# Or use start.sh
./start.sh
```

---

### macOS

#### Step 1: Install Homebrew (if not installed)

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

#### Step 2: Install Python 3

```bash
# Install Python 3.10+
brew install python@3.10

# Verify installation
python3 --version
```

#### Step 3: Install Optional Tools

```bash
# Forensic tools
brew install exiftool binwalk

# Image processing
brew install dcraw
```

#### Step 4: Clone and Install

```bash
cd ~
git clone https://github.com/YOUR-USERNAME/StegoGuard.git
cd StegoGuard/StegoGuard_Pro

# Install dependencies
pip3 install -r requirements.txt

# Or use start.sh
chmod +x start.sh
./start.sh
```

---

### Windows

#### Option A: WSL2 (Recommended)

**1. Enable WSL2:**

```powershell
# Open PowerShell as Administrator
wsl --install
# Restart computer
```

**2. Install Ubuntu from Microsoft Store**

**3. Follow Linux (Ubuntu) instructions above**

#### Option B: Native Windows

**1. Install Python:**
- Download Python 3.10+ from https://www.python.org/downloads/
- ✅ Check "Add Python to PATH" during installation
- Verify: `python --version` in Command Prompt

**2. Install Git:**
- Download Git from https://git-scm.com/download/win
- Install with default settings

**3. Clone and Install:**

```cmd
# Open Command Prompt
cd %USERPROFILE%
git clone https://github.com/YOUR-USERNAME/StegoGuard.git
cd StegoGuard\StegoGuard_Pro

# Install dependencies
pip install -r requirements.txt

# Launch
python stegoguard_pro.py --help
```

**4. Optional Tools (Advanced):**
- ExifTool: https://exiftool.org/
- Binwalk: Requires Cygwin or WSL

**Note:** Web dashboard may have limited functionality on native Windows. WSL2 recommended for full features.

---

## 🐳 Docker Installation

### Using Docker

```bash
# Clone repository
git clone https://github.com/YOUR-USERNAME/StegoGuard.git
cd StegoGuard/StegoGuard_Pro

# Build Docker image
docker build -t stegoguard:2.7 .

# Run CLI mode
docker run --rm -v $(pwd)/test_images:/images stegoguard:2.7 scan /images/test.jpg

# Run web dashboard
docker run -p 5000:5000 stegoguard:2.7 dashboard
# Access at: http://localhost:5000
```

### Docker Compose

**docker-compose.yml:**
```yaml
version: '3.8'

services:
  stegoguard:
    build: .
    ports:
      - "5000:5000"
    volumes:
      - ./images:/images
      - ./reports:/reports
    command: dashboard --host 0.0.0.0
```

**Usage:**
```bash
docker-compose up -d
# Access at: http://localhost:5000
```

---

## 🔧 Virtual Environment Setup (Recommended)

### Why Use Virtual Environments?

- Isolate dependencies
- Prevent version conflicts
- Clean uninstallation
- Multiple Python versions

### Create Virtual Environment

```bash
cd StegoGuard/StegoGuard_Pro

# Create venv
python3 -m venv venv

# Activate venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Deactivate when done
deactivate
```

### Using virtualenv

```bash
# Install virtualenv
pip3 install virtualenv

# Create environment
virtualenv -p python3.10 stegoguard_env

# Activate
source stegoguard_env/bin/activate

# Install
pip install -r requirements.txt
```

---

## ✅ Verification

### Check Installation

```bash
# 1. Verify Python version
python3 --version
# Expected: Python 3.8.0 or higher (3.10+ recommended)

# 2. Check dependencies
pip3 list | grep -E "flask|rich|pillow|numpy"
# Expected: All packages installed

# 3. Run help command
python3 stegoguard_pro.py --help
# Expected: Command help displayed

# 4. Test quick scan
python3 stegoguard_pro.py quick test_images/test.jpg
# Expected: Analysis completes successfully

# 5. Test web dashboard
python3 stegoguard_pro.py dashboard --help
# Expected: Dashboard options displayed
```

### Test Functionality

```bash
# Create test directory
mkdir -p ~/stegoguard_test && cd ~/stegoguard_test

# Download test image (or use your own)
# ...

# Run quick scan
python3 ~/StegoGuard/StegoGuard_Pro/stegoguard_pro.py quick test.jpg

# Expected output:
# ════════════════════════════════════════════════════════
# StegoGuard Quick Scan - v2.7
# ════════════════════════════════════════════════════════
# File: test.jpg
# Threat Level: CLEAN (Confidence: 28%)
# ...
```

---

## 🔍 Troubleshooting

### Common Issues

#### 1. Python Version Too Old

**Problem:**
```
ERROR: Python 3.6 is not supported. Requires 3.8+
```

**Solution:**
```bash
# Ubuntu/Debian
sudo apt install python3.10 python3.10-pip

# Update alternatives
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 1

# Verify
python3 --version
```

#### 2. Permission Denied on start.sh

**Problem:**
```
bash: ./start.sh: Permission denied
```

**Solution:**
```bash
chmod +x start.sh
./start.sh
```

#### 3. pip not found

**Problem:**
```
bash: pip3: command not found
```

**Solution:**
```bash
# Install pip
sudo apt install python3-pip  # Debian/Ubuntu
sudo pacman -S python-pip      # Arch
brew install python@3.10       # macOS

# Verify
pip3 --version
```

#### 4. ModuleNotFoundError

**Problem:**
```
ModuleNotFoundError: No module named 'PIL'
```

**Solution:**
```bash
# Reinstall dependencies
pip3 install -r requirements.txt

# Or install specific package
pip3 install Pillow
```

#### 5. Port 5000 Already in Use

**Problem:**
```
OSError: [Errno 98] Address already in use
```

**Solution:**
```bash
# Option A: Use different port
python3 stegoguard_pro.py dashboard --port 8080

# Option B: Kill process using port 5000
lsof -ti:5000 | xargs kill -9
```

#### 6. Out of Memory

**Problem:**
```
MemoryError: Unable to allocate array
```

**Solution:**
```bash
# Use quick scan (less memory)
python3 stegoguard_pro.py quick large_image.jpg

# Or reduce image size first
convert large_image.jpg -resize 50% smaller.jpg
```

#### 7. SSL Certificate Error

**Problem:**
```
SSLError: [SSL: CERTIFICATE_VERIFY_FAILED]
```

**Solution:**
```bash
# Install certificates
pip3 install --upgrade certifi

# Or disable SSL verify (not recommended)
pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
```

---

## 📦 Dependency Details

### Core Dependencies

**Web Framework:**
- flask==3.0.2
- flask-cors==4.0.0
- flask-socketio==5.3.6
- werkzeug==3.0.1

**CLI:**
- rich==13.7.0
- click==8.1.7
- colorama==0.4.6

**Image Processing:**
- Pillow==10.2.0
- numpy==1.26.4
- opencv-python==4.9.0.80
- PyWavelets==1.5.0
- scipy==1.12.0

**Cryptography:**
- cryptography==42.0.2
- pycryptodome==3.20.0
- PyJWT==2.8.0

**Analysis:**
- scikit-learn==1.4.0
- pandas==2.2.0
- matplotlib==3.8.2

**Utilities:**
- requests==2.31.0
- aiohttp==3.9.3
- psutil==5.9.8
- python-dateutil==2.8.2

### Optional Dependencies

**AI/ML (optional):**
- tensorflow==2.15.0 (for advanced GAN detection)
- keras==2.15.0

**Development (optional):**
- pytest==7.4.3
- pytest-cov==4.1.0
- black==23.12.1
- flake8==7.0.0

---

## 🌐 Network Configuration

### Firewall Rules

If using web dashboard over network:

```bash
# Allow port 5000 (or your custom port)
sudo ufw allow 5000/tcp

# For specific interface only
sudo ufw allow in on eth0 to any port 5000

# Check status
sudo ufw status
```

### HTTPS Setup (Production)

**Using Nginx as reverse proxy:**

```nginx
server {
    listen 443 ssl;
    server_name stegoguard.local;

    ssl_certificate /etc/ssl/certs/stegoguard.crt;
    ssl_certificate_key /etc/ssl/private/stegoguard.key;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /socket.io {
        proxy_pass http://127.0.0.1:5000/socket.io;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
    }
}
```

---

## 🔄 Updating StegoGuard

### Update to Latest Version

```bash
cd StegoGuard/StegoGuard_Pro

# Check for updates
git fetch origin
git log HEAD..origin/main --oneline

# Backup current config
cp -r config/ config.backup/

# Pull updates
git pull origin main

# Update dependencies
pip3 install -r requirements.txt --upgrade

# Verify
python3 stegoguard_pro.py --version
```

### Rollback to Previous Version

```bash
# View available versions
git tag

# Checkout specific version
git checkout v2.6.0

# Reinstall dependencies
pip3 install -r requirements.txt
```

---

## ❓ Getting Help

**Installation Issues:**
- Check [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)
- Search [GitHub Issues](https://github.com/YOUR-USERNAME/StegoGuard/issues)
- Create new issue with installation details

**System Information to Include:**
```bash
# Gather system info
python3 --version
pip3 --version
uname -a  # Linux/macOS
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"  # Windows
```

---

**Installation complete!** 🎉

Next: See [QUICKSTART.md](QUICKSTART.md) for first steps.
