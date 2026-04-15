# Security Policy

## 🔒 Security Overview

StegoGuard is designed with security and privacy as core principles. This document outlines our security practices, vulnerability reporting process, and supported versions.

---

## 📋 Table of Contents

- [Supported Versions](#supported-versions)
- [Security Features](#security-features)
- [Reporting a Vulnerability](#reporting-a-vulnerability)
- [Security Best Practices](#security-best-practices)
- [Known Limitations](#known-limitations)
- [Security Updates](#security-updates)

---

## ✅ Supported Versions

We actively maintain and provide security updates for the following versions:

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 2.7.x   | :white_check_mark: | Current stable release |
| 2.6.x   | :white_check_mark: | Security fixes only |
| 2.5.x   | :x:                | End of life |
| < 2.5   | :x:                | End of life |

**Recommendation:** Always use the latest stable version (2.7.x) for the best security and features.

---

## 🛡️ Security Features

StegoGuard implements multiple security layers:

### Zero Network Communications
- **100% Offline Operation:** No external network calls
- **No Telemetry:** No data collection or analytics
- **Air-Gap Compatible:** Works in isolated environments
- **No Phone Home:** No version checks or usage reporting

### Secure Processing
- **Sandboxed Analysis:** Safe handling of potentially malicious content
- **Memory Clearing:** Sensitive data wiped after operations
- **Temp File Management:** Automatic cleanup of temporary files
- **Process Isolation:** Separate processes for untrusted operations

### Cryptographic Security
- **CSPRNG:** Cryptographically Secure Pseudo-Random Number Generator
- **Strong Hashing:** SHA256 for integrity verification
- **Secure Comparison:** Constant-time comparisons to prevent timing attacks
- **Key Derivation:** Argon2id for password-based key derivation

### Forensic Soundness
- **SHA256 Hashing:** All analyzed files hashed for integrity
- **Chain of Custody:** Complete audit trail of operations
- **Immutable Logs:** Tamper-evident logging system
- **Timestamping:** UTC timestamps for all operations

### Input Validation
- **File Type Verification:** Magic byte validation
- **Size Limits:** Maximum file size enforcement (100MB)
- **Path Sanitization:** Prevention of path traversal attacks
- **Format Validation:** Strict image format verification

---

## 🚨 Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please follow this process:

### Reporting Process

**DO NOT** open a public GitHub issue for security vulnerabilities.

**Instead, please:**

1. **Email:** Send details to `security@stegoguard.local` (or create a private security advisory on GitHub)
2. **Encrypt (Optional):** Use PGP key if available
3. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Affected versions
   - Suggested fix (if any)

### What to Expect

| Timeline | Action |
|----------|--------|
| **< 24 hours** | Initial acknowledgment |
| **< 7 days** | Preliminary assessment and severity rating |
| **< 30 days** | Fix developed and tested |
| **< 45 days** | Patch released and advisory published |

### Severity Ratings

**Critical:**
- Remote code execution
- Authentication bypass
- Data exfiltration
- Privilege escalation

**High:**
- Local code execution
- Denial of service
- Information disclosure (sensitive data)
- Security feature bypass

**Medium:**
- Information disclosure (non-sensitive)
- Cross-site scripting (XSS) in web dashboard
- Improper input validation

**Low:**
- Minor information leaks
- Best practice violations
- Non-exploitable bugs

---

## 🔐 Security Best Practices

### For Users

1. **Verify Downloads:**
   ```bash
   # Check SHA256 hash
   sha256sum StegoGuard.tar.gz
   # Compare with official hash
   ```

2. **Use Virtual Environments:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip3 install -r requirements.txt
   ```

3. **Run with Least Privilege:**
   ```bash
   # Don't run as root unless necessary
   python3 stegoguard_pro.py scan image.jpg
   ```

4. **Isolate Untrusted Files:**
   ```bash
   # Analyze suspicious files in isolated environment
   # Use VM or container for maximum safety
   ```

5. **Keep Updated:**
   ```bash
   git pull origin main
   pip3 install -r requirements.txt --upgrade
   ```

### For Developers

1. **Input Validation:**
   ```python
   def validate_image_path(path):
       """Validate and sanitize image path."""
       # Check path exists
       if not os.path.exists(path):
           raise ValueError(f"File not found: {path}")

       # Prevent path traversal
       real_path = os.path.realpath(path)
       if not real_path.startswith(ALLOWED_DIR):
           raise ValueError("Path traversal detected")

       # Verify file type
       if not is_valid_image(path):
           raise ValueError("Invalid image format")
   ```

2. **Secure File Handling:**
   ```python
   def secure_temp_file():
       """Create secure temporary file."""
       import tempfile

       # Use secure temp directory
       fd, path = tempfile.mkstemp(
           prefix="stegoguard_",
           suffix=".tmp",
           dir="/secure/tmp"
       )

       # Set restrictive permissions
       os.chmod(path, 0o600)

       return fd, path
   ```

3. **Error Handling:**
   ```python
   try:
       result = analyze_image(untrusted_file)
   except Exception as e:
       # Don't leak sensitive info in error messages
       logger.error(f"Analysis failed: {type(e).__name__}")
       raise GenericError("Analysis failed")
   ```

---

## ⚠️ Known Limitations

### Intentional Design Decisions

1. **No Network Access:**
   - Cannot fetch updates automatically
   - No cloud-based threat intelligence
   - **Reason:** Privacy and air-gap compatibility

2. **Local Processing Only:**
   - All analysis happens locally
   - No distributed processing
   - **Reason:** Security and data protection

3. **Size Limits:**
   - Maximum file size: 100MB
   - **Reason:** Memory management and DoS prevention

### Technical Limitations

1. **False Positives:**
   - <3% false positive rate
   - Some clean images may trigger warnings
   - **Mitigation:** Multi-layer validation system

2. **Encrypted Payload Limits:**
   - Cannot decrypt strong encryption without keys
   - 74-78% success rate with hardened engine
   - **Mitigation:** 18-probe decryption engine

3. **Format Support:**
   - Not all image formats fully supported
   - Some tools work on subset of formats
   - **Mitigation:** Pillow-based normalization

---

## 🔄 Security Updates

### Update Channels

1. **GitHub Releases:**
   - https://github.com/YOUR-USERNAME/StegoGuard/releases
   - Subscribe to release notifications

2. **Security Advisories:**
   - https://github.com/YOUR-USERNAME/StegoGuard/security/advisories
   - Critical vulnerabilities published here

3. **CHANGELOG.md:**
   - Security fixes marked with [SECURITY] tag
   - Review before updating

### Update Process

```bash
# 1. Backup current version
cp -r StegoGuard_Pro StegoGuard_Pro.backup

# 2. Check for updates
git fetch origin
git log HEAD..origin/main --oneline

# 3. Review changes
git diff HEAD..origin/main

# 4. Update
git pull origin main

# 5. Update dependencies
pip3 install -r requirements.txt --upgrade

# 6. Test
python3 stegoguard_pro.py quick test_images/test.jpg

# 7. Remove backup if successful
rm -rf StegoGuard_Pro.backup
```

---

## 🔍 Security Audit

### Self-Audit Checklist

- [ ] All dependencies up to date
- [ ] No hardcoded credentials
- [ ] No sensitive data in logs
- [ ] Input validation on all user inputs
- [ ] Secure file handling
- [ ] Proper error handling (no info leaks)
- [ ] Temp files cleaned up
- [ ] SHA256 verification enabled
- [ ] Running latest version
- [ ] Security best practices followed

### Third-Party Audits

**Status:** Not yet audited

**Interested in auditing?** Contact maintainers to coordinate a security audit.

---

## 🛠️ Secure Configuration

### Web Dashboard Security

```python
# api/app.py - Recommended security settings

# Disable debug mode in production
app.config['DEBUG'] = False

# Use strong secret key
app.config['SECRET_KEY'] = os.urandom(32)

# Enable HTTPS only (if using over network)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Set CSP headers
app.config['CONTENT_SECURITY_POLICY'] = {
    'default-src': ["'self'"],
    'script-src': ["'self'"],
    'style-src': ["'self'", "'unsafe-inline'"]
}

# Limit upload size
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB
```

### File System Security

```bash
# Restrictive permissions on sensitive files
chmod 600 config.yml
chmod 700 reports/

# Separate user for StegoGuard
useradd -r -s /bin/false stegoguard
chown -R stegoguard:stegoguard StegoGuard_Pro/

# Run as non-root
sudo -u stegoguard python3 stegoguard_pro.py dashboard
```

---

## 📞 Contact

**For security vulnerabilities only:**
- Email: `security@stegoguard.local` (create private advisory)
- PGP Key: [Link to public key]

**For general issues:**
- GitHub Issues: https://github.com/YOUR-USERNAME/StegoGuard/issues

---

## 📄 Disclosure Policy

**Coordinated Disclosure:**
- We follow a 90-day disclosure timeline
- Security fixes released before public disclosure
- Credit given to reporters (if desired)

**Public Disclosure:**
- After patch is released
- Or after 90 days (whichever comes first)
- With reporter's consent

---

## 🏆 Security Hall of Fame

We thank the following researchers for responsibly disclosing vulnerabilities:

| Researcher | Vulnerability | Version | Date |
|------------|--------------|---------|------|
| TBD | TBD | TBD | TBD |

*No vulnerabilities reported yet.*

---

## 🔏 Cryptographic Verification

### Release Signing (Coming Soon)

Future releases will be signed with PGP:

```bash
# Verify release signature
gpg --verify StegoGuard-2.7.tar.gz.sig StegoGuard-2.7.tar.gz
```

### File Integrity

```bash
# Generate checksums
sha256sum StegoGuard_Pro/* > checksums.txt

# Verify integrity
sha256sum -c checksums.txt
```

---

**Last Updated:** 2026-04-15
**Version:** 2.7
**Status:** Active

---

**Security is everyone's responsibility. Thank you for helping keep StegoGuard secure!** 🛡️
