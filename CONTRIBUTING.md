# Contributing to StegoGuard

Thank you for your interest in contributing to StegoGuard! We welcome contributions from the security community to make this tool even better.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Coding Guidelines](#coding-guidelines)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)
- [Testing](#testing)
- [Documentation](#documentation)

---

## 📜 Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment for all contributors, regardless of experience level, gender, gender identity, sexual orientation, disability, personal appearance, body size, race, ethnicity, age, religion, or nationality.

### Our Standards

**Positive Behavior:**
- Using welcoming and inclusive language
- Being respectful of differing viewpoints
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

**Unacceptable Behavior:**
- Harassment, trolling, or derogatory comments
- Publishing others' private information
- Other conduct which could reasonably be considered inappropriate

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported by opening an issue or contacting the project maintainers. All complaints will be reviewed and investigated promptly and fairly.

---

## 🤝 How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates.

**When reporting bugs, include:**
- StegoGuard version (`cat VERSION`)
- Python version (`python3 --version`)
- Operating system and version
- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- Screenshots if applicable
- Relevant log output

**Bug Report Template:**
```markdown
**StegoGuard Version:** 2.7
**Python Version:** 3.10.8
**OS:** Kali Linux 2026.1

**Steps to Reproduce:**
1. Run `python3 stegoguard_pro.py scan test.jpg`
2. Observe error message

**Expected:** Analysis completes successfully
**Actual:** Error: "ModuleNotFoundError: No module named 'PIL'"

**Logs:**
[Paste relevant logs here]
```

### Suggesting Enhancements

Enhancement suggestions are welcome! Please provide:
- Clear and descriptive title
- Detailed description of the proposed functionality
- Explain why this enhancement would be useful
- Provide examples if possible

**Areas for Enhancement:**
- New detection modules
- Additional decryption probes
- Format support expansion
- APT attribution database updates
- Performance optimizations
- UI/UX improvements
- Documentation improvements

### Contributing Code

We welcome code contributions! Here are some areas where you can help:

**Detection Modules:**
- New steganography detection algorithms
- Improved statistical tests
- Machine learning enhancements

**Decryption Engine:**
- Additional decryption probes
- Improved key derivation techniques
- Crypto algorithm support

**Features:**
- New export formats
- Additional themes
- CLI improvements
- API enhancements

**Infrastructure:**
- Test coverage expansion
- Performance optimizations
- Bug fixes

---

## 🛠️ Development Setup

### Prerequisites

- Python 3.8+ (3.10+ recommended)
- pip3
- git
- 4GB RAM minimum

### Setup Steps

```bash
# 1. Fork the repository on GitHub

# 2. Clone your fork
git clone https://github.com/YOUR-USERNAME/StegoGuard.git
cd StegoGuard/StegoGuard_Pro

# 3. Add upstream remote
git remote add upstream https://github.com/ORIGINAL-OWNER/StegoGuard.git

# 4. Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate  # Windows

# 5. Install dependencies
pip3 install -r requirements.txt
pip3 install -r requirements-optional.txt  # For AI/ML features

# 6. Install development dependencies
pip3 install pytest pytest-cov black flake8

# 7. Verify installation
python3 stegoguard_pro.py --help
./start.sh
```

### Running Tests

```bash
# Run all tests
pytest testing/

# Run specific test
pytest testing/test_analyzer.py

# Run with coverage
pytest --cov=core --cov=api --cov=cli testing/

# Run format compatibility tests
pytest testing/test_format_support.py -v
```

---

## 💻 Coding Guidelines

### Python Style

Follow PEP 8 with these guidelines:

**Formatting:**
```python
# Use 4 spaces for indentation (not tabs)
# Max line length: 100 characters
# Use descriptive variable names

# Good
def analyze_lsb_entropy(image_data, bit_planes=8):
    """Analyze LSB bit-plane entropy."""
    entropy_values = []
    for plane in range(bit_planes):
        entropy = calculate_entropy(image_data, plane)
        entropy_values.append(entropy)
    return entropy_values

# Bad
def anlz(d,b=8):
    e=[]
    for p in range(b):e.append(calc(d,p))
    return e
```

**Docstrings:**
```python
def decrypt_with_metadata_keys(image_path, exif_data):
    """
    Attempt decryption using metadata-derived keys.

    Derives encryption keys from EXIF metadata including
    timestamps, GPS coordinates, and device information.

    Args:
        image_path (str): Path to the image file
        exif_data (dict): Extracted EXIF metadata

    Returns:
        dict: Decryption results with keys:
            - success (bool): Whether decryption succeeded
            - payload (bytes): Decrypted payload if successful
            - confidence (float): Confidence score 0-100

    Raises:
        ValueError: If image_path is invalid
        IOError: If image cannot be read
    """
    pass
```

**Imports:**
```python
# Standard library imports
import os
import sys
from pathlib import Path

# Third-party imports
import numpy as np
from PIL import Image
from flask import Flask, request

# Local imports
from core.analyzer import StegoAnalyzer
from core.threat_intel import ThreatIntelligence
```

### Code Organization

**Module Structure:**
```
core/
├── __init__.py          # Package initialization
├── analyzer.py          # Main analyzer class
├── threat_intel.py      # APT detection
└── utils.py             # Utility functions

# Each module should have:
# 1. Module docstring
# 2. Imports
# 3. Constants
# 4. Classes
# 5. Functions
# 6. Main block (if applicable)
```

### Error Handling

```python
# Use specific exceptions
try:
    image = Image.open(image_path)
except FileNotFoundError:
    logger.error(f"Image not found: {image_path}")
    raise
except PIL.UnidentifiedImageError:
    logger.error(f"Invalid image format: {image_path}")
    raise ValueError(f"Unsupported image format")

# Provide helpful error messages
if not os.path.exists(output_dir):
    raise ValueError(
        f"Output directory does not exist: {output_dir}\n"
        f"Create it with: mkdir -p {output_dir}"
    )
```

### Logging

```python
import logging

logger = logging.getLogger(__name__)

# Use appropriate log levels
logger.debug("LSB analysis started for 8 bit planes")
logger.info("Detection complete: 4/12 modules triggered")
logger.warning("Low confidence score: 62% (threshold: 70%)")
logger.error("Failed to load image: FileNotFoundError")
```

---

## 📝 Commit Messages

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, no logic change)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

### Examples

```
feat(detection): Add PQC lattice detector for Dilithium/Kyber

Implements post-quantum cryptography detection for lattice-based
algorithms including Dilithium, Kyber, NTRU, and SPHINCS+.

- Added PQCLatticeDetector class
- Integrated with main analyzer
- Added unit tests
- Updated documentation

Closes #42
```

```
fix(decryption): Resolve metadata key derivation edge case

Fixed issue where EXIF timestamps with timezone offsets
caused key derivation to fail.

- Handle UTC offsets correctly
- Add fallback for missing timezone data
- Add regression test

Fixes #58
```

```
docs: Update QUICKSTART.md with web dashboard examples

- Added drag & drop upload instructions
- Included theme switching guide
- Fixed broken screenshot links
```

---

## 🔄 Pull Request Process

### Before Submitting

1. **Update your fork:**
   ```bash
   git fetch upstream
   git checkout main
   git merge upstream/main
   ```

2. **Create a feature branch:**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-number-description
   ```

3. **Make your changes:**
   - Write clean, documented code
   - Follow coding guidelines
   - Add tests for new functionality
   - Update documentation

4. **Test your changes:**
   ```bash
   # Run tests
   pytest testing/

   # Check code style
   black core/ api/ cli/
   flake8 core/ api/ cli/

   # Verify functionality
   python3 stegoguard_pro.py quick test_images/test.jpg
   ```

5. **Commit your changes:**
   ```bash
   git add .
   git commit -m "feat(scope): descriptive message"
   ```

6. **Push to your fork:**
   ```bash
   git push origin feature/your-feature-name
   ```

### Submitting the PR

1. Go to https://github.com/ORIGINAL-OWNER/StegoGuard
2. Click "New Pull Request"
3. Select your fork and branch
4. Fill in the PR template:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex code
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Tests added for new functionality
- [ ] Dependent changes merged

## Screenshots (if applicable)
[Add screenshots here]

## Related Issues
Closes #XX
```

### Review Process

1. **Automated Checks:**
   - GitHub Actions will run tests
   - Code coverage will be checked
   - Style checks will be performed

2. **Code Review:**
   - Maintainers will review your code
   - Address feedback promptly
   - Be open to suggestions

3. **Approval:**
   - At least one maintainer approval required
   - All tests must pass
   - No merge conflicts

4. **Merge:**
   - Maintainer will merge when approved
   - Your contribution will be credited in CHANGELOG.md

---

## 🧪 Testing

### Test Structure

```
testing/
├── test_analyzer.py              # Core analyzer tests
├── test_decryption_enhanced.py   # Decryption engine tests
├── test_gan_detector.py          # GAN detector tests
├── test_confidence_scoring.py    # Confidence tests
├── test_reliability.py           # Reliability system tests
└── test_format_support.py        # Format compatibility tests
```

### Writing Tests

```python
import pytest
from core.analyzer import StegoAnalyzer

def test_lsb_detection_high_entropy():
    """Test LSB detection on high-entropy image."""
    analyzer = StegoAnalyzer()
    result = analyzer.analyze_lsb("test_images/lsb_stego.jpg")

    assert result['anomaly_detected'] is True
    assert result['confidence'] > 80
    assert result['entropy_spike'] > 7.5

def test_clean_image_no_false_positive():
    """Verify clean image doesn't trigger false positive."""
    analyzer = StegoAnalyzer()
    result = analyzer.analyze("test_images/clean.jpg")

    assert result['threat_level'] == "CLEAN"
    assert result['confidence'] < 30
```

### Test Coverage

Aim for:
- **Unit Tests:** 80%+ coverage
- **Integration Tests:** Critical paths covered
- **Format Tests:** All supported formats

---

## 📚 Documentation

### Documentation Types

1. **Code Comments:**
   - Explain complex algorithms
   - Document non-obvious decisions
   - Add TODO/FIXME for future work

2. **Docstrings:**
   - All public functions and classes
   - Follow Google or NumPy style
   - Include examples for complex functions

3. **README Updates:**
   - Update feature lists
   - Add new examples
   - Update performance metrics

4. **CHANGELOG:**
   - Add entry for each change
   - Follow semantic versioning

### Documentation Standards

```python
def analyze_dct_coefficients(image, block_size=8):
    """
    Analyze DCT coefficient distribution for anomalies.

    Performs 8x8 block DCT transformation and analyzes
    mid-band coefficient distribution for steganography
    indicators.

    Args:
        image (PIL.Image): Input image
        block_size (int): DCT block size (default: 8)

    Returns:
        dict: Analysis results containing:
            - anomaly_detected (bool): Whether anomaly found
            - coefficient_histogram (np.array): Histogram data
            - suspicious_blocks (list): Coordinates of suspicious blocks
            - confidence (float): Confidence score 0-100

    Example:
        >>> from PIL import Image
        >>> img = Image.open("test.jpg")
        >>> result = analyze_dct_coefficients(img)
        >>> print(result['confidence'])
        87.5

    Note:
        This function is optimized for JPEG images. For other
        formats, the image is internally converted which may
        introduce artifacts.
    """
    pass
```

---

## 🎯 Areas for Contribution

### High Priority

- [ ] Additional decryption probes
- [ ] New steganography detection techniques
- [ ] Performance optimizations
- [ ] Test coverage expansion
- [ ] Documentation improvements

### Medium Priority

- [ ] Additional export formats (CSV, XML)
- [ ] More themes for web dashboard
- [ ] Enhanced APT attribution database
- [ ] Mobile-responsive web UI
- [ ] Docker containerization

### Low Priority

- [ ] Additional language translations
- [ ] Alternative database backends
- [ ] Plugin system architecture
- [ ] Cloud deployment guides

---

## 🙏 Recognition

Contributors will be:
- Listed in CHANGELOG.md for each release
- Credited in README.md contributors section
- Mentioned in release notes
- Given credit in commit history

---

## 📞 Questions?

- **GitHub Issues:** For bugs and feature requests
- **GitHub Discussions:** For questions and community chat
- **Email:** For private security concerns (see SECURITY.md)

---

## ⚖️ License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to StegoGuard!** 🛡️

Your contributions help make the security community stronger.
