#!/usr/bin/env python3
"""
StegoGuard - Professional Steganography Detection & Forensics
Self-Contained Launcher - No Installation Required

Usage:
    python stegoguard_pro.py scan image.jpg
    python stegoguard_pro.py quick image.jpg
    python stegoguard_pro.py batch ./images
    python stegoguard_pro.py dashboard
"""

import sys
import os
from pathlib import Path

# Add all necessary paths
BASE_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BASE_DIR))

# Check Python version
if sys.version_info < (3, 8):
    print("Error: Python 3.8+ required")
    sys.exit(1)

# Import CLI
try:
    from StegoGuard_Pro.cli.stegoguard_cli import cli

    if __name__ == '__main__':
        cli()

except ImportError as e:
    print(f"Error importing modules: {e}")
    print("\\nMissing dependencies. Install with:")
    print("pip install -r requirements.txt")
    sys.exit(1)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
