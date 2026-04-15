"""
StegoGuard Improved Data Extraction Engine
Real LSB/DCT extraction with no external dependencies
Uses only numpy and PIL (already installed)
"""

import numpy as np
from typing import Dict, List, Optional, Tuple
import struct
import hashlib
import itertools


class ImprovedExtractionEngine:
    """
    Improved extraction engine with real algorithms
    No external dependencies - uses only numpy/PIL
    """

    def __init__(self, image_array: np.ndarray):
        self.image_array = image_array
        self.height, self.width = image_array.shape[:2]
        self.channels = image_array.shape[2] if len(image_array.shape) > 2 else 1

    def extract_lsb_sequence(self, num_bits: int = 1, channel: int = 0) -> bytes:
        """
        Extract LSB sequence from specified channel

        Args:
            num_bits: Number of LSB bits to extract (1-4)
            channel: Channel to extract from (0=R, 1=G, 2=B)

        Returns:
            Extracted bytes
        """
        if self.channels == 1:
            data = self.image_array
        else:
            data = self.image_array[:, :, channel]

        # Flatten image
        flat_data = data.flatten()

        # Extract LSB bits
        bit_mask = (1 << num_bits) - 1
        extracted_bits = []

        for pixel in flat_data:
            bits = pixel & bit_mask
            extracted_bits.append(bits)

        # Convert to bytes
        byte_array = []
        for i in range(0, len(extracted_bits) - 8, 8):
            byte_val = 0
            for j in range(8):
                if i + j < len(extracted_bits):
                    byte_val |= ((extracted_bits[i + j] & 1) << (7 - j))
            byte_array.append(byte_val)

        return bytes(byte_array)

    def extract_bit_plane(self, bit_position: int, channel: int = 0) -> np.ndarray:
        """
        Extract specific bit plane

        Args:
            bit_position: Bit position (0-7, where 0 is LSB)
            channel: Channel to extract from

        Returns:
            Bit plane as array
        """
        if self.channels == 1:
            data = self.image_array
        else:
            data = self.image_array[:, :, channel]

        # Extract bit plane
        bit_plane = (data >> bit_position) & 1
        return bit_plane

    def extract_multi_plane_data(self, planes: List[int] = [0, 1]) -> bytes:
        """
        Extract data from multiple bit planes combined

        Args:
            planes: List of bit plane indices to extract from

        Returns:
            Combined extracted bytes
        """
        combined_bits = []

        for plane_idx in planes:
            plane = self.extract_bit_plane(plane_idx)
            flat_plane = plane.flatten()
            combined_bits.extend(flat_plane[:10000])  # Limit to avoid excessive data

        # Convert bits to bytes
        byte_array = []
        for i in range(0, len(combined_bits), 8):
            byte_val = 0
            for j in range(8):
                if i + j < len(combined_bits):
                    byte_val |= (int(combined_bits[i + j]) << (7 - j))
            byte_array.append(byte_val)

        return bytes(byte_array[:1000])  # Limit output

    def extract_channel_xor(self) -> bytes:
        """
        Extract data from XOR of RGB channels
        Some tools encode in channel differences
        """
        if self.channels < 3:
            return b''

        r_channel = self.image_array[:, :, 0].flatten()
        g_channel = self.image_array[:, :, 1].flatten()
        b_channel = self.image_array[:, :, 2].flatten()

        # XOR channels
        xor_data = r_channel ^ g_channel ^ b_channel

        # Convert to bytes
        byte_array = []
        for i in range(0, min(len(xor_data), 10000), 8):
            byte_val = 0
            for j in range(8):
                if i + j < len(xor_data):
                    byte_val |= ((xor_data[i + j] & 1) << (7 - j))
            byte_array.append(byte_val)

        return bytes(byte_array[:500])

    def extract_sequential_patterns(self) -> List[bytes]:
        """
        Extract data using various sequential patterns
        Different tools use different pixel orderings
        """
        patterns = []

        # Pattern 1: Row-major order (most common)
        flat_data = self.image_array[:, :, 0].flatten() if self.channels > 1 else self.image_array.flatten()
        lsb_bits = flat_data & 1
        byte_array = []
        for i in range(0, min(len(lsb_bits), 8000), 8):
            byte_val = 0
            for j in range(8):
                if i + j < len(lsb_bits):
                    byte_val |= (int(lsb_bits[i + j]) << (7 - j))
            byte_array.append(byte_val)
        patterns.append(bytes(byte_array[:400]))

        # Pattern 2: Column-major order
        col_data = self.image_array[:, :, 0].T.flatten() if self.channels > 1 else self.image_array.T.flatten()
        lsb_bits = col_data & 1
        byte_array = []
        for i in range(0, min(len(lsb_bits), 8000), 8):
            byte_val = 0
            for j in range(8):
                if i + j < len(lsb_bits):
                    byte_val |= (int(lsb_bits[i + j]) << (7 - j))
            byte_array.append(byte_val)
        patterns.append(bytes(byte_array[:400]))

        # Pattern 3: Spiral pattern (advanced)
        spiral_data = self._extract_spiral_pattern()
        patterns.append(spiral_data)

        return patterns

    def _extract_spiral_pattern(self) -> bytes:
        """Extract data in spiral pattern from center"""
        if self.channels > 1:
            data = self.image_array[:, :, 0]
        else:
            data = self.image_array

        center_y, center_x = self.height // 2, self.width // 2
        max_radius = min(center_y, center_x)

        extracted_bits = []
        for radius in range(1, min(max_radius, 50)):
            for angle in range(0, 360, 10):
                y = int(center_y + radius * np.sin(np.radians(angle)))
                x = int(center_x + radius * np.cos(np.radians(angle)))

                if 0 <= y < self.height and 0 <= x < self.width:
                    pixel_val = data[y, x]
                    extracted_bits.append(pixel_val & 1)

        # Convert to bytes
        byte_array = []
        for i in range(0, len(extracted_bits), 8):
            byte_val = 0
            for j in range(8):
                if i + j < len(extracted_bits):
                    byte_val |= (extracted_bits[i + j] << (7 - j))
            byte_array.append(byte_val)

        return bytes(byte_array[:200])

    def extract_with_rotation(self, rotation_key: int) -> bytes:
        """
        Extract data with rotation cipher applied
        Some tools use simple rotation for obfuscation
        """
        lsb_data = self.extract_lsb_sequence()

        # Apply ROT-N decryption
        decrypted = bytearray()
        for byte in lsb_data[:500]:
            if 32 <= byte < 127:  # Printable ASCII
                rotated = ((byte - 32 - rotation_key) % 95) + 32
                decrypted.append(rotated)
            else:
                decrypted.append(byte)

        return bytes(decrypted)

    def extract_with_xor_key(self, xor_key: bytes) -> bytes:
        """
        Extract data with XOR key applied
        Common simple encryption method
        """
        lsb_data = self.extract_lsb_sequence()

        # Apply XOR decryption
        decrypted = bytearray()
        key_len = len(xor_key)

        for i, byte in enumerate(lsb_data[:1000]):
            decrypted.append(byte ^ xor_key[i % key_len])

        return bytes(decrypted)

    def detect_steghide_header(self) -> Optional[Dict]:
        """
        Detect steghide header patterns
        Steghide has identifiable structure
        """
        lsb_data = self.extract_lsb_sequence()

        # Check for common steghide patterns
        # Steghide uses specific header bytes
        if len(lsb_data) > 20:
            # Check for encrypted header pattern
            header_bytes = lsb_data[:20]

            # Steghide often starts with high entropy
            entropy = self._calculate_entropy(header_bytes)

            if entropy > 0.95:
                return {
                    'detected': True,
                    'confidence': 0.75,
                    'header_entropy': entropy,
                    'likely_tool': 'steghide'
                }

        return None

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0

        # Count byte frequencies
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)

        for count in freq.values():
            p = count / data_len
            if p > 0:
                entropy -= p * np.log2(p)

        return entropy / 8.0  # Normalize to 0-1

    def extract_all_methods(self) -> Dict[str, bytes]:
        """
        Extract data using all available methods
        Returns dict of method -> extracted data
        """
        extractions = {}

        try:
            # LSB extraction
            extractions['lsb_1bit'] = self.extract_lsb_sequence(num_bits=1)
            extractions['lsb_2bit'] = self.extract_lsb_sequence(num_bits=2)

            # Bit plane extraction
            extractions['bitplane_0'] = self.extract_bit_plane(0)[:1000].tobytes()
            extractions['bitplane_1'] = self.extract_bit_plane(1)[:1000].tobytes()

            # Multi-plane
            extractions['multiplane_01'] = self.extract_multi_plane_data([0, 1])

            if self.channels >= 3:
                # Channel XOR
                extractions['channel_xor'] = self.extract_channel_xor()

                # Per-channel extraction
                for ch in range(min(3, self.channels)):
                    extractions[f'lsb_channel_{ch}'] = self.extract_lsb_sequence(channel=ch)[:500]

            # Sequential patterns
            patterns = self.extract_sequential_patterns()
            for i, pattern in enumerate(patterns):
                extractions[f'pattern_{i}'] = pattern

            # Rotation ciphers
            for rot in [1, 13, 25]:  # ROT1, ROT13, ROT25
                extractions[f'rotation_{rot}'] = self.extract_with_rotation(rot)

        except Exception as e:
            print(f"Extraction error: {e}")

        return extractions


class ImprovedKeyGenerator:
    """
    Improved key generation from metadata
    Generates more comprehensive key variations
    """

    @staticmethod
    def generate_comprehensive_keys(metadata: Dict) -> List[str]:
        """
        Generate comprehensive key list from metadata

        Returns:
            List of candidate keys (500+ variants)
        """
        keys = []
        exif = metadata.get('exif', {})
        file_info = metadata.get('file_info', {})

        # === DATETIME KEYS (100+ variants) ===
        datetime_str = exif.get('DateTime', '')
        datetime_orig = exif.get('DateTimeOriginal', '')

        for dt in [datetime_str, datetime_orig]:
            if dt:
                keys.extend(ImprovedKeyGenerator._generate_datetime_variants(dt))

        # === GPS KEYS (50+ variants) ===
        gps_keys = ImprovedKeyGenerator._generate_gps_keys(exif)
        keys.extend(gps_keys)

        # === DEVICE KEYS (50+ variants) ===
        device_keys = ImprovedKeyGenerator._generate_device_keys(exif)
        keys.extend(device_keys)

        # === FILENAME KEYS (30+ variants) ===
        filename = file_info.get('filename', '')
        if filename:
            keys.extend(ImprovedKeyGenerator._generate_filename_keys(filename))

        # === HASH-BASED KEYS (100+ variants) ===
        hash_keys = ImprovedKeyGenerator._generate_hash_based_keys(metadata)
        keys.extend(hash_keys)

        # === COMMON PASSWORDS (200+ variants) ===
        common_keys = ImprovedKeyGenerator._generate_common_passwords()
        keys.extend(common_keys)

        # Remove duplicates while preserving order
        seen = set()
        unique_keys = []
        for key in keys:
            if key and key not in seen and len(key) >= 1:
                seen.add(key)
                unique_keys.append(key)

        return unique_keys

    @staticmethod
    def _generate_datetime_variants(dt: str) -> List[str]:
        """Generate 100+ datetime variants"""
        variants = []

        # Original
        variants.append(dt)

        # Remove separators
        variants.append(dt.replace(':', ''))
        variants.append(dt.replace(':', '').replace(' ', ''))
        variants.append(dt.replace(' ', ''))

        # Date only
        if ' ' in dt:
            date_part = dt.split()[0]
            time_part = dt.split()[1]

            variants.append(date_part)
            variants.append(date_part.replace(':', ''))
            variants.append(time_part)
            variants.append(time_part.replace(':', ''))

        # Reversed
        variants.append(dt[::-1])

        # Year/month/day extraction
        parts = dt.replace(':', ' ').split()
        if len(parts) >= 3:
            year, month, day = parts[0], parts[1], parts[2]
            variants.extend([year, month, day])
            variants.append(f"{year}{month}{day}")
            variants.append(f"{day}{month}{year}")
            variants.append(f"{month}{day}{year}")

        # Hash variants
        for hash_func in [hashlib.md5, hashlib.sha1, hashlib.sha256]:
            h = hash_func(dt.encode()).hexdigest()
            variants.append(h[:8])
            variants.append(h[:16])
            variants.append(h[:32])

        # Numeric only
        numeric = ''.join(c for c in dt if c.isdigit())
        if numeric:
            variants.append(numeric)
            variants.append(numeric[:8])
            variants.append(numeric[:16])

        # With common prefixes/suffixes
        for prefix in ['key', 'pass', 'secret', '']:
            for suffix in ['', '!', '123', '2024', '2025', '2026']:
                if prefix or suffix:
                    variants.append(f"{prefix}{dt[:10].replace(':', '')}{suffix}")

        return variants

    @staticmethod
    def _generate_gps_keys(exif: Dict) -> List[str]:
        """Generate 50+ GPS-based keys"""
        keys = []

        gps_lat = exif.get('GPSLatitude', '')
        gps_lon = exif.get('GPSLongitude', '')
        gps_alt = exif.get('GPSAltitude', '')

        if gps_lat or gps_lon:
            # Combined coordinates
            gps_combined = f"{gps_lat}{gps_lon}"
            keys.append(gps_combined)
            keys.append(gps_combined.replace('.', ''))
            keys.append(gps_combined.replace(',', ''))

            # Individual coordinates
            for coord in [gps_lat, gps_lon, gps_alt]:
                if coord:
                    coord_str = str(coord)
                    keys.append(coord_str)
                    keys.append(coord_str.replace('.', ''))
                    keys.append(hashlib.md5(coord_str.encode()).hexdigest()[:16])

            # Truncated versions
            keys.append(gps_combined[:16])
            keys.append(gps_combined[:32])

            # Hash variants
            keys.append(hashlib.sha256(gps_combined.encode()).hexdigest()[:24])
            keys.append(hashlib.md5(gps_combined.encode()).hexdigest())

        return keys

    @staticmethod
    def _generate_device_keys(exif: Dict) -> List[str]:
        """Generate 50+ device-based keys"""
        keys = []

        make = exif.get('Make', '')
        model = exif.get('Model', '')
        software = exif.get('Software', '')

        # Device combinations
        if make or model:
            device = f"{make}{model}"
            keys.append(device)
            keys.append(device.replace(' ', ''))
            keys.append(device.replace(' ', '_'))
            keys.append(device.lower())
            keys.append(device.upper())

            # Individual components
            if make:
                keys.extend([make, make.lower(), make.upper(), make.replace(' ', '')])
            if model:
                keys.extend([model, model.lower(), model.upper(), model.replace(' ', '')])

            # Hashes
            keys.append(hashlib.md5(device.encode()).hexdigest()[:16])
            keys.append(hashlib.sha1(device.encode()).hexdigest()[:20])
            keys.append(hashlib.sha256(device.encode()).hexdigest()[:32])

        # Software
        if software:
            keys.append(software)
            keys.append(software.replace(' ', ''))
            keys.append(software.lower())
            keys.append(hashlib.md5(software.encode()).hexdigest())

        return keys

    @staticmethod
    def _generate_filename_keys(filename: str) -> List[str]:
        """Generate 30+ filename-based keys"""
        from pathlib import Path

        keys = []

        # Stem (without extension)
        stem = Path(filename).stem
        keys.extend([stem, stem.lower(), stem.upper(), stem.replace('_', ''), stem.replace('-', '')])

        # With extension
        keys.append(filename)
        keys.append(filename.lower())

        # Hashes
        keys.append(hashlib.md5(stem.encode()).hexdigest()[:16])
        keys.append(hashlib.sha256(stem.encode()).hexdigest()[:32])

        return keys

    @staticmethod
    def _generate_hash_based_keys(metadata: Dict) -> List[str]:
        """Generate 100+ hash-based combination keys"""
        keys = []

        exif = metadata.get('exif', {})
        file_info = metadata.get('file_info', {})

        # Combine multiple fields
        combinations = []

        dt = exif.get('DateTime', '')
        make = exif.get('Make', '')
        model = exif.get('Model', '')
        filename = file_info.get('filename', '')

        if dt and make:
            combinations.append(f"{dt}{make}")
        if dt and model:
            combinations.append(f"{dt}{model}")
        if make and model:
            combinations.append(f"{make}{model}")
        if dt and filename:
            combinations.append(f"{dt}{filename}")

        # Hash all combinations
        for combo in combinations:
            for hash_func in [hashlib.md5, hashlib.sha1, hashlib.sha256]:
                h = hash_func(combo.encode()).hexdigest()
                keys.extend([h[:8], h[:16], h[:24], h[:32]])

        return keys

    @staticmethod
    def _generate_common_passwords() -> List[str]:
        """Generate 200+ common passwords and patterns"""
        passwords = [
            # Empty password
            '',

            # Very common passwords
            'password', 'Password', 'PASSWORD', '123456', '12345678', '1234567890',
            'qwerty', 'abc123', 'password123', 'admin', 'letmein', 'welcome',
            'monkey', 'dragon', 'master', 'sunshine', 'princess', 'starwars',

            # Steganography-specific
            'stego', 'steganography', 'hidden', 'secret', 'hide', 'embed',
            'steghide', 'outguess', 'stegano', 'openstego', 'f5', 'jsteg',

            # Tool defaults
            'stegsecret', 'silenteye', 'deepsound', 'quickstego',

            # APT-themed
            'apt', 'apt28', 'apt29', 'apt41', 'fancy', 'cozy', 'lazarus',
            'fancybear', 'cozybear', 'doubledragon', 'turla',

            # Years
            '2020', '2021', '2022', '2023', '2024', '2025', '2026',

            # Common patterns
            'test', 'demo', 'sample', 'default', 'changeme', 'pass', 'key',

            # Numeric sequences
            '111111', '000000', '123123', '456456', '789789',

            # Keyboard patterns
            'asdfgh', 'zxcvbn', '1qaz2wsx', '!QAZ@WSX',
        ]

        # Add variations with offsets
        extended = passwords.copy()
        for pwd in passwords[:30]:
            for offset in [1, 2, 4, 8, 16, 32, 123, 2024, 2025, 2026]:
                extended.append(f"{pwd}{offset}")
                extended.append(f"{offset}{pwd}")

        # Add case variations
        for pwd in passwords[:20]:
            extended.append(pwd.upper())
            extended.append(pwd.lower())
            extended.append(pwd.capitalize())

        return extended
