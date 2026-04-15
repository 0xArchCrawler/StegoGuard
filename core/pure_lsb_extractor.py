"""
Pure Python LSB (Least Significant Bit) Extractor
Replaces external 'zsteg' tool with 100% pip-installable dependencies

This module provides LSB extraction from images without requiring external binaries.
Supports PNG, JPEG, BMP, TIFF formats using only PIL and NumPy.
"""

import numpy as np
from PIL import Image
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import re


class LSBExtractor:
    """
    Extract LSB data from images using pure Python

    Features:
    - Multi-plane extraction (1-bit, 2-bit, 4-bit LSB)
    - Automatic format detection
    - Data marker detection
    - Confidence scoring
    """

    def __init__(self):
        self.supported_formats = {'.png', '.jpg', '.jpeg', '.bmp', '.tiff', '.gif', '.webp'}

    def extract(self, image_path: str, max_planes: int = 4) -> Dict:
        """
        Main extraction method - tries multiple LSB planes

        Args:
            image_path: Path to image file
            max_planes: Maximum LSB planes to extract (1-4)

        Returns:
            Dict with extraction results and confidence scores
        """
        try:
            img_path = Path(image_path)
            if not img_path.exists():
                return {'success': False, 'error': 'File not found'}

            if img_path.suffix.lower() not in self.supported_formats:
                return {'success': False, 'error': 'Unsupported format'}

            # Load image
            img = Image.open(image_path)
            img_array = np.array(img)

            results = {
                'success': True,
                'image_format': img.format,
                'image_size': img.size,
                'extractions': []
            }

            # Try each LSB plane (1-bit, 2-bit, 4-bit)
            for bit_plane in range(1, min(max_planes + 1, 5)):
                extraction = self._extract_lsb_plane(img_array, bit_plane)

                if extraction['data_found']:
                    results['extractions'].append({
                        'bit_plane': bit_plane,
                        'data': extraction['data'],
                        'confidence': extraction['confidence'],
                        'markers': extraction['markers'],
                        'entropy': extraction['entropy']
                    })

            # Sort by confidence
            results['extractions'].sort(key=lambda x: x['confidence'], reverse=True)

            # Best extraction
            if results['extractions']:
                best = results['extractions'][0]
                results['best_extraction'] = best
                results['extracted_data'] = best['data']
                results['confidence'] = best['confidence']
            else:
                results['success'] = False
                results['confidence'] = 0.0
                results['extracted_data'] = b''

            return results

        except Exception as e:
            return {'success': False, 'error': str(e), 'confidence': 0.0}

    def _extract_lsb_plane(self, img_array: np.ndarray, bit_plane: int) -> Dict:
        """
        Extract specific LSB plane from image

        Args:
            img_array: NumPy array of image
            bit_plane: Number of LSB bits to extract (1-4)

        Returns:
            Dict with extracted data and analysis
        """
        try:
            # Handle different image shapes
            if len(img_array.shape) == 3:
                # RGB/RGBA image - flatten all channels
                height, width, channels = img_array.shape
                flat_array = img_array.flatten()
            elif len(img_array.shape) == 2:
                # Grayscale image
                height, width = img_array.shape
                channels = 1
                flat_array = img_array.flatten()
            else:
                return {'data_found': False, 'confidence': 0.0}

            # Extract LSB bits
            lsb_bits = []
            mask = (1 << bit_plane) - 1  # Create mask for N LSB bits

            for pixel_value in flat_array:
                lsb_value = pixel_value & mask

                # Convert to bits
                for i in range(bit_plane):
                    bit = (lsb_value >> i) & 1
                    lsb_bits.append(bit)

            # Convert bits to bytes
            extracted_bytes = self._bits_to_bytes(lsb_bits)

            # Analyze extracted data
            analysis = self._analyze_extracted_data(extracted_bytes)

            # Detect data markers
            markers = self._detect_markers(extracted_bytes)

            # Calculate confidence
            confidence = self._calculate_confidence(
                extracted_bytes,
                analysis,
                markers,
                bit_plane
            )

            return {
                'data_found': confidence > 0.2,
                'data': extracted_bytes,
                'confidence': confidence,
                'markers': markers,
                'entropy': analysis['entropy'],
                'text_ratio': analysis['text_ratio']
            }

        except Exception:
            return {'data_found': False, 'confidence': 0.0}

    def _bits_to_bytes(self, bits: List[int]) -> bytes:
        """Convert list of bits to bytes"""
        try:
            # Pad to byte boundary
            while len(bits) % 8 != 0:
                bits.append(0)

            byte_array = bytearray()
            for i in range(0, len(bits), 8):
                byte_bits = bits[i:i+8]
                byte_value = 0
                for j, bit in enumerate(byte_bits):
                    byte_value |= (bit << j)
                byte_array.append(byte_value)

            return bytes(byte_array)
        except Exception:
            return b''

    def _analyze_extracted_data(self, data: bytes) -> Dict:
        """
        Analyze extracted data for characteristics

        Returns:
            Dict with entropy, text_ratio, etc.
        """
        if not data or len(data) < 10:
            return {'entropy': 0.0, 'text_ratio': 0.0}

        try:
            # Calculate entropy
            byte_counts = np.bincount(np.frombuffer(data[:min(10000, len(data))], dtype=np.uint8), minlength=256)
            probabilities = byte_counts / byte_counts.sum()
            entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))

            # Calculate text ratio (printable ASCII)
            text_bytes = sum(1 for b in data[:min(1000, len(data))] if 32 <= b <= 126 or b in [9, 10, 13])
            text_ratio = text_bytes / min(1000, len(data))

            return {
                'entropy': float(entropy),
                'text_ratio': float(text_ratio)
            }
        except Exception:
            return {'entropy': 0.0, 'text_ratio': 0.0}

    def _detect_markers(self, data: bytes) -> List[Dict]:
        """
        Detect common steganography markers in extracted data

        Returns:
            List of detected markers with positions
        """
        markers = []

        if not data or len(data) < 10:
            return markers

        try:
            # Check first 100 bytes for common markers
            header = data[:min(100, len(data))]

            # PNG signature
            if b'\x89PNG' in header:
                markers.append({'type': 'PNG_SIGNATURE', 'confidence': 0.9})

            # JPEG signature
            if b'\xff\xd8\xff' in header:
                markers.append({'type': 'JPEG_SIGNATURE', 'confidence': 0.9})

            # ZIP signature
            if b'PK\x03\x04' in header or b'PK\x05\x06' in header:
                markers.append({'type': 'ZIP_ARCHIVE', 'confidence': 0.85})

            # RAR signature
            if b'Rar!' in header:
                markers.append({'type': 'RAR_ARCHIVE', 'confidence': 0.85})

            # PDF signature
            if b'%PDF' in header:
                markers.append({'type': 'PDF_FILE', 'confidence': 0.85})

            # Steghide signature
            if b'STEG' in header or b'steghide' in data[:200]:
                markers.append({'type': 'STEGHIDE_MARKER', 'confidence': 0.8})

            # Text file indicators
            try:
                text = data[:500].decode('utf-8', errors='ignore')

                # XML/HTML
                if '<' in text and '>' in text:
                    if '<?xml' in text:
                        markers.append({'type': 'XML_DATA', 'confidence': 0.7})
                    elif '<html' in text.lower():
                        markers.append({'type': 'HTML_DATA', 'confidence': 0.7})

                # JSON
                if text.strip().startswith('{') or text.strip().startswith('['):
                    markers.append({'type': 'JSON_DATA', 'confidence': 0.6})

                # Base64 detection
                b64_pattern = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$', re.MULTILINE)
                if b64_pattern.search(text):
                    markers.append({'type': 'BASE64_ENCODED', 'confidence': 0.65})

            except Exception:
                pass

        except Exception:
            pass

        return markers

    def _calculate_confidence(self, data: bytes, analysis: Dict, markers: List[Dict], bit_plane: int) -> float:
        """
        Calculate confidence score for extraction

        Factors:
        - Entropy (high = encrypted/compressed, medium = text)
        - Text ratio (high = readable text)
        - Markers detected
        - Bit plane used (1-bit more likely than 4-bit)
        """
        if not data or len(data) < 10:
            return 0.0

        confidence = 0.0

        # Entropy scoring
        entropy = analysis.get('entropy', 0.0)
        if 7.0 <= entropy <= 8.0:
            # High entropy - likely encrypted/compressed
            confidence += 0.4
        elif 4.0 <= entropy <= 6.5:
            # Medium entropy - likely text
            confidence += 0.3
        elif entropy > 0.5:
            # Some structure
            confidence += 0.1

        # Text ratio scoring
        text_ratio = analysis.get('text_ratio', 0.0)
        if text_ratio > 0.8:
            # Mostly printable text
            confidence += 0.3
        elif text_ratio > 0.5:
            confidence += 0.2
        elif text_ratio > 0.2:
            confidence += 0.1

        # Marker scoring
        if markers:
            max_marker_conf = max(m['confidence'] for m in markers)
            confidence += max_marker_conf * 0.3

        # Bit plane scoring (1-bit LSB more common)
        if bit_plane == 1:
            confidence += 0.1
        elif bit_plane == 2:
            confidence += 0.05

        # Normalize to 0-1
        confidence = min(1.0, confidence)

        return confidence

    def extract_text_sequences(self, image_path: str, min_length: int = 10) -> List[str]:
        """
        Extract readable text sequences from LSB data

        Args:
            image_path: Path to image
            min_length: Minimum text sequence length

        Returns:
            List of extracted text sequences
        """
        result = self.extract(image_path)

        if not result.get('success'):
            return []

        data = result.get('extracted_data', b'')
        if not data:
            return []

        # Extract printable sequences
        text_sequences = []
        current_sequence = []

        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_sequence.append(chr(byte))
            else:
                if len(current_sequence) >= min_length:
                    text_sequences.append(''.join(current_sequence))
                current_sequence = []

        # Add final sequence
        if len(current_sequence) >= min_length:
            text_sequences.append(''.join(current_sequence))

        return text_sequences


# Convenience function for quick extraction
def extract_lsb(image_path: str) -> Dict:
    """
    Quick LSB extraction function

    Args:
        image_path: Path to image file

    Returns:
        Extraction results dict
    """
    extractor = LSBExtractor()
    return extractor.extract(image_path)
