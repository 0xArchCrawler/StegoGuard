"""
Extraction Workflow Module for StegoGuard Pro
Handles LSB extraction and decryption pipeline
"""
import numpy as np
from PIL import Image
from typing import Dict, List, Optional, Tuple
import struct


class ExtractionWorkflow:
    """
    Complete extraction and parsing workflow
    Extracts LSB data, parses headers, identifies encryption
    """

    def __init__(self):
        self.supported_markers = {
            b'STEG': 'StegoGuard Header',
            b'AES\x00': 'AES Header',
            b'{"': 'JSON',
            b'<?xml': 'XML',
            b'<html': 'HTML',
            b'\x89PNG': 'PNG',
            b'\xFF\xD8\xFF': 'JPEG',
            b'\x00\x00\x00': 'NULL',
        }

        self.eof_markers = [
            b'\xFF\xFE',  # Standard EOF
            b'END\x00',   # Text EOF
            b'\x00\x00\x00\x00',  # NULL terminator
        ]

    def extract_and_parse(
        self,
        image_path: str,
        bit_planes: int = 1,
        max_size: int = 1024 * 1024  # 1MB max
    ) -> Dict:
        """
        Complete extraction pipeline: Extract LSB → Parse header → Return structured data

        Args:
            image_path: Image to extract from
            bit_planes: Number of LSB planes to extract (1, 2, or 4)
            max_size: Maximum bytes to extract

        Returns:
            Dict with extracted data, header info, encryption details
        """
        try:
            # Step 1: Extract raw LSB data
            lsb_result = self.extract_lsb_data(
                image_path=image_path,
                bit_planes=bit_planes,
                max_size=max_size
            )

            if not lsb_result['success']:
                return lsb_result

            extracted_bytes = lsb_result['data']

            # Step 2: Parse header if present
            header_result = self.parse_lsb_header(extracted_bytes)

            # Step 3: Extract payload
            if header_result['has_header']:
                payload_result = self.extract_encrypted_payload(
                    data=extracted_bytes,
                    header_info=header_result
                )
            else:
                # No header, try to find EOF marker
                payload_result = self.find_payload_with_eof(extracted_bytes)

            # Combine results
            result = {
                'success': True,
                'extraction_method': f'{bit_planes}-bit LSB',
                'bytes_extracted': len(extracted_bytes),
                'header_info': header_result,
                'payload_info': payload_result,
                'raw_data': extracted_bytes if not header_result['has_header'] else None
            }

            if payload_result.get('payload'):
                result['payload'] = payload_result['payload']
                result['payload_size'] = len(payload_result['payload'])

            return result

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def extract_lsb_data(
        self,
        image_path: str,
        bit_planes: int = 1,
        max_size: int = 1024 * 1024
    ) -> Dict:
        """
        Extract LSB data from image

        Args:
            image_path: Image file path
            bit_planes: Number of LSB planes to extract (1, 2, or 4)
            max_size: Maximum bytes to extract

        Returns:
            Dict with extracted bytes
        """
        try:
            img = Image.open(image_path)
            img_array = np.array(img)

            # Handle grayscale images
            if len(img_array.shape) < 3:
                height, width = img_array.shape
                channels = 1
                img_array = img_array.reshape(height, width, 1)
            else:
                height, width, channels = img_array.shape

            bits = []
            max_bits = max_size * 8

            for y in range(height):
                for x in range(width):
                    for c in range(channels):
                        if len(bits) >= max_bits:
                            break

                        pixel = img_array[y, x, c] if channels > 1 else img_array[y, x]

                        # Extract N least significant bits
                        for plane in range(bit_planes):
                            if len(bits) >= max_bits:
                                break
                            bits.append((pixel >> plane) & 1)

                    if len(bits) >= max_bits:
                        break
                if len(bits) >= max_bits:
                    break

            # Convert bits to bytes
            data = self._bits_to_bytes(bits)

            return {
                'success': True,
                'data': data,
                'bits_extracted': len(bits),
                'bytes_extracted': len(data),
                'bit_planes': bit_planes
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def parse_lsb_header(self, data: bytes) -> Dict:
        """
        Parse LSB header to identify encryption metadata

        Expected format: [MAGIC(4)][ALGO(1)][KDF(1)][SALT(16)][NONCE(8-16)][TAG(16)?]

        Returns:
            Dict with header information
        """
        try:
            if len(data) < 22:  # Minimum header size
                return {'has_header': False}

            # Check for magic bytes
            magic = data[:4]

            if magic == b'STEG':
                # StegoGuard format header
                algorithm_byte = data[4]
                kdf_byte = data[5]
                salt = data[6:22]  # 16 bytes salt

                algorithm = self._byte_to_algorithm(algorithm_byte)
                kdf_method = self._byte_to_kdf(kdf_byte)

                # Determine nonce size based on algorithm
                if algorithm in ['AES-256-GCM', 'ChaCha20-Poly1305']:
                    nonce_size = 12  # 96-bit nonce
                    nonce = data[22:34]
                    tag_start = 34
                    has_tag = True
                    tag = data[34:50] if len(data) >= 50 else None
                    payload_start = 50
                elif algorithm == 'AES-256-CBC':
                    nonce_size = 16  # 128-bit IV
                    nonce = data[22:38]
                    tag_start = 38
                    has_tag = False
                    tag = None
                    payload_start = 38
                elif algorithm == 'ChaCha20':
                    nonce_size = 8  # 64-bit nonce
                    nonce = data[22:30]
                    tag_start = 30
                    has_tag = False
                    tag = None
                    payload_start = 30
                else:
                    # Unknown algorithm
                    return {'has_header': False}

                return {
                    'has_header': True,
                    'magic': magic,
                    'algorithm': algorithm,
                    'kdf_method': kdf_method,
                    'salt': salt,
                    'nonce': nonce,
                    'tag': tag,
                    'has_tag': has_tag,
                    'payload_start': payload_start,
                    'header_size': payload_start
                }

            elif magic == b'AES\x00':
                # Legacy AES header
                salt = data[4:20]
                nonce = data[20:32]
                tag = data[32:48] if len(data) >= 48 else None

                return {
                    'has_header': True,
                    'magic': magic,
                    'algorithm': 'AES-256-GCM',
                    'kdf_method': 'PBKDF2',
                    'salt': salt,
                    'nonce': nonce,
                    'tag': tag,
                    'has_tag': True,
                    'payload_start': 48,
                    'header_size': 48
                }

            else:
                # No recognized header
                return {'has_header': False}

        except Exception as e:
            return {'has_header': False, 'error': str(e)}

    def extract_encrypted_payload(
        self,
        data: bytes,
        header_info: Dict
    ) -> Dict:
        """
        Extract encrypted payload using header information

        Returns:
            Dict with payload and metadata
        """
        try:
            payload_start = header_info.get('payload_start', 0)
            payload_data = data[payload_start:]

            # Find EOF marker
            eof_pos = len(payload_data)
            for eof_marker in self.eof_markers:
                pos = payload_data.find(eof_marker)
                if pos > 0 and pos < eof_pos:
                    eof_pos = pos

            payload = payload_data[:eof_pos]

            return {
                'success': True,
                'payload': payload,
                'payload_size': len(payload),
                'eof_found': eof_pos < len(payload_data),
                'encryption_detected': True,
                'algorithm': header_info.get('algorithm'),
                'requires_decryption': True
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def find_payload_with_eof(self, data: bytes) -> Dict:
        """
        Find payload by searching for EOF markers (no header present)

        Returns:
            Dict with payload information
        """
        try:
            # Look for known data markers
            for marker, marker_type in self.supported_markers.items():
                pos = data.find(marker)
                if pos >= 0 and pos < 100:
                    # Found marker, extract until EOF
                    eof_pos = len(data)
                    for eof_marker in self.eof_markers:
                        eof = data.find(eof_marker, pos + len(marker))
                        if eof > 0 and eof < eof_pos:
                            eof_pos = eof

                    payload = data[pos:eof_pos]

                    return {
                        'success': True,
                        'payload': payload,
                        'payload_size': len(payload),
                        'marker_type': marker_type,
                        'eof_found': eof_pos < len(data),
                        'encryption_detected': False,
                        'requires_decryption': False
                    }

            # No markers found, return first reasonable chunk
            return {
                'success': True,
                'payload': data[:4096],
                'payload_size': min(4096, len(data)),
                'marker_type': 'Unknown',
                'eof_found': False,
                'encryption_detected': False,
                'requires_decryption': False
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _bits_to_bytes(self, bits: List[int]) -> bytes:
        """Convert bit array to bytes"""
        bytes_list = []
        for i in range(0, len(bits), 8):
            if i + 8 <= len(bits):
                byte = 0
                for j in range(8):
                    byte = (byte << 1) | bits[i + j]
                bytes_list.append(byte)
        return bytes(bytes_list)

    def _byte_to_algorithm(self, byte: int) -> str:
        """Convert algorithm byte to name"""
        algo_map = {
            0x01: 'AES-256-GCM',
            0x02: 'AES-256-CBC',
            0x03: 'ChaCha20',
            0x04: 'ChaCha20-Poly1305'
        }
        return algo_map.get(byte, 'Unknown')

    def _byte_to_kdf(self, byte: int) -> str:
        """Convert KDF byte to name"""
        kdf_map = {
            0x01: 'PBKDF2',
            0x02: 'Scrypt',
            0x03: 'SHA256',
            0x04: 'SHA512'
        }
        return kdf_map.get(byte, 'Unknown')

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if len(data) == 0:
            return 0.0

        entropy = 0.0
        byte_counts = {}

        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1

        import math
        for count in byte_counts.values():
            probability = count / len(data)
            entropy -= probability * math.log2(probability)

        return entropy


# Convenience function for easy import
def extract_from_image(image_path: str, bit_planes: int = 1) -> Dict:
    """
    Quick helper to extract data from steganographic image

    Example:
        result = extract_from_image('encrypted_image.jpg', bit_planes=1)
        if result['success']:
            payload = result.get('payload')
    """
    workflow = ExtractionWorkflow()
    return workflow.extract_and_parse(
        image_path=image_path,
        bit_planes=bit_planes
    )
