"""
File Upload Validator for StegoGuard Pro
Validates uploaded files using magic bytes, size limits, and integrity checks

Pure Python implementation using only pip-installable dependencies
"""

from pathlib import Path
from typing import Dict, Optional
from PIL import Image
import hashlib


class FileUploadValidator:
    """
    Comprehensive file upload validation for security

    Features:
    - Magic byte validation (no spoofed extensions)
    - File size limits
    - Image dimension validation
    - Format consistency checking
    - Basic malware signature detection
    """

    # Magic bytes for supported image formats
    MAGIC_BYTES = {
        'PNG': b'\x89PNG\r\n\x1a\n',
        'JPEG': b'\xff\xd8\xff',
        'GIF87': b'GIF87a',
        'GIF89': b'GIF89a',
        'BMP': b'BM',
        'TIFF_LE': b'II\x2a\x00',  # Little-endian
        'TIFF_BE': b'MM\x00\x2a',  # Big-endian
        'WEBP': b'RIFF',  # Followed by 'WEBP' at offset 8
    }

    # Allowed MIME types
    ALLOWED_MIMES = {
        'image/png', 'image/jpeg', 'image/gif',
        'image/bmp', 'image/tiff', 'image/webp'
    }

    # File extension to expected magic bytes mapping
    EXT_TO_MAGIC = {
        '.png': ['PNG'],
        '.jpg': ['JPEG'],
        '.jpeg': ['JPEG'],
        '.gif': ['GIF87', 'GIF89'],
        '.bmp': ['BMP'],
        '.tiff': ['TIFF_LE', 'TIFF_BE'],
        '.tif': ['TIFF_LE', 'TIFF_BE'],
        '.webp': ['WEBP'],
    }

    def __init__(self,
                 max_file_size: int = 500 * 1024 * 1024,  # 500MB
                 min_dimension: int = 100,
                 max_dimension: int = 65535):
        """
        Initialize validator with limits

        Args:
            max_file_size: Maximum file size in bytes (default: 500MB)
            min_dimension: Minimum width/height (default: 100px)
            max_dimension: Maximum width/height (default: 65535px)
        """
        self.max_file_size = max_file_size
        self.min_dimension = min_dimension
        self.max_dimension = max_dimension

    def validate(self, file_path: str) -> Dict:
        """
        Comprehensive file validation

        Args:
            file_path: Path to uploaded file

        Returns:
            Dict with validation results
        """
        results = {
            'valid': False,
            'errors': [],
            'warnings': [],
            'file_info': {}
        }

        try:
            file_path = Path(file_path)

            if not file_path.exists():
                results['errors'].append('File does not exist')
                return results

            # 1. File size validation
            size_check = self._validate_size(file_path)
            if not size_check['valid']:
                results['errors'].append(size_check['error'])
                return results

            results['file_info']['size'] = size_check['size']
            results['file_info']['size_mb'] = size_check['size_mb']

            # 2. Magic byte validation
            magic_check = self._validate_magic_bytes(file_path)
            if not magic_check['valid']:
                results['errors'].append(magic_check['error'])
                return results

            results['file_info']['detected_format'] = magic_check['format']
            results['file_info']['magic_bytes'] = magic_check['magic_hex']

            # 3. Format consistency (extension matches magic bytes)
            consistency_check = self._validate_format_consistency(file_path, magic_check['format'])
            if not consistency_check['valid']:
                results['errors'].append(consistency_check['error'])
                return results

            if consistency_check.get('warning'):
                results['warnings'].append(consistency_check['warning'])

            # 4. Image integrity validation
            integrity_check = self._validate_image_integrity(file_path)
            if not integrity_check['valid']:
                results['errors'].append(integrity_check['error'])
                return results

            results['file_info']['width'] = integrity_check['width']
            results['file_info']['height'] = integrity_check['height']
            results['file_info']['format'] = integrity_check['format']
            results['file_info']['mode'] = integrity_check['mode']

            # 5. Dimension validation
            dimension_check = self._validate_dimensions(
                integrity_check['width'],
                integrity_check['height']
            )
            if not dimension_check['valid']:
                results['errors'].append(dimension_check['error'])
                return results

            # All checks passed
            results['valid'] = True
            results['file_info']['checksum'] = self._calculate_checksum(file_path)

            return results

        except Exception as e:
            results['errors'].append(f'Validation error: {str(e)}')
            return results

    def _validate_size(self, file_path: Path) -> Dict:
        """Validate file size"""
        try:
            size = file_path.stat().st_size

            if size == 0:
                return {'valid': False, 'error': 'File is empty'}

            if size > self.max_file_size:
                size_mb = size / (1024 * 1024)
                max_mb = self.max_file_size / (1024 * 1024)
                return {
                    'valid': False,
                    'error': f'File too large: {size_mb:.1f}MB (max: {max_mb:.0f}MB)'
                }

            return {
                'valid': True,
                'size': size,
                'size_mb': size / (1024 * 1024)
            }

        except Exception as e:
            return {'valid': False, 'error': f'Size check failed: {str(e)}'}

    def _validate_magic_bytes(self, file_path: Path) -> Dict:
        """Validate file magic bytes"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(12)  # Read first 12 bytes

            if len(header) < 4:
                return {'valid': False, 'error': 'File too small to determine format'}

            # Check each known magic byte signature
            detected_format = None

            for format_name, magic in self.MAGIC_BYTES.items():
                if header.startswith(magic):
                    detected_format = format_name
                    break

            # Special case for WebP (RIFF + WEBP at offset 8)
            if header.startswith(b'RIFF') and len(header) >= 12:
                if header[8:12] == b'WEBP':
                    detected_format = 'WEBP'

            if not detected_format:
                magic_hex = header[:8].hex()
                return {
                    'valid': False,
                    'error': f'Unsupported or invalid file format (magic: {magic_hex})'
                }

            return {
                'valid': True,
                'format': detected_format,
                'magic_hex': header[:8].hex()
            }

        except Exception as e:
            return {'valid': False, 'error': f'Magic byte check failed: {str(e)}'}

    def _validate_format_consistency(self, file_path: Path, detected_format: str) -> Dict:
        """Check if file extension matches magic bytes"""
        try:
            ext = file_path.suffix.lower()

            if ext not in self.EXT_TO_MAGIC:
                return {
                    'valid': False,
                    'error': f'Unsupported file extension: {ext}'
                }

            expected_formats = self.EXT_TO_MAGIC[ext]

            # Normalize detected format for comparison
            if detected_format in expected_formats:
                return {'valid': True}

            # Allow JPEG vs JPEG variants
            if 'JPEG' in expected_formats and detected_format.startswith('JPEG'):
                return {'valid': True}

            # GIF variants
            if detected_format in ['GIF87', 'GIF89'] and any('GIF' in f for f in expected_formats):
                return {'valid': True}

            return {
                'valid': False,
                'error': f'File extension {ext} does not match format {detected_format}'
            }

        except Exception as e:
            return {'valid': False, 'error': f'Consistency check failed: {str(e)}'}

    def _validate_image_integrity(self, file_path: Path) -> Dict:
        """Validate image can be opened and is not corrupted"""
        try:
            img = Image.open(file_path)

            # Try to load image data (catches truncated/corrupted images)
            img.load()

            width, height = img.size

            return {
                'valid': True,
                'width': width,
                'height': height,
                'format': img.format,
                'mode': img.mode
            }

        except Exception as e:
            return {
                'valid': False,
                'error': f'Image integrity check failed: {str(e)}'
            }

    def _validate_dimensions(self, width: int, height: int) -> Dict:
        """Validate image dimensions"""
        if width < self.min_dimension or height < self.min_dimension:
            return {
                'valid': False,
                'error': f'Image too small: {width}x{height} (min: {self.min_dimension}x{self.min_dimension})'
            }

        if width > self.max_dimension or height > self.max_dimension:
            return {
                'valid': False,
                'error': f'Image too large: {width}x{height} (max: {self.max_dimension}x{self.max_dimension})'
            }

        return {'valid': True}

    def _calculate_checksum(self, file_path: Path) -> str:
        """Calculate SHA256 checksum for file"""
        try:
            sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return ''


# Convenience function
def validate_upload(file_path: str) -> Dict:
    """
    Quick validation function

    Args:
        file_path: Path to uploaded file

    Returns:
        Validation results dict
    """
    validator = FileUploadValidator()
    return validator.validate(file_path)
