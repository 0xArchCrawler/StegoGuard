"""
StegoGuard Real Decryption Engine
Professional steganography extraction using real tools
"""

import asyncio
import subprocess
import tempfile
import shutil
from typing import Dict, Optional
from datetime import datetime
from pathlib import Path


class AdvancedDecryptionEngine:
    """
    Real decryption engine using professional steganography tools
    """

    def __init__(self, detection_results: Dict, metadata: Dict, image_data, file_path: str = None):
        self.detection_results = detection_results
        self.metadata = metadata
        self.image_data = image_data
        self.file_path = file_path
        self.temp_dir = None

    async def decrypt(self) -> Dict:
        """
        Perform real decryption using detected steganography tools
        """
        start_time = datetime.now()

        results = {
            'activated': False,
            'success': False,
            'partial_success': False,
            'extracted_data': None,
            'decryption_method': None,
            'time_elapsed': 0,
            'attempts': []
        }

        # Only activate if there are actual detections
        detected_tools = self.detection_results.get('detected_tools', [])
        if not detected_tools:
            return results

        results['activated'] = True
        img_format = self.metadata.get('format', 'Unknown')

        # Create temp directory for extraction
        self.temp_dir = tempfile.mkdtemp(prefix='stego_decrypt_')

        try:
            # Method 1: steghide extraction (JPEG/BMP)
            if 'steghide' in detected_tools and img_format in ['JPEG', 'JPG', 'BMP']:
                steghide_result = await self._try_steghide_extraction()
                results['attempts'].append(steghide_result)
                if steghide_result['success']:
                    results['success'] = True
                    results['extracted_data'] = steghide_result['data']
                    results['decryption_method'] = 'steghide'
                    results['time_elapsed'] = (datetime.now() - start_time).total_seconds()
                    return results

            # Method 2: zsteg extraction (PNG/BMP)
            if 'zsteg' in detected_tools and img_format in ['PNG', 'BMP']:
                zsteg_result = await self._try_zsteg_extraction()
                results['attempts'].append(zsteg_result)
                if zsteg_result['success']:
                    results['success'] = True
                    results['extracted_data'] = zsteg_result['data']
                    results['decryption_method'] = 'zsteg'
                    results['time_elapsed'] = (datetime.now() - start_time).total_seconds()
                    return results

            # Method 3: outguess extraction (JPEG)
            if img_format in ['JPEG', 'JPG']:
                outguess_result = await self._try_outguess_extraction()
                results['attempts'].append(outguess_result)
                if outguess_result['success']:
                    results['success'] = True
                    results['extracted_data'] = outguess_result['data']
                    results['decryption_method'] = 'outguess'
                    results['time_elapsed'] = (datetime.now() - start_time).total_seconds()
                    return results

            # Method 4: jsteg extraction (JPEG)
            if 'stegdetect' in detected_tools and img_format in ['JPEG', 'JPG']:
                jsteg_result = await self._try_jsteg_extraction()
                results['attempts'].append(jsteg_result)
                if jsteg_result['success']:
                    results['success'] = True
                    results['extracted_data'] = jsteg_result['data']
                    results['decryption_method'] = 'jsteg'
                    results['time_elapsed'] = (datetime.now() - start_time).total_seconds()
                    return results

            # If no method succeeded
            results['time_elapsed'] = (datetime.now() - start_time).total_seconds()

        finally:
            # Cleanup temp directory
            if self.temp_dir and Path(self.temp_dir).exists():
                shutil.rmtree(self.temp_dir, ignore_errors=True)

        return results

    async def _try_steghide_extraction(self) -> Dict:
        """Try to extract with steghide using common passwords"""
        result = {'method': 'steghide', 'success': False, 'data': None}

        if not self.file_path or not Path(self.file_path).exists():
            return result

        # Common passwords for steghide
        passwords = ['', 'password', '123456', 'admin', 'secret', 'key', 'steghide', 'hidden', 'stego']

        for pwd in passwords:
            try:
                output_file = Path(self.temp_dir) / f'steghide_output_{pwd if pwd else "empty"}.txt'

                # Try to extract with this password (always use -p flag)
                cmd = subprocess.run(
                    ['steghide', 'extract', '-sf', str(self.file_path), '-xf', str(output_file), '-p', pwd, '-f'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                # Check if extraction succeeded
                if output_file.exists() and output_file.stat().st_size > 0:
                    with open(output_file, 'rb') as f:
                        data = f.read()

                    # Try to decode as text, fallback to hex
                    try:
                        result['data'] = data.decode('utf-8', errors='replace')[:1000]
                    except:
                        result['data'] = data.hex()[:1000]

                    result['success'] = True
                    result['password_used'] = pwd if pwd else '(empty)'
                    return result

            except subprocess.TimeoutExpired:
                continue
            except Exception as e:
                # Continue trying other passwords
                continue

        return result

    async def _try_zsteg_extraction(self) -> Dict:
        """Try to extract with zsteg"""
        result = {'method': 'zsteg', 'success': False, 'data': None}

        if not self.file_path or not Path(self.file_path).exists():
            return result

        try:
            # Run zsteg with extraction mode
            cmd = subprocess.run(
                ['zsteg', '-a', str(self.file_path)],
                capture_output=True,
                text=True,
                timeout=10
            )

            # Look for actual embedded data in output
            output = cmd.stdout

            # Extract LSB data if found
            lines = output.split('\n')
            for line in lines:
                if 'text:' in line or 'file:' in line or 'zlib:' in line:
                    # Found embedded data
                    data = line.split(':', 1)[1].strip() if ':' in line else line.strip()
                    if len(data) > 10:  # Meaningful data
                        result['data'] = data[:1000]
                        result['success'] = True
                        return result

        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        return result

    async def _try_outguess_extraction(self) -> Dict:
        """Try to extract with outguess"""
        result = {'method': 'outguess', 'success': False, 'data': None}

        if not self.file_path or not Path(self.file_path).exists():
            return result

        try:
            output_file = Path(self.temp_dir) / 'outguess_output.txt'

            # Try to extract with outguess
            cmd = subprocess.run(
                ['outguess', '-r', str(self.file_path), str(output_file)],
                capture_output=True,
                text=True,
                timeout=10
            )

            # Check if extraction succeeded
            if output_file.exists() and output_file.stat().st_size > 0:
                with open(output_file, 'rb') as f:
                    data = f.read()

                # Try to decode as text
                try:
                    result['data'] = data.decode('utf-8', errors='replace')[:1000]
                except:
                    result['data'] = data.hex()[:1000]

                result['success'] = True
                return result

        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        return result

    async def _try_jsteg_extraction(self) -> Dict:
        """Try to extract with jsteg"""
        result = {'method': 'jsteg', 'success': False, 'data': None}

        try:
            # Real jsteg extraction would happen here
            result['attempted'] = True
        except:
            pass

        return result
