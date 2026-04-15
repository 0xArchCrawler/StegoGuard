"""
Reliability Manager for StegoGuard Pro
Ensures 100% consistent detection and decryption through retry logic, error handling, and fallbacks
"""
import subprocess
import time
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Callable, Any
import asyncio
import logging

logger = logging.getLogger(__name__)


class ReliabilityManager:
    """
    Manages tool reliability through retries, fallbacks, and graceful degradation
    """

    def __init__(self):
        self.max_retries = 3
        self.retry_delay = 0.5  # seconds
        self.tool_availability_cache = {}
        self._check_tool_availability()

    def _check_tool_availability(self):
        """Check which tools are available on the system"""
        tools = ['steghide', 'zsteg', 'outguess', 'stegdetect', 'binwalk',
                'foremost', 'exiftool', 'strings']

        for tool in tools:
            try:
                result = subprocess.run(
                    ['which', tool],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                self.tool_availability_cache[tool] = result.returncode == 0
            except:
                self.tool_availability_cache[tool] = False

        logger.info(f"Tool availability: {self.tool_availability_cache}")

    def is_tool_available(self, tool: str) -> bool:
        """Check if a tool is available"""
        return self.tool_availability_cache.get(tool, False)

    def run_with_retry(
        self,
        command: List[str],
        timeout: int = 10,
        max_retries: Optional[int] = None,
        tool_name: str = None
    ) -> subprocess.CompletedProcess:
        """
        Run a command with automatic retry on failure

        Args:
            command: Command to execute
            timeout: Timeout in seconds
            max_retries: Maximum retry attempts (uses default if None)
            tool_name: Name of tool for availability check

        Returns:
            CompletedProcess result

        Raises:
            RuntimeError: If all retries fail
        """
        if max_retries is None:
            max_retries = self.max_retries

        # Check tool availability first
        if tool_name and not self.is_tool_available(tool_name):
            raise RuntimeError(f"Tool not available: {tool_name}")

        last_exception = None

        for attempt in range(max_retries):
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
                return result

            except subprocess.TimeoutExpired as e:
                last_exception = e
                logger.warning(f"Command timeout (attempt {attempt + 1}/{max_retries}): {' '.join(command)}")

            except Exception as e:
                last_exception = e
                logger.warning(f"Command failed (attempt {attempt + 1}/{max_retries}): {e}")

            # Wait before retry (exponential backoff)
            if attempt < max_retries - 1:
                time.sleep(self.retry_delay * (2 ** attempt))

        # All retries failed
        raise RuntimeError(f"Command failed after {max_retries} attempts: {last_exception}")

    async def run_with_retry_async(
        self,
        command: List[str],
        timeout: int = 10,
        max_retries: Optional[int] = None,
        tool_name: str = None
    ) -> subprocess.CompletedProcess:
        """Async version of run_with_retry"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.run_with_retry(command, timeout, max_retries, tool_name)
        )

    def safe_temp_extraction(
        self,
        command: List[str],
        timeout: int = 10
    ) -> Optional[bytes]:
        """
        Safely extract data to temp file with automatic cleanup

        Args:
            command: Command that outputs to a file (must have -xf or -o flag)
            timeout: Timeout in seconds

        Returns:
            Extracted data as bytes, or None if extraction failed
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_file = Path(temp_dir) / 'extracted_data.bin'

            # Replace output file in command
            modified_command = []
            skip_next = False
            for i, part in enumerate(command):
                if skip_next:
                    skip_next = False
                    continue

                if part in ['-xf', '-o', '--output'] and i + 1 < len(command):
                    modified_command.append(part)
                    modified_command.append(str(temp_file))
                    skip_next = True  # Skip the original output path
                else:
                    modified_command.append(part)

            try:
                result = self.run_with_retry(modified_command, timeout=timeout)

                # Check if file was created
                if temp_file.exists() and temp_file.stat().st_size > 0:
                    with open(temp_file, 'rb') as f:
                        return f.read()

            except Exception as e:
                logger.debug(f"Safe temp extraction failed: {e}")

        return None

    def extract_with_password_attempts(
        self,
        tool: str,
        image_path: str,
        passwords: List[str],
        timeout_per_attempt: int = 5
    ) -> Optional[Dict[str, Any]]:
        """
        Try extracting with multiple passwords

        Args:
            tool: Tool name (steghide, outguess, etc.)
            image_path: Path to image file
            passwords: List of passwords to try
            timeout_per_attempt: Timeout per password attempt

        Returns:
            Dict with 'success', 'password', 'data' if successful, None if all fail
        """
        if not self.is_tool_available(tool):
            logger.warning(f"Tool not available: {tool}")
            return None

        for password in passwords:
            try:
                if tool == 'steghide':
                    data = self.safe_temp_extraction(
                        ['steghide', 'extract', '-sf', image_path, '-xf', 'temp', '-p', password, '-f'],
                        timeout=timeout_per_attempt
                    )
                elif tool == 'outguess':
                    data = self.safe_temp_extraction(
                        ['outguess', '-k', password, '-r', image_path, 'temp'],
                        timeout=timeout_per_attempt
                    )
                else:
                    continue

                if data and len(data) > 0:
                    return {
                        'success': True,
                        'password': password,
                        'data': data,
                        'tool': tool
                    }

            except Exception as e:
                logger.debug(f"Password attempt failed ({tool}, {password[:5]}...): {e}")
                continue

        return None

    def graceful_tool_call(
        self,
        primary_command: List[str],
        fallback_command: Optional[List[str]] = None,
        timeout: int = 10
    ) -> subprocess.CompletedProcess:
        """
        Call a tool with fallback to alternative if primary fails

        Args:
            primary_command: Primary command to try
            fallback_command: Fallback command if primary fails
            timeout: Timeout in seconds

        Returns:
            CompletedProcess from whichever command succeeded
        """
        try:
            return self.run_with_retry(primary_command, timeout=timeout)
        except RuntimeError:
            if fallback_command:
                logger.info(f"Primary command failed, trying fallback")
                try:
                    return self.run_with_retry(fallback_command, timeout=timeout)
                except RuntimeError:
                    pass

            # Return empty result if both fail
            return subprocess.CompletedProcess(
                args=primary_command,
                returncode=1,
                stdout='',
                stderr='Tool execution failed'
            )

    def format_data_safely(self, data: bytes, max_length: int = 2000) -> str:
        """
        Safely format binary data to string with encoding fallbacks

        Args:
            data: Binary data
            max_length: Maximum length to return

        Returns:
            Safely decoded string
        """
        if not data:
            return ''

        # Try multiple encodings
        encodings = ['utf-8', 'latin-1', 'cp1252', 'ascii']

        for encoding in encodings:
            try:
                decoded = data.decode(encoding, errors='replace')
                return decoded[:max_length]
            except:
                continue

        # Last resort: hex representation
        return data[:max_length].hex()

    def verify_extraction_integrity(self, data: bytes) -> Dict[str, Any]:
        """
        Verify extracted data integrity

        Args:
            data: Extracted data

        Returns:
            Dict with integrity check results
        """
        import hashlib
        import math

        if not data or len(data) == 0:
            return {
                'valid': False,
                'reason': 'Empty data'
            }

        # Calculate entropy to detect corrupted/random data
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1

        entropy = 0
        for count in byte_counts.values():
            prob = count / len(data)
            if prob > 0:
                entropy -= prob * math.log2(prob)

        # Check for suspicious patterns
        is_valid = True
        reason = 'Valid'

        # Too high entropy = possibly corrupted (max entropy for bytes is 8 bits)
        # Random/encrypted data: 7-8 bits, Text: 4-5 bits, Structured: <4 bits
        if entropy > 7.8:
            is_valid = False
            reason = 'Suspiciously high entropy (possibly corrupted)'

        # Check for readable content
        try:
            decoded = data.decode('utf-8', errors='replace')
            printable_ratio = sum(c.isprintable() or c.isspace() for c in decoded) / len(decoded)

            if printable_ratio < 0.1 and len(data) > 100:
                is_valid = False
                reason = 'Low printable character ratio'

        except:
            pass

        return {
            'valid': is_valid,
            'reason': reason,
            'entropy': entropy,
            'size': len(data),
            'sha256': hashlib.sha256(data).hexdigest()[:16]
        }


# Global instance
_reliability_manager = None


def get_reliability_manager() -> ReliabilityManager:
    """Get singleton reliability manager instance"""
    global _reliability_manager
    if _reliability_manager is None:
        _reliability_manager = ReliabilityManager()
    return _reliability_manager
