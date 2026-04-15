"""
Pure Python String Extractor
Replaces external 'strings' command with 100% pip-installable dependencies

This module extracts readable text sequences from binary files without requiring
external binaries. Supports ASCII, UTF-8, and UTF-16 text extraction.
"""

import re
from pathlib import Path
from typing import List, Dict, Optional
import struct


class StringExtractor:
    """
    Extract text strings from binary data using pure Python

    Features:
    - ASCII string extraction
    - UTF-8 string extraction
    - UTF-16 (little/big endian) extraction
    - Pattern detection (JSON, XML, URLs, etc.)
    - Confidence scoring
    """

    def __init__(self, min_length: int = 4):
        """
        Initialize string extractor

        Args:
            min_length: Minimum string length to extract (default: 4)
        """
        self.min_length = min_length

        # Common patterns
        self.patterns = {
            'url': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
            'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
            'ipv4': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'base64': re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'),
            'hex': re.compile(r'[0-9a-fA-F]{32,}'),
            'bitcoin': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
            'ethereum': re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
        }

    def extract_from_file(self, file_path: str) -> Dict:
        """
        Extract strings from a file

        Args:
            file_path: Path to binary file

        Returns:
            Dict with extracted strings and analysis
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                return {'success': False, 'error': 'File not found'}

            # Read file
            with open(file_path, 'rb') as f:
                data = f.read()

            return self.extract_from_bytes(data)

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def extract_from_bytes(self, data: bytes) -> Dict:
        """
        Extract strings from bytes

        Args:
            data: Binary data

        Returns:
            Dict with extracted strings and patterns
        """
        try:
            results = {
                'success': True,
                'total_bytes': len(data),
                'strings': {},
                'patterns': {},
                'statistics': {}
            }

            # Extract ASCII strings
            ascii_strings = self._extract_ascii(data)
            results['strings']['ascii'] = ascii_strings

            # Extract UTF-8 strings
            utf8_strings = self._extract_utf8(data)
            results['strings']['utf8'] = utf8_strings

            # Extract UTF-16 strings
            utf16le_strings = self._extract_utf16(data, 'little')
            utf16be_strings = self._extract_utf16(data, 'big')
            results['strings']['utf16_le'] = utf16le_strings
            results['strings']['utf16_be'] = utf16be_strings

            # Combine unique strings
            all_strings = list(set(
                ascii_strings + utf8_strings + utf16le_strings + utf16be_strings
            ))

            # Detect patterns
            results['patterns'] = self._detect_patterns(all_strings)

            # Statistics
            results['statistics'] = {
                'total_strings': len(all_strings),
                'ascii_count': len(ascii_strings),
                'utf8_count': len(utf8_strings),
                'utf16_count': len(utf16le_strings) + len(utf16be_strings),
                'longest_string': max((len(s) for s in all_strings), default=0),
                'average_length': sum(len(s) for s in all_strings) / len(all_strings) if all_strings else 0
            }

            # All strings combined
            results['all_strings'] = sorted(all_strings, key=len, reverse=True)

            return results

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _extract_ascii(self, data: bytes) -> List[str]:
        """
        Extract ASCII strings from binary data

        Args:
            data: Binary data

        Returns:
            List of ASCII strings
        """
        strings = []
        current_string = []

        for byte in data:
            # Printable ASCII (32-126) plus common whitespace
            if 32 <= byte <= 126:
                current_string.append(chr(byte))
            elif byte in [9, 10, 13]:  # Tab, LF, CR
                current_string.append(chr(byte))
            else:
                # Non-printable - end current string
                if len(current_string) >= self.min_length:
                    strings.append(''.join(current_string).strip())
                current_string = []

        # Add final string
        if len(current_string) >= self.min_length:
            strings.append(''.join(current_string).strip())

        return [s for s in strings if s]  # Remove empty strings

    def _extract_utf8(self, data: bytes) -> List[str]:
        """
        Extract UTF-8 strings from binary data

        Args:
            data: Binary data

        Returns:
            List of UTF-8 strings
        """
        strings = []

        try:
            # Try to decode entire data as UTF-8
            text = data.decode('utf-8', errors='ignore')

            # Split into sequences
            sequences = re.split(r'[\x00-\x1f\x7f-\x9f]+', text)

            for seq in sequences:
                seq = seq.strip()
                if len(seq) >= self.min_length:
                    strings.append(seq)

        except Exception:
            pass

        return strings

    def _extract_utf16(self, data: bytes, endianness: str = 'little') -> List[str]:
        """
        Extract UTF-16 strings from binary data

        Args:
            data: Binary data
            endianness: 'little' or 'big'

        Returns:
            List of UTF-16 strings
        """
        strings = []

        try:
            # Pad data to even length
            if len(data) % 2 != 0:
                data = data + b'\x00'

            # Try to decode as UTF-16
            if endianness == 'little':
                text = data.decode('utf-16-le', errors='ignore')
            else:
                text = data.decode('utf-16-be', errors='ignore')

            # Split into sequences
            sequences = re.split(r'[\x00-\x1f\x7f-\x9f]+', text)

            for seq in sequences:
                seq = seq.strip()
                if len(seq) >= self.min_length:
                    strings.append(seq)

        except Exception:
            pass

        return strings

    def _detect_patterns(self, strings: List[str]) -> Dict:
        """
        Detect specific patterns in extracted strings

        Args:
            strings: List of extracted strings

        Returns:
            Dict with detected patterns
        """
        detected = {
            'urls': [],
            'emails': [],
            'ip_addresses': [],
            'base64': [],
            'hex_sequences': [],
            'bitcoin_addresses': [],
            'ethereum_addresses': [],
            'json_data': [],
            'xml_data': [],
            'sql_queries': [],
            'file_paths': []
        }

        all_text = ' '.join(strings)

        # URLs
        detected['urls'] = list(set(self.patterns['url'].findall(all_text)))

        # Emails
        detected['emails'] = list(set(self.patterns['email'].findall(all_text)))

        # IP addresses
        detected['ip_addresses'] = list(set(self.patterns['ipv4'].findall(all_text)))

        # Bitcoin addresses
        detected['bitcoin_addresses'] = list(set(self.patterns['bitcoin'].findall(all_text)))

        # Ethereum addresses
        detected['ethereum_addresses'] = list(set(self.patterns['ethereum'].findall(all_text)))

        # Base64 sequences
        detected['base64'] = list(set(self.patterns['base64'].findall(all_text)))[:10]  # Limit to 10

        # Hex sequences
        detected['hex_sequences'] = list(set(self.patterns['hex'].findall(all_text)))[:10]  # Limit to 10

        # JSON data
        for s in strings:
            s_strip = s.strip()
            if (s_strip.startswith('{') and s_strip.endswith('}')) or \
               (s_strip.startswith('[') and s_strip.endswith(']')):
                detected['json_data'].append(s[:200])  # Truncate long JSON

        # XML data
        xml_pattern = re.compile(r'<[^>]+>.*?</[^>]+>', re.DOTALL)
        for s in strings:
            if xml_pattern.search(s):
                detected['xml_data'].append(s[:200])  # Truncate long XML

        # SQL queries
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER']
        for s in strings:
            s_upper = s.upper()
            if any(keyword in s_upper for keyword in sql_keywords):
                detected['sql_queries'].append(s)

        # File paths
        path_pattern = re.compile(r'(?:[A-Za-z]:\\|/)[^\s<>"{}|\\^`\[\]]+')
        detected['file_paths'] = list(set(path_pattern.findall(all_text)))

        # Remove empty lists
        detected = {k: v for k, v in detected.items() if v}

        return detected

    def extract_interesting_strings(self, file_path: str) -> Dict:
        """
        Extract only interesting/suspicious strings

        Args:
            file_path: Path to file

        Returns:
            Dict with interesting strings categorized
        """
        result = self.extract_from_file(file_path)

        if not result.get('success'):
            return result

        interesting = {
            'success': True,
            'high_value': [],
            'medium_value': [],
            'low_value': []
        }

        patterns = result.get('patterns', {})

        # High value: Credentials, addresses, etc.
        if patterns.get('urls'):
            interesting['high_value'].extend([
                {'type': 'URL', 'value': url} for url in patterns['urls']
            ])

        if patterns.get('emails'):
            interesting['high_value'].extend([
                {'type': 'Email', 'value': email} for email in patterns['emails']
            ])

        if patterns.get('bitcoin_addresses'):
            interesting['high_value'].extend([
                {'type': 'Bitcoin Address', 'value': addr} for addr in patterns['bitcoin_addresses']
            ])

        if patterns.get('ethereum_addresses'):
            interesting['high_value'].extend([
                {'type': 'Ethereum Address', 'value': addr} for addr in patterns['ethereum_addresses']
            ])

        # Medium value: IP addresses, base64, etc.
        if patterns.get('ip_addresses'):
            interesting['medium_value'].extend([
                {'type': 'IP Address', 'value': ip} for ip in patterns['ip_addresses']
            ])

        if patterns.get('base64'):
            interesting['medium_value'].extend([
                {'type': 'Base64', 'value': b64[:50]} for b64 in patterns['base64'][:5]
            ])

        if patterns.get('json_data'):
            interesting['medium_value'].extend([
                {'type': 'JSON Data', 'value': json[:100]} for json in patterns['json_data'][:3]
            ])

        # Low value: Long strings, file paths
        all_strings = result.get('all_strings', [])
        long_strings = [s for s in all_strings if len(s) > 50][:10]
        interesting['low_value'].extend([
            {'type': 'Long String', 'value': s[:100]} for s in long_strings
        ])

        if patterns.get('file_paths'):
            interesting['low_value'].extend([
                {'type': 'File Path', 'value': path} for path in patterns['file_paths'][:5]
            ])

        return interesting


# Convenience functions
def extract_strings(file_path: str, min_length: int = 4) -> List[str]:
    """
    Quick string extraction function

    Args:
        file_path: Path to file
        min_length: Minimum string length

    Returns:
        List of extracted strings
    """
    extractor = StringExtractor(min_length=min_length)
    result = extractor.extract_from_file(file_path)

    if result.get('success'):
        return result.get('all_strings', [])
    return []


def find_patterns(file_path: str) -> Dict:
    """
    Quick pattern detection function

    Args:
        file_path: Path to file

    Returns:
        Dict with detected patterns
    """
    extractor = StringExtractor()
    result = extractor.extract_from_file(file_path)

    if result.get('success'):
        return result.get('patterns', {})
    return {}
