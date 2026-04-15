"""
Blockchain Steganography Detector for StegoGuard Pro
Detects blockchain addresses and decentralized network indicators in steganographic payloads

Supports:
- Bitcoin addresses (P2PKH, P2SH, Bech32, Taproot)
- Ethereum addresses and smart contract bytecode
- IPFS content hashes (CIDv0, CIDv1)
- Monero addresses and view keys
- Transaction hashes and blockchain markers

Pure Python implementation using regex pattern matching
"""

import logging
import re
from typing import Dict, List, Tuple, Optional
from pathlib import Path

# Configure logger
logger = logging.getLogger(__name__)


class BlockchainStegoDetector:
    """
    Detect blockchain-related steganographic content

    Features:
    - Multi-cryptocurrency address detection
    - IPFS hash detection
    - Transaction hash identification
    - Blockchain metadata analysis
    - C2 communication pattern detection
    """

    # Cryptocurrency address patterns
    PATTERNS = {
        # Bitcoin addresses
        'bitcoin_p2pkh': re.compile(r'\b1[a-km-zA-HJ-NP-Z1-9]{25,34}\b'),  # P2PKH (1...)
        'bitcoin_p2sh': re.compile(r'\b3[a-km-zA-HJ-NP-Z1-9]{25,34}\b'),  # P2SH (3...)
        'bitcoin_bech32': re.compile(r'\bbc1[ac-hj-np-z02-9]{39,87}\b'),  # Segwit (bc1...)
        'bitcoin_taproot': re.compile(r'\bbc1p[ac-hj-np-z02-9]{58}\b'),  # Taproot (bc1p...)

        # Ethereum addresses
        'ethereum': re.compile(r'\b0x[a-fA-F0-9]{40}\b'),  # Standard address

        # IPFS hashes
        'ipfs_cidv0': re.compile(r'\bQm[1-9A-HJ-NP-Za-km-z]{44,46}\b'),  # CIDv0
        'ipfs_cidv1': re.compile(r'\bbafy[a-z2-7]{55,59}\b'),  # CIDv1 (base32)

        # Monero
        'monero': re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93,104}\b'),  # Main address

        # Transaction hashes (generic 64 hex chars)
        'tx_hash': re.compile(r'\b[a-fA-F0-9]{64}\b'),

        # Blockchain URLs
        'blockchain_url': re.compile(r'https?://(?:www\.)?(?:blockchain\.com|etherscan\.io|blockchair\.com|ipfs\.io|gateway\.ipfs\.io)/[^\s]+'),

        # ENS domains
        'ens_domain': re.compile(r'\b[a-z0-9-]+\.eth\b'),

        # Cryptocurrency tickers
        'crypto_ticker': re.compile(r'\b(?:BTC|ETH|XMR|LTC|DOGE|ADA|SOL|MATIC|USDT|USDC)\b'),
    }

    # Blockchain-related keywords
    BLOCKCHAIN_KEYWORDS = [
        'bitcoin', 'ethereum', 'blockchain', 'cryptocurrency', 'wallet',
        'private key', 'seed phrase', 'mnemonic', 'satoshi', 'wei', 'gwei',
        'ipfs', 'decentralized', 'smart contract', 'web3', 'metamask',
        'ledger', 'trezor', 'transaction', 'mining', 'block height'
    ]

    def __init__(self):
        """Initialize blockchain detector"""
        pass

    def detect(self, data: bytes, file_path: Optional[str] = None) -> Dict:
        """
        Main detection method

        Args:
            data: Binary data to analyze
            file_path: Optional path to file

        Returns:
            Dict with detection results
        """
        logger.info("Starting blockchain steganography detection")
        logger.debug(f"Analyzing {len(data) if data else 0} bytes of data")

        if not data or len(data) < 20:
            logger.debug("Data too small for blockchain analysis (< 20 bytes)")
            return {'blockchain_detected': False, 'confidence': 0.0}

        results = {
            'blockchain_detected': False,
            'confidence': 0.0,
            'addresses': {
                'bitcoin': [],
                'ethereum': [],
                'ipfs': [],
                'monero': [],
                'other': []
            },
            'transaction_hashes': [],
            'blockchain_urls': [],
            'keywords_found': [],
            'indicators': []
        }

        # Convert to text for analysis
        try:
            text = data.decode('utf-8', errors='ignore')
        except Exception:
            text = data.decode('latin-1', errors='ignore')

        # 1. Detect Bitcoin addresses
        logger.debug("Scanning for Bitcoin addresses")
        bitcoin_results = self._detect_bitcoin(text)
        if bitcoin_results['addresses']:
            logger.info(f"Found {len(bitcoin_results['addresses'])} Bitcoin address(es): {bitcoin_results['variants']}")
            results['addresses']['bitcoin'] = bitcoin_results['addresses']
            results['blockchain_detected'] = True
            results['confidence'] += bitcoin_results['confidence']
            results['indicators'].append({
                'type': 'Bitcoin Address',
                'count': len(bitcoin_results['addresses']),
                'variants': bitcoin_results['variants']
            })
        else:
            logger.debug("No Bitcoin addresses found")

        # 2. Detect Ethereum addresses
        logger.debug("Scanning for Ethereum addresses")
        ethereum_results = self._detect_ethereum(text)
        if ethereum_results['addresses']:
            logger.info(f"Found {len(ethereum_results['addresses'])} Ethereum address(es)")
            results['addresses']['ethereum'] = ethereum_results['addresses']
            results['blockchain_detected'] = True
            results['confidence'] += ethereum_results['confidence']
            results['indicators'].append({
                'type': 'Ethereum Address',
                'count': len(ethereum_results['addresses'])
            })
        else:
            logger.debug("No Ethereum addresses found")

        # 3. Detect IPFS hashes
        logger.debug("Scanning for IPFS content hashes")
        ipfs_results = self._detect_ipfs(text)
        if ipfs_results['hashes']:
            logger.info(f"Found {len(ipfs_results['hashes'])} IPFS hash(es): {ipfs_results['versions']}")
            results['addresses']['ipfs'] = ipfs_results['hashes']
            results['blockchain_detected'] = True
            results['confidence'] += ipfs_results['confidence']
            results['indicators'].append({
                'type': 'IPFS Hash',
                'count': len(ipfs_results['hashes']),
                'versions': ipfs_results['versions']
            })
        else:
            logger.debug("No IPFS hashes found")

        # 4. Detect Monero addresses
        monero_results = self._detect_monero(text)
        if monero_results['addresses']:
            results['addresses']['monero'] = monero_results['addresses']
            results['blockchain_detected'] = True
            results['confidence'] += monero_results['confidence']

        # 5. Detect transaction hashes
        tx_hashes = self._detect_transaction_hashes(text)
        if tx_hashes:
            results['transaction_hashes'] = tx_hashes[:10]  # Limit to 10
            results['blockchain_detected'] = True
            results['confidence'] += 0.15

        # 6. Detect blockchain URLs
        blockchain_urls = self._detect_blockchain_urls(text)
        if blockchain_urls:
            results['blockchain_urls'] = blockchain_urls[:5]  # Limit to 5
            results['blockchain_detected'] = True
            results['confidence'] += 0.20

        # 7. Detect blockchain keywords
        keywords = self._detect_blockchain_keywords(text)
        if keywords:
            results['keywords_found'] = keywords
            results['confidence'] += min(0.15, len(keywords) * 0.03)

        # Normalize confidence to 0-1
        results['confidence'] = min(1.0, results['confidence'])

        # Add threat assessment
        if results['blockchain_detected']:
            threat_assessment = self._assess_threat(results)
            results['threat_assessment'] = threat_assessment
            total_addresses = sum(len(addrs) for addrs in results['addresses'].values() if isinstance(addrs, list))
            logger.info(f"Blockchain detection complete: {total_addresses} address(es) found, {results['confidence']*100:.1f}% confidence, threat: {threat_assessment['level']}")
        else:
            logger.info(f"No blockchain indicators detected (final confidence: {results['confidence']*100:.1f}%)")

        return results

    def _detect_bitcoin(self, text: str) -> Dict:
        """Detect Bitcoin addresses"""
        addresses = []
        variants = []

        # P2PKH (1...)
        p2pkh = list(set(self.PATTERNS['bitcoin_p2pkh'].findall(text)))
        if p2pkh:
            addresses.extend(p2pkh)
            variants.append('P2PKH')

        # P2SH (3...)
        p2sh = list(set(self.PATTERNS['bitcoin_p2sh'].findall(text)))
        if p2sh:
            addresses.extend(p2sh)
            variants.append('P2SH')

        # Bech32 (bc1...)
        bech32 = list(set(self.PATTERNS['bitcoin_bech32'].findall(text)))
        if bech32:
            addresses.extend(bech32)
            variants.append('Bech32')

        # Taproot (bc1p...)
        taproot = list(set(self.PATTERNS['bitcoin_taproot'].findall(text)))
        if taproot:
            addresses.extend(taproot)
            variants.append('Taproot')

        # Calculate confidence based on number and variety
        confidence = 0.0
        if addresses:
            confidence = min(0.40, len(addresses) * 0.10 + len(variants) * 0.05)

        return {
            'addresses': addresses,
            'variants': variants,
            'confidence': confidence
        }

    def _detect_ethereum(self, text: str) -> Dict:
        """Detect Ethereum addresses"""
        addresses = list(set(self.PATTERNS['ethereum'].findall(text)))

        # Validate checksum if possible (basic validation)
        valid_addresses = []
        for addr in addresses:
            # Basic validation: must start with 0x and be 42 chars
            if len(addr) == 42:
                valid_addresses.append(addr)

        confidence = 0.0
        if valid_addresses:
            confidence = min(0.35, len(valid_addresses) * 0.12)

        # Check for ENS domains
        ens_domains = list(set(self.PATTERNS['ens_domain'].findall(text)))
        if ens_domains:
            confidence += 0.10

        return {
            'addresses': valid_addresses,
            'ens_domains': ens_domains,
            'confidence': confidence
        }

    def _detect_ipfs(self, text: str) -> Dict:
        """Detect IPFS content hashes"""
        hashes = []
        versions = []

        # CIDv0 (Qm...)
        cidv0 = list(set(self.PATTERNS['ipfs_cidv0'].findall(text)))
        if cidv0:
            hashes.extend(cidv0)
            versions.append('CIDv0')

        # CIDv1 (bafy...)
        cidv1 = list(set(self.PATTERNS['ipfs_cidv1'].findall(text)))
        if cidv1:
            hashes.extend(cidv1)
            versions.append('CIDv1')

        confidence = 0.0
        if hashes:
            confidence = min(0.30, len(hashes) * 0.15)

        return {
            'hashes': hashes,
            'versions': versions,
            'confidence': confidence
        }

    def _detect_monero(self, text: str) -> Dict:
        """Detect Monero addresses"""
        addresses = list(set(self.PATTERNS['monero'].findall(text)))

        confidence = 0.0
        if addresses:
            confidence = min(0.35, len(addresses) * 0.15)

        return {
            'addresses': addresses,
            'confidence': confidence
        }

    def _detect_transaction_hashes(self, text: str) -> List[str]:
        """Detect transaction hashes (64 hex chars)"""
        hashes = list(set(self.PATTERNS['tx_hash'].findall(text)))

        # Filter out common false positives (e.g., repeated patterns)
        filtered_hashes = []
        for h in hashes:
            # Skip if all same character
            if len(set(h)) > 10:  # At least 10 unique characters
                filtered_hashes.append(h)

        return filtered_hashes[:10]  # Limit to 10

    def _detect_blockchain_urls(self, text: str) -> List[str]:
        """Detect blockchain explorer URLs"""
        urls = list(set(self.PATTERNS['blockchain_url'].findall(text)))
        return urls[:5]  # Limit to 5

    def _detect_blockchain_keywords(self, text: str) -> List[str]:
        """Detect blockchain-related keywords"""
        text_lower = text.lower()
        found_keywords = []

        for keyword in self.BLOCKCHAIN_KEYWORDS:
            if keyword in text_lower:
                found_keywords.append(keyword)

        return found_keywords[:15]  # Limit to 15

    def _assess_threat(self, results: Dict) -> Dict:
        """Assess threat level based on detection results"""
        confidence = results['confidence']

        # Count total addresses
        total_addresses = sum(len(addrs) for addrs in results['addresses'].values() if isinstance(addrs, list))

        threat_level = 'LOW'
        threat_description = ''

        if confidence >= 0.80 and total_addresses >= 5:
            threat_level = 'CRITICAL'
            threat_description = 'Multiple cryptocurrency addresses detected - likely C2 communication or ransom demand'
        elif confidence >= 0.60 and total_addresses >= 3:
            threat_level = 'HIGH'
            threat_description = 'Cryptocurrency addresses detected - possible ransomware or crypto-jacking'
        elif confidence >= 0.40:
            threat_level = 'MEDIUM'
            threat_description = 'Blockchain indicators detected - possible covert channel'
        else:
            threat_level = 'LOW'
            threat_description = 'Weak blockchain indicators - may be false positive'

        # Check for IPFS + cryptocurrency combo (ransomware pattern)
        if results['addresses']['ipfs'] and (results['addresses']['bitcoin'] or results['addresses']['ethereum']):
            threat_level = 'CRITICAL'
            threat_description = 'IPFS + cryptocurrency detected - strong ransomware/C2 indicator'

        return {
            'level': threat_level,
            'description': threat_description,
            'total_addresses': total_addresses,
            'confidence': confidence
        }


# Convenience function
def detect_blockchain(data: bytes) -> Dict:
    """
    Quick blockchain detection function

    Args:
        data: Binary data to analyze

    Returns:
        Detection results dict
    """
    detector = BlockchainStegoDetector()
    return detector.detect(data)
