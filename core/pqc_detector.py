"""
Post-Quantum Cryptography (PQC) Detector for StegoGuard Pro
Detects quantum-resistant cryptographic algorithms in steganographic payloads

Supports:
- Dilithium (ML-DSA) - NIST standard digital signatures
- Kyber (ML-KEM) - NIST standard key encapsulation
- SPHINCS+ (SLH-DSA) - Hash-based signatures
- Lattice-based cryptography patterns

Pure Python implementation using pattern matching and statistical analysis
"""

import logging
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import re

# Configure logger
logger = logging.getLogger(__name__)


class PQCDetector:
    """
    Detect Post-Quantum Cryptography algorithms in data

    Features:
    - Dilithium signature detection (key sizes, signature patterns)
    - Kyber key exchange detection (ciphertext sizes)
    - SPHINCS+ detection (hash-based signatures)
    - Lattice pattern analysis (entropy, modular arithmetic)
    """

    # Known PQC algorithm parameters
    PQC_SIGNATURES = {
        'DILITHIUM2': {
            'public_key_size': 1312,
            'secret_key_size': 2528,
            'signature_size': 2420,
            'security_level': 128
        },
        'DILITHIUM3': {
            'public_key_size': 1952,
            'secret_key_size': 4000,
            'signature_size': 3293,
            'security_level': 192
        },
        'DILITHIUM5': {
            'public_key_size': 2592,
            'secret_key_size': 4864,
            'signature_size': 4595,
            'security_level': 256
        },
        'KYBER512': {
            'public_key_size': 800,
            'secret_key_size': 1632,
            'ciphertext_size': 768,
            'security_level': 128
        },
        'KYBER768': {
            'public_key_size': 1184,
            'secret_key_size': 2400,
            'ciphertext_size': 1088,
            'security_level': 192
        },
        'KYBER1024': {
            'public_key_size': 1568,
            'secret_key_size': 3168,
            'ciphertext_size': 1568,
            'security_level': 256
        },
        'SPHINCS128S': {
            'public_key_size': 32,
            'secret_key_size': 64,
            'signature_size': 7856,
            'security_level': 128
        },
        'SPHINCS256S': {
            'public_key_size': 64,
            'secret_key_size': 128,
            'signature_size': 29792,
            'security_level': 256
        }
    }

    # Common PQC markers in metadata/headers
    PQC_MARKERS = [
        b'DILITHIUM', b'KYBER', b'SPHINCS', b'ML-KEM', b'ML-DSA', b'SLH-DSA',
        b'CRYSTALS', b'FALCON', b'NTRU', b'SABER', b'LATTICE',
        b'post-quantum', b'PQC', b'quantum-resistant'
    ]

    def __init__(self):
        """Initialize PQC detector"""
        pass

    def detect(self, data: bytes, file_path: Optional[str] = None) -> Dict:
        """
        Main detection method

        Args:
            data: Binary data to analyze
            file_path: Optional path to file for additional analysis

        Returns:
            Dict with detection results and confidence scores
        """
        logger.info("Starting PQC detection analysis")
        logger.debug(f"Analyzing {len(data) if data else 0} bytes of data")

        if not data or len(data) < 100:
            logger.debug("Data too small for PQC analysis (< 100 bytes)")
            return {'pqc_detected': False, 'confidence': 0.0}

        results = {
            'pqc_detected': False,
            'confidence': 0.0,
            'algorithms_detected': [],
            'markers_found': [],
            'size_matches': [],
            'lattice_score': 0.0,
            'analysis': {}
        }

        # 1. Check for PQC markers in data
        logger.debug("Checking for PQC algorithm markers")
        markers = self._detect_pqc_markers(data)
        if markers:
            logger.info(f"Found PQC markers: {', '.join(markers)}")
            results['markers_found'] = markers
            results['pqc_detected'] = True
            results['confidence'] += 0.3
        else:
            logger.debug("No PQC markers found")

        # 2. Check for Dilithium signatures
        logger.debug("Checking for Dilithium (ML-DSA) signatures")
        dilithium_score, dilithium_variant = self._detect_dilithium(data)
        if dilithium_score > 0.5:
            logger.info(f"Dilithium detected: {dilithium_variant} with {dilithium_score*100:.1f}% confidence")
            results['algorithms_detected'].append({
                'algorithm': 'Dilithium',
                'variant': dilithium_variant,
                'confidence': dilithium_score,
                'type': 'Digital Signature (ML-DSA)'
            })
            results['pqc_detected'] = True
            results['confidence'] += dilithium_score * 0.4
        else:
            logger.debug(f"No Dilithium detected (score: {dilithium_score*100:.1f}%)")

        # 3. Check for Kyber key exchange
        logger.debug("Checking for Kyber (ML-KEM) key exchange")
        kyber_score, kyber_variant = self._detect_kyber(data)
        if kyber_score > 0.5:
            logger.info(f"Kyber detected: {kyber_variant} with {kyber_score*100:.1f}% confidence")
            results['algorithms_detected'].append({
                'algorithm': 'Kyber',
                'variant': kyber_variant,
                'confidence': kyber_score,
                'type': 'Key Encapsulation (ML-KEM)'
            })
            results['pqc_detected'] = True
            results['confidence'] += kyber_score * 0.4
        else:
            logger.debug(f"No Kyber detected (score: {kyber_score*100:.1f}%)")

        # 4. Check for SPHINCS+ signatures
        logger.debug("Checking for SPHINCS+ (SLH-DSA) signatures")
        sphincs_score, sphincs_variant = self._detect_sphincs(data)
        if sphincs_score > 0.5:
            logger.info(f"SPHINCS+ detected: {sphincs_variant} with {sphincs_score*100:.1f}% confidence")
            results['algorithms_detected'].append({
                'algorithm': 'SPHINCS+',
                'variant': sphincs_variant,
                'confidence': sphincs_score,
                'type': 'Hash-based Signature (SLH-DSA)'
            })
            results['pqc_detected'] = True
            results['confidence'] += sphincs_score * 0.3
        else:
            logger.debug(f"No SPHINCS+ detected (score: {sphincs_score*100:.1f}%)")

        # 5. Lattice pattern analysis
        logger.debug("Analyzing lattice cryptography patterns")
        lattice_score = self._analyze_lattice_patterns(data)
        results['lattice_score'] = lattice_score
        if lattice_score > 0.6:
            logger.info(f"Lattice patterns detected with {lattice_score*100:.1f}% confidence")
            results['pqc_detected'] = True
            results['confidence'] += lattice_score * 0.2
        else:
            logger.debug(f"Weak lattice patterns (score: {lattice_score*100:.1f}%)")

        # Normalize confidence to 0-1
        results['confidence'] = min(1.0, results['confidence'])

        # Add threat assessment
        if results['pqc_detected']:
            threat_level = self._assess_threat_level(results)
            results['threat_level'] = threat_level
            logger.info(f"PQC detection complete: {len(results['algorithms_detected'])} algorithms found, {results['confidence']*100:.1f}% confidence, threat level: {threat_level}")
        else:
            logger.info(f"No PQC detected (final confidence: {results['confidence']*100:.1f}%)")

        return results

    def _detect_pqc_markers(self, data: bytes) -> List[str]:
        """Detect PQC algorithm markers in data"""
        found_markers = []

        for marker in self.PQC_MARKERS:
            if marker in data:
                found_markers.append(marker.decode('utf-8', errors='ignore'))

        return found_markers

    def _detect_dilithium(self, data: bytes) -> Tuple[float, Optional[str]]:
        """
        Detect Dilithium (ML-DSA) signatures

        Dilithium uses lattice-based cryptography with specific key/signature sizes
        """
        confidence = 0.0
        variant = None

        data_len = len(data)

        # Check for exact size matches
        for algo_name, params in self.PQC_SIGNATURES.items():
            if not algo_name.startswith('DILITHIUM'):
                continue

            # Check signature size
            if abs(data_len - params['signature_size']) < 50:
                confidence = 0.85
                variant = algo_name
                break

            # Check public key size
            if abs(data_len - params['public_key_size']) < 50:
                confidence = 0.75
                variant = f"{algo_name} (public key)"
                break

        # Entropy analysis for lattice-based signatures
        if confidence == 0.0:
            entropy = self._calculate_entropy(data[:min(1000, len(data))])
            # Dilithium signatures have high entropy (7.5-7.9)
            if 7.4 <= entropy <= 7.95:
                # Check for polynomial structure
                if self._check_polynomial_structure(data):
                    confidence = 0.6
                    variant = "Dilithium (inferred from structure)"

        return confidence, variant

    def _detect_kyber(self, data: bytes) -> Tuple[float, Optional[str]]:
        """
        Detect Kyber (ML-KEM) key exchange

        Kyber uses module-lattice-based key encapsulation
        """
        confidence = 0.0
        variant = None

        data_len = len(data)

        # Check for exact size matches
        for algo_name, params in self.PQC_SIGNATURES.items():
            if not algo_name.startswith('KYBER'):
                continue

            # Check ciphertext size
            if abs(data_len - params['ciphertext_size']) < 30:
                confidence = 0.90
                variant = algo_name
                break

            # Check public key size
            if abs(data_len - params['public_key_size']) < 30:
                confidence = 0.80
                variant = f"{algo_name} (public key)"
                break

        # Module-LWE pattern detection
        if confidence == 0.0:
            if self._check_module_lwe_pattern(data):
                confidence = 0.65
                variant = "Kyber (inferred from LWE pattern)"

        return confidence, variant

    def _detect_sphincs(self, data: bytes) -> Tuple[float, Optional[str]]:
        """
        Detect SPHINCS+ (SLH-DSA) hash-based signatures

        SPHINCS+ uses stateless hash-based signatures
        """
        confidence = 0.0
        variant = None

        data_len = len(data)

        # Check for exact size matches
        for algo_name, params in self.PQC_SIGNATURES.items():
            if not algo_name.startswith('SPHINCS'):
                continue

            # SPHINCS+ signatures are very large
            if abs(data_len - params['signature_size']) < 100:
                confidence = 0.85
                variant = algo_name
                break

        # Hash-tree structure detection
        if confidence == 0.0 and data_len > 5000:
            if self._check_hash_tree_structure(data):
                confidence = 0.60
                variant = "SPHINCS+ (inferred from hash-tree structure)"

        return confidence, variant

    def _analyze_lattice_patterns(self, data: bytes) -> float:
        """
        Analyze data for lattice cryptography patterns

        Lattice-based crypto shows specific statistical properties
        """
        if len(data) < 256:
            return 0.0

        score = 0.0

        # 1. Entropy check (lattice crypto has 7.4-7.9 entropy)
        entropy = self._calculate_entropy(data[:min(2000, len(data))])
        if 7.3 <= entropy <= 8.0:
            score += 0.3

        # 2. Byte distribution (should be relatively uniform)
        # MEMORY FIX: Convert once and reuse
        sample_size = min(1000, len(data))
        sample_array = np.frombuffer(data[:sample_size], dtype=np.uint8)
        byte_counts = np.bincount(sample_array, minlength=256)
        uniformity = np.std(byte_counts) / (np.mean(byte_counts) + 1)
        if 0.8 <= uniformity <= 1.5:  # Relatively uniform
            score += 0.2

        # 3. Modular arithmetic patterns (check for q-ary values)
        if self._check_modular_patterns(data):
            score += 0.3

        # 4. Polynomial structure
        if self._check_polynomial_structure(data):
            score += 0.2

        return min(1.0, score)

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0

        try:
            byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
            probabilities = byte_counts / len(data)
            entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
            return float(entropy)
        except Exception:
            return 0.0

    def _check_polynomial_structure(self, data: bytes) -> bool:
        """Check for polynomial coefficient patterns"""
        try:
            # MEMORY FIX: Use smaller sample size for large files
            sample_size = min(512, len(data))
            sample = np.frombuffer(data[:sample_size], dtype=np.uint8)

            # Polynomial coefficients often show periodic patterns
            fft = np.fft.fft(sample)
            magnitude = np.abs(fft)

            # MEMORY FIX: Compute stats once
            mag_mean = np.mean(magnitude)
            mag_std = np.std(magnitude)
            threshold = mag_mean + 2 * mag_std

            # Check for dominant frequencies (polynomial structure)
            peaks = magnitude > threshold
            if np.sum(peaks) > 3:
                return True

            return False
        except Exception:
            return False

    def _check_module_lwe_pattern(self, data: bytes) -> bool:
        """Check for Module-LWE (Learning With Errors) patterns"""
        try:
            # MEMORY FIX: Convert once
            sample_size = min(1000, len(data))
            sample = np.frombuffer(data[:sample_size], dtype=np.uint8)

            # Error terms follow discrete Gaussian distribution
            # MEMORY FIX: Compute stats once
            mean = np.mean(sample)
            std = np.std(sample)
            lower_bound = mean - 2*std
            upper_bound = mean + 2*std

            # Gaussian: most values within 2 std deviations
            within_2std = np.sum((sample >= lower_bound) & (sample <= upper_bound))
            ratio = within_2std / len(sample)

            # Should be around 0.95 for Gaussian
            return 0.90 <= ratio <= 0.98

        except Exception:
            return False

    def _check_hash_tree_structure(self, data: bytes) -> bool:
        """Check for hash-tree structure in SPHINCS+ signatures"""
        try:
            # SPHINCS+ uses Merkle trees with hash outputs
            # Check for repeating 32-byte or 64-byte patterns (hash sizes)

            hash_sizes = [32, 64]  # SHA-256, SHA-512
            for hash_size in hash_sizes:
                if len(data) < hash_size * 4:
                    continue

                # Check if data length is multiple of hash size
                if len(data) % hash_size == 0:
                    # Count unique hash-sized blocks
                    blocks = [data[i:i+hash_size] for i in range(0, min(len(data), hash_size*10), hash_size)]
                    unique_blocks = len(set(blocks))

                    # Tree structure has many unique hashes
                    if unique_blocks >= len(blocks) * 0.8:
                        return True

            return False
        except Exception:
            return False

    def _check_modular_patterns(self, data: bytes) -> bool:
        """Check for modular arithmetic patterns (q-ary values)"""
        try:
            # Lattice crypto uses modular arithmetic with prime q
            # Common primes: 3329 (Kyber), 8380417 (Dilithium)

            # MEMORY FIX: Use single conversion and reuse
            sample_size = min(512, len(data))

            # Check if values cluster around modular boundaries
            # Convert to 16-bit values (need even number of bytes)
            if sample_size >= 2:
                # Align to even boundary
                aligned_size = (sample_size // 2) * 2
                values_16 = np.frombuffer(data[:aligned_size], dtype=np.uint16)

                # MEMORY FIX: Compute uniqueness efficiently
                unique_ratio = len(np.unique(values_16)) / len(values_16)

                # Modular patterns show less uniqueness
                return 0.3 <= unique_ratio <= 0.7

            return False
        except Exception:
            return False

    def _assess_threat_level(self, results: Dict) -> str:
        """Assess threat level based on detection results"""
        confidence = results['confidence']
        num_algorithms = len(results['algorithms_detected'])

        if confidence >= 0.85 and num_algorithms >= 2:
            return 'CRITICAL'
        elif confidence >= 0.70:
            return 'HIGH'
        elif confidence >= 0.50:
            return 'MEDIUM'
        else:
            return 'LOW'


# Convenience function
def detect_pqc(data: bytes) -> Dict:
    """
    Quick PQC detection function

    Args:
        data: Binary data to analyze

    Returns:
        Detection results dict
    """
    detector = PQCDetector()
    return detector.detect(data)
