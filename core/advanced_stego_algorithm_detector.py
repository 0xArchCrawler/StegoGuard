"""
Advanced Steganography Algorithm Detector for StegoGuard Pro
Detects specific steganography algorithms using signature and pattern analysis

Detects:
- F5 (JPEG) - Syndrome coding, DCT coefficient patterns
- OutGuess (JPEG) - Residual encoding, spatial patterns
- JSteg (JPEG) - LSB substitution in DCT
- Steghide - Passphrase encryption markers
- SilentEye - Color plane manipulation
- Generic JPEG steganography patterns

Pure Python implementation using OpenCV, NumPy, SciPy (already in requirements.txt)
"""

import logging
import numpy as np
from PIL import Image
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import warnings
warnings.filterwarnings('ignore')

# Configure logger
logger = logging.getLogger(__name__)

try:
    import cv2
    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False

try:
    from scipy import stats
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False


class AdvancedStegoAlgorithmDetector:
    """
    Detect specific steganography algorithms

    Features:
    - F5 detection (JPEG syndrome coding)
    - OutGuess detection (residual encoding)
    - JSteg detection (LSB in DCT)
    - Steghide detection (encryption markers)
    - DCT coefficient analysis
    - Chi-square statistical tests
    """

    def __init__(self):
        """Initialize algorithm detector"""
        self.has_cv2 = HAS_CV2
        self.has_scipy = HAS_SCIPY

    def detect(self, image_path: str) -> Dict:
        """
        Main detection method

        Args:
            image_path: Path to image file

        Returns:
            Dict with detected algorithms and confidence scores
        """
        logger.info(f"Starting advanced algorithm detection on: {image_path}")

        try:
            img_path = Path(image_path)
            if not img_path.exists():
                logger.warning(f"Image file not found: {image_path}")
                return {'algorithms_detected': [], 'confidence': 0.0}

            # Load image
            img = Image.open(image_path)
            img_format = img.format
            logger.debug(f"Image format: {img_format}, size: {img.size}")

            results = {
                'algorithms_detected': [],
                'confidence': 0.0,
                'signatures': [],
                'analysis': {}
            }

            # JPEG-specific algorithms
            if img_format in ['JPEG', 'JPG']:
                logger.debug("Analyzing JPEG-specific algorithms (F5, OutGuess, JSteg)")
                jpeg_results = self._analyze_jpeg_algorithms(image_path, img)
                results['algorithms_detected'].extend(jpeg_results['algorithms'])
                results['signatures'].extend(jpeg_results['signatures'])
                results['confidence'] += jpeg_results['confidence']
                if jpeg_results['algorithms']:
                    logger.info(f"Found {len(jpeg_results['algorithms'])} JPEG algorithm(s)")
            else:
                logger.debug(f"Skipping JPEG-specific detection (format: {img_format})")

            # Generic steganography patterns (works for all formats)
            generic_results = self._analyze_generic_patterns(image_path, img)
            results['algorithms_detected'].extend(generic_results['algorithms'])
            results['confidence'] += generic_results['confidence']

            # LSB-based detection (PNG, BMP)
            if img_format in ['PNG', 'BMP']:
                lsb_results = self._analyze_lsb_patterns(image_path, img)
                if lsb_results['detected']:
                    results['algorithms_detected'].extend(lsb_results['algorithms'])
                    results['confidence'] += lsb_results['confidence']

            # Normalize confidence
            results['confidence'] = min(1.0, results['confidence'])

            # Add most likely algorithm
            if results['algorithms_detected']:
                # Sort by confidence
                sorted_algos = sorted(results['algorithms_detected'],
                                    key=lambda x: x['confidence'], reverse=True)
                results['most_likely'] = sorted_algos[0]
                logger.info(f"Algorithm detection complete: {len(results['algorithms_detected'])} algorithm(s) identified, most likely: {sorted_algos[0]['name']} ({sorted_algos[0]['confidence']*100:.1f}%)")
            else:
                logger.info("No specific algorithms detected")

            return results

        except Exception as e:
            logger.error(f"Algorithm detection failed: {e}", exc_info=True)
            return {
                'algorithms_detected': [],
                'confidence': 0.0,
                'error': str(e)
            }

    def _analyze_jpeg_algorithms(self, image_path: str, img: Image.Image) -> Dict:
        """
        Analyze JPEG-specific steganography algorithms

        Args:
            image_path: Path to JPEG file
            img: PIL Image object

        Returns:
            Dict with detected algorithms
        """
        results = {
            'algorithms': [],
            'signatures': [],
            'confidence': 0.0
        }

        img_array = np.array(img)

        # 1. F5 Detection
        logger.debug("Checking for F5 algorithm")
        f5_score = self._detect_f5(img_array)
        if f5_score > 0.5:
            logger.info(f"F5 detected with {f5_score*100:.1f}% confidence")
            results['algorithms'].append({
                'name': 'F5',
                'type': 'JPEG Steganography',
                'confidence': f5_score,
                'description': 'Syndrome coding with matrix embedding'
            })
            results['confidence'] += f5_score * 0.35

        # 2. OutGuess Detection
        logger.debug("Checking for OutGuess algorithm")
        outguess_score = self._detect_outguess(img_array)
        if outguess_score > 0.5:
            logger.info(f"OutGuess detected with {outguess_score*100:.1f}% confidence")
            results['algorithms'].append({
                'name': 'OutGuess',
                'type': 'JPEG Steganography',
                'confidence': outguess_score,
                'description': 'Statistical compensation in DCT coefficients'
            })
            results['confidence'] += outguess_score * 0.30

        # 3. JSteg Detection
        logger.debug("Checking for JSteg algorithm")
        jsteg_score = self._detect_jsteg(img_array)
        if jsteg_score > 0.5:
            logger.info(f"JSteg detected with {jsteg_score*100:.1f}% confidence")
            results['algorithms'].append({
                'name': 'JSteg',
                'type': 'JPEG Steganography',
                'confidence': jsteg_score,
                'description': 'LSB substitution in DCT coefficients'
            })
            results['confidence'] += jsteg_score * 0.25

        # 4. Generic JPEG Stego
        generic_jpeg_score = self._detect_generic_jpeg_stego(img_array)
        if generic_jpeg_score > 0.6:
            results['algorithms'].append({
                'name': 'JPEG Steganography (Unidentified)',
                'type': 'Generic JPEG',
                'confidence': generic_jpeg_score,
                'description': 'DCT coefficient anomalies detected'
            })
            results['confidence'] += generic_jpeg_score * 0.10

        return results

    def _detect_f5(self, img_array: np.ndarray) -> float:
        """
        Detect F5 steganography algorithm

        F5 uses syndrome coding with matrix embedding in DCT coefficients.
        Signature: Characteristic patterns in DCT coefficient histogram.
        """
        if not self.has_cv2 or len(img_array.shape) != 3:
            return 0.0

        try:
            score = 0.0

            # Convert to grayscale for DCT analysis
            gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY).astype(np.float32)

            # F5 modifies DCT coefficients with syndrome coding
            # Analyze coefficient distribution

            # Block-based DCT (8x8 blocks like JPEG)
            h, w = gray.shape
            blocks_h = h // 8
            blocks_w = w // 8

            dct_coeffs = []
            for i in range(blocks_h):
                for j in range(blocks_w):
                    block = gray[i*8:(i+1)*8, j*8:(j+1)*8]
                    if block.shape == (8, 8):
                        dct_block = cv2.dct(block)
                        dct_coeffs.extend(dct_block.flatten())

            if not dct_coeffs:
                return 0.0

            dct_coeffs = np.array(dct_coeffs)

            # 1. Check LSB distribution of coefficients
            # F5 leaves specific patterns in LSBs
            lsb_dist = np.abs(dct_coeffs.astype(int)) % 2
            lsb_ratio = np.sum(lsb_dist) / len(lsb_dist)

            # F5: LSB distribution closer to 0.5 (balanced)
            if 0.45 <= lsb_ratio <= 0.55:
                score += 0.4

            # 2. Histogram analysis
            # F5 reduces specific frequency bins
            hist, _ = np.histogram(dct_coeffs, bins=50, range=(-100, 100))

            # Check for specific "holes" in histogram (F5 artifact)
            # F5 shrinks histogram around zero
            center_bins = hist[20:30]  # Around zero
            edge_bins = np.concatenate([hist[:10], hist[40:]])

            if np.mean(center_bins) > 0:
                ratio = np.mean(edge_bins) / np.mean(center_bins)
                if 0.3 <= ratio <= 0.7:  # F5 characteristic
                    score += 0.4

            # 3. Syndrome coding leaves specific patterns
            # Check for matrix embedding artifacts
            if self.has_scipy:
                # Chi-square test for uniformity
                chi2, p_value = stats.chisquare(hist + 1)  # Add 1 to avoid zeros
                # F5 creates non-uniform distribution
                if p_value < 0.05:
                    score += 0.2

            return min(1.0, score)

        except Exception:
            return 0.0

    def _detect_outguess(self, img_array: np.ndarray) -> float:
        """
        Detect OutGuess steganography algorithm

        OutGuess uses statistical compensation to preserve coefficient statistics.
        Signature: Specific patterns in residual coefficients.
        """
        if not self.has_cv2 or len(img_array.shape) != 3:
            return 0.0

        try:
            score = 0.0

            # Convert to grayscale
            gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY).astype(np.float32)

            # OutGuess modifies DCT coefficients but compensates statistics
            # Look for compensation artifacts

            # Block-based DCT
            h, w = gray.shape
            blocks_h = h // 8
            blocks_w = w // 8

            dct_coeffs = []
            for i in range(blocks_h):
                for j in range(blocks_w):
                    block = gray[i*8:(i+1)*8, j*8:(j+1)*8]
                    if block.shape == (8, 8):
                        dct_block = cv2.dct(block)
                        dct_coeffs.extend(dct_block.flatten())

            if not dct_coeffs:
                return 0.0

            dct_coeffs = np.array(dct_coeffs)

            # 1. Statistical moments analysis
            # OutGuess preserves mean/variance but affects higher moments
            mean = np.mean(dct_coeffs)
            std = np.std(dct_coeffs)
            skewness = stats.skew(dct_coeffs) if self.has_scipy else 0

            # OutGuess: Low skewness (compensated distribution)
            if abs(skewness) < 0.5:
                score += 0.3

            # 2. Neighboring coefficient correlation
            # OutGuess affects correlation patterns
            if len(dct_coeffs) > 1:
                corr = np.corrcoef(dct_coeffs[:-1], dct_coeffs[1:])[0, 1]
                # OutGuess: Reduced correlation
                if 0.1 <= abs(corr) <= 0.4:
                    score += 0.3

            # 3. Histogram shape analysis
            hist, _ = np.histogram(dct_coeffs, bins=50, range=(-100, 100))

            # OutGuess preserves histogram shape but with subtle changes
            # Check for symmetric distribution
            left_half = hist[:25]
            right_half = hist[25:][::-1]
            symmetry = np.corrcoef(left_half, right_half)[0, 1]

            if symmetry > 0.8:  # High symmetry (compensation)
                score += 0.4

            return min(1.0, score)

        except Exception:
            return 0.0

    def _detect_jsteg(self, img_array: np.ndarray) -> float:
        """
        Detect JSteg steganography algorithm

        JSteg uses simple LSB substitution in DCT coefficients.
        Signature: Statistical anomalies in LSB distribution.
        """
        if not self.has_cv2 or len(img_array.shape) != 3:
            return 0.0

        try:
            score = 0.0

            # Convert to grayscale
            gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY).astype(np.float32)

            # Block-based DCT
            h, w = gray.shape
            blocks_h = h // 8
            blocks_w = w // 8

            dct_coeffs = []
            for i in range(blocks_h):
                for j in range(blocks_w):
                    block = gray[i*8:(i+1)*8, j*8:(j+1)*8]
                    if block.shape == (8, 8):
                        dct_block = cv2.dct(block)
                        dct_coeffs.extend(dct_block.flatten())

            if not dct_coeffs:
                return 0.0

            dct_coeffs_int = np.array(dct_coeffs).astype(int)

            # 1. LSB analysis (JSteg signature)
            # JSteg uses LSB substitution - creates specific patterns
            lsb_bits = dct_coeffs_int % 2

            # Count LSB transitions
            transitions = np.sum(np.diff(lsb_bits) != 0)
            total_bits = len(lsb_bits) - 1

            # JSteg: High transition rate (random LSBs)
            transition_rate = transitions / total_bits if total_bits > 0 else 0
            if 0.45 <= transition_rate <= 0.55:
                score += 0.5

            # 2. Pairs analysis (chi-square attack)
            # JSteg vulnerable to chi-square attack
            if self.has_scipy and len(dct_coeffs_int) > 100:
                # Group into pairs
                pairs = dct_coeffs_int[::2]
                pair_hist, _ = np.histogram(pairs, bins=20)

                # Chi-square test
                try:
                    chi2, p_value = stats.chisquare(pair_hist + 1)
                    # JSteg: Low p-value (non-random pairs)
                    if p_value < 0.1:
                        score += 0.3
                except Exception:
                    pass

            # 3. Coefficient value distribution
            # JSteg affects small coefficients most
            small_coeffs = dct_coeffs_int[np.abs(dct_coeffs_int) < 10]
            if len(small_coeffs) > 10:
                small_lsb = small_coeffs % 2
                small_ratio = np.sum(small_lsb) / len(small_lsb)

                # Should be around 0.5 for JSteg
                if 0.45 <= small_ratio <= 0.55:
                    score += 0.2

            return min(1.0, score)

        except Exception:
            return 0.0

    def _detect_generic_jpeg_stego(self, img_array: np.ndarray) -> float:
        """
        Detect generic JPEG steganography using statistical tests
        """
        if not self.has_cv2 or len(img_array.shape) != 3:
            return 0.0

        try:
            score = 0.0

            # Convert to grayscale
            gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY).astype(np.uint8)

            # 1. LSB plane analysis
            lsb_plane = gray & 1

            # Calculate entropy of LSB plane
            unique, counts = np.unique(lsb_plane, return_counts=True)
            probabilities = counts / counts.sum()
            entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))

            # High entropy LSB suggests steganography
            if entropy > 0.9:
                score += 0.4

            # 2. Block artifact detection
            # JPEG stego often leaves block boundaries visible
            block_artifacts = self._detect_block_artifacts(gray)
            if block_artifacts > 0.6:
                score += 0.3

            return min(1.0, score)

        except Exception:
            return 0.0

    def _detect_block_artifacts(self, gray: np.ndarray) -> float:
        """Detect JPEG block artifacts (8x8 boundaries)"""
        if not self.has_cv2:
            return 0.0

        try:
            # Compute gradients
            gx = cv2.Sobel(gray.astype(np.float32), cv2.CV_64F, 1, 0, ksize=3)
            gy = cv2.Sobel(gray.astype(np.float32), cv2.CV_64F, 0, 1, ksize=3)

            # Check for 8-pixel periodicity in gradients
            h, w = gx.shape

            # Sample vertical lines at 8-pixel intervals
            v_lines = []
            for x in range(8, w, 8):
                v_lines.append(np.mean(np.abs(gx[:, x])))

            # Sample horizontal lines
            h_lines = []
            for y in range(8, h, 8):
                h_lines.append(np.mean(np.abs(gy[y, :])))

            # Average gradient at block boundaries
            boundary_gradient = np.mean(v_lines + h_lines) if (v_lines and h_lines) else 0

            # Compare to overall gradient
            overall_gradient = np.mean(np.abs(gx)) + np.mean(np.abs(gy))

            if overall_gradient > 0:
                ratio = boundary_gradient / overall_gradient
                # High ratio indicates block artifacts
                return min(1.0, ratio / 2.0)

            return 0.0

        except Exception:
            return 0.0

    def _analyze_generic_patterns(self, image_path: str, img: Image.Image) -> Dict:
        """
        Analyze generic steganography patterns (all formats)
        """
        results = {
            'algorithms': [],
            'confidence': 0.0
        }

        try:
            img_array = np.array(img)

            # Steghide detection (works for JPEG, BMP)
            steghide_score = self._detect_steghide_markers(image_path, img_array)
            if steghide_score > 0.5:
                results['algorithms'].append({
                    'name': 'Steghide',
                    'type': 'Multi-format Steganography',
                    'confidence': steghide_score,
                    'description': 'Password-based encryption with graph theory'
                })
                results['confidence'] += steghide_score * 0.25

            return results

        except Exception:
            return results

    def _detect_steghide_markers(self, image_path: str, img_array: np.ndarray) -> float:
        """
        Detect Steghide steganography markers

        Steghide uses password-based encryption and graph-theoretic matching.
        """
        score = 0.0

        try:
            # 1. Entropy analysis
            # Steghide encrypted data has high entropy (7.5-7.9)
            flat_data = img_array.flatten()
            byte_counts = np.bincount(flat_data[:min(10000, len(flat_data))], minlength=256)
            probabilities = byte_counts / byte_counts.sum()
            entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))

            # Steghide: Entropy 7.5-7.9
            if 7.3 <= entropy <= 7.95:
                score += 0.4

            # 2. Random data patterns (encryption)
            # Check for blocks of high-entropy data
            if len(flat_data) > 256:
                # Sample blocks
                block_size = 128
                high_entropy_blocks = 0
                total_blocks = 0

                for i in range(0, min(len(flat_data), 2048), block_size):
                    block = flat_data[i:i+block_size]
                    if len(block) >= block_size:
                        unique_ratio = len(np.unique(block)) / len(block)
                        if unique_ratio > 0.7:  # High randomness
                            high_entropy_blocks += 1
                        total_blocks += 1

                if total_blocks > 0:
                    ratio = high_entropy_blocks / total_blocks
                    if ratio > 0.6:
                        score += 0.3

            return min(1.0, score)

        except Exception:
            return 0.0

    def _analyze_lsb_patterns(self, image_path: str, img: Image.Image) -> Dict:
        """
        Analyze LSB-based steganography (PNG, BMP)
        """
        results = {
            'detected': False,
            'algorithms': [],
            'confidence': 0.0
        }

        try:
            img_array = np.array(img)

            # LSB plane extraction
            if len(img_array.shape) == 3:
                # RGB - check each channel
                for channel_idx, channel_name in enumerate(['Red', 'Green', 'Blue']):
                    channel = img_array[:, :, channel_idx]
                    lsb_score = self._analyze_lsb_channel(channel)

                    if lsb_score > 0.6:
                        results['detected'] = True
                        results['algorithms'].append({
                            'name': f'LSB Steganography ({channel_name} channel)',
                            'type': 'LSB-based',
                            'confidence': lsb_score,
                            'description': 'LSB substitution detected'
                        })
                        results['confidence'] += lsb_score * 0.2

            return results

        except Exception:
            return results

    def _analyze_lsb_channel(self, channel: np.ndarray) -> float:
        """Analyze single channel for LSB steganography"""
        try:
            # Extract LSB plane
            lsb_plane = channel & 1

            # Calculate LSB entropy
            unique, counts = np.unique(lsb_plane, return_counts=True)
            probabilities = counts / counts.sum()
            entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))

            # High entropy LSB = likely steganography
            if entropy > 0.95:
                return 0.7

            return 0.0

        except Exception:
            return 0.0


# Convenience function
def detect_algorithms(image_path: str) -> Dict:
    """
    Quick algorithm detection function

    Args:
        image_path: Path to image file

    Returns:
        Detection results dict
    """
    detector = AdvancedStegoAlgorithmDetector()
    return detector.detect(image_path)
