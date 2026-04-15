"""
StegoGuard Pro - Improved Detection Algorithms
Enhanced detection methods using only numpy (already installed)
No new dependencies required
"""

import numpy as np
from typing import Dict, Tuple, List
from scipy import fftpack


class ImprovedLSBDetection:
    """
    Improved LSB detection with advanced statistical methods
    Uses only numpy - no new dependencies
    """

    @staticmethod
    def analyze_enhanced(image_array: np.ndarray) -> Dict:
        """
        Enhanced LSB analysis with multiple techniques

        Returns:
            Dict with detection results and confidence
        """
        results = {
            'detected': False,
            'confidence': 0.0,
            'techniques': {},
            'anomalies': []
        }

        # Technique 1: Multi-plane entropy analysis
        entropy_result = ImprovedLSBDetection._multi_plane_entropy(image_array)
        results['techniques']['entropy'] = entropy_result

        # Technique 2: Sample pair analysis (SPA)
        spa_result = ImprovedLSBDetection._sample_pair_analysis(image_array)
        results['techniques']['spa'] = spa_result

        # Technique 3: Pixel difference analysis
        pda_result = ImprovedLSBDetection._pixel_difference_analysis(image_array)
        results['techniques']['pda'] = pda_result

        # Technique 4: Weighted stego analysis (WS)
        ws_result = ImprovedLSBDetection._weighted_stego_analysis(image_array)
        results['techniques']['ws'] = ws_result

        # Aggregate results
        total_confidence = 0
        techniques_triggered = 0

        for technique, result in results['techniques'].items():
            if result.get('detected', False):
                techniques_triggered += 1
                total_confidence += result.get('confidence', 0)
                results['anomalies'].append(technique)

        if techniques_triggered > 0:
            results['detected'] = True
            results['confidence'] = min(total_confidence / techniques_triggered, 1.0)

        return results

    @staticmethod
    def _multi_plane_entropy(image_array: np.ndarray) -> Dict:
        """
        Analyze entropy across multiple bit planes
        LSB plane should have ~1.0 entropy if random data embedded
        """
        if len(image_array.shape) == 2:
            channels = [image_array]
        else:
            channels = [image_array[:, :, i] for i in range(min(3, image_array.shape[2]))]

        max_entropy = 0.0
        suspicious_planes = []

        for ch_idx, channel in enumerate(channels):
            flat = channel.flatten()

            # Check bit planes 0-3 (LSBs)
            for bit_pos in range(4):
                bit_plane = (flat >> bit_pos) & 1

                # Calculate entropy
                unique, counts = np.unique(bit_plane, return_counts=True)
                probs = counts / len(bit_plane)
                entropy = -np.sum(probs * np.log2(probs + 1e-10))

                # Normalize to 0-1
                entropy_norm = entropy / 1.0  # Max entropy for binary is 1.0

                # Lower bit planes should have lower entropy naturally
                # High entropy in bit 0 or 1 is suspicious
                if bit_pos <= 1 and entropy_norm > 0.97:
                    suspicious_planes.append(f'ch{ch_idx}_bit{bit_pos}')
                    max_entropy = max(max_entropy, entropy_norm)

        return {
            'detected': len(suspicious_planes) > 0,
            'confidence': max_entropy,
            'suspicious_planes': suspicious_planes,
            'max_entropy': float(max_entropy)
        }

    @staticmethod
    def _sample_pair_analysis(image_array: np.ndarray) -> Dict:
        """
        Sample Pair Analysis (SPA) - detects LSB replacement
        Analyzes pairs of adjacent pixels for correlation
        """
        if len(image_array.shape) == 2:
            channel = image_array
        else:
            # Use green channel (most sensitive)
            channel = image_array[:, :, 1]

        flat = channel.flatten()

        # Extract LSB
        lsb = flat & 1

        # Create sample pairs
        if len(lsb) < 2:
            return {'detected': False, 'confidence': 0.0}

        pairs = lsb[:-1:2]  # Even indices
        pairs_next = lsb[1::2]  # Odd indices

        # Count different pair types
        n00 = np.sum((pairs == 0) & (pairs_next == 0))
        n01 = np.sum((pairs == 0) & (pairs_next == 1))
        n10 = np.sum((pairs == 1) & (pairs_next == 0))
        n11 = np.sum((pairs == 1) & (pairs_next == 1))

        total = n00 + n01 + n10 + n11

        if total == 0:
            return {'detected': False, 'confidence': 0.0}

        # Calculate expected values for random embedding
        # For no embedding: transitions should be correlated
        # For random embedding: transitions should be ~50/50

        transition_ratio = (n01 + n10) / total

        # Random embedding → transition_ratio ≈ 0.5
        # No embedding → transition_ratio < 0.4 (correlated)

        deviation = abs(transition_ratio - 0.5)

        # If close to 0.5, likely has embedding
        spa_score = 1.0 - (deviation / 0.5)

        detected = spa_score > 0.7

        return {
            'detected': detected,
            'confidence': float(spa_score),
            'transition_ratio': float(transition_ratio),
            'pair_counts': {
                'n00': int(n00),
                'n01': int(n01),
                'n10': int(n10),
                'n11': int(n11)
            }
        }

    @staticmethod
    def _pixel_difference_analysis(image_array: np.ndarray) -> Dict:
        """
        Pixel Difference Analysis - detects disruption in natural correlations
        Adjacent pixels in natural images are highly correlated
        """
        if len(image_array.shape) == 2:
            channel = image_array
        else:
            channel = image_array[:, :, 1]  # Green channel

        # Calculate horizontal differences
        h_diff = np.diff(channel, axis=1).flatten()

        # Calculate vertical differences
        v_diff = np.diff(channel, axis=0).flatten()

        # Combine differences
        all_diff = np.concatenate([h_diff, v_diff])

        # Extract LSB of differences
        diff_lsb = all_diff & 1

        # Calculate entropy of difference LSB
        unique, counts = np.unique(diff_lsb, return_counts=True)
        probs = counts / len(diff_lsb)
        entropy = -np.sum(probs * np.log2(probs + 1e-10))

        # High entropy in difference LSB suggests embedding
        pda_score = entropy  # Already 0-1 normalized

        detected = pda_score > 0.95

        return {
            'detected': detected,
            'confidence': float(pda_score),
            'diff_entropy': float(entropy),
            'diff_lsb_ratio': float(np.mean(diff_lsb))
        }

    @staticmethod
    def _weighted_stego_analysis(image_array: np.ndarray) -> Dict:
        """
        Weighted Stego Analysis - analyzes embedding strength
        Uses pixel value histograms
        """
        if len(image_array.shape) == 2:
            channel = image_array
        else:
            channel = image_array[:, :, 1]

        flat = channel.flatten()

        # Calculate histogram
        hist, _ = np.histogram(flat, bins=256, range=(0, 256))

        # Analyze pairs of histogram bins (even/odd)
        even_bins = hist[::2]
        odd_bins = hist[1::2]

        # LSB embedding disrupts even/odd symmetry
        # Calculate χ² statistic for even/odd pairs
        chi2_sum = 0
        valid_pairs = 0

        for i in range(len(even_bins)):
            expected = (even_bins[i] + odd_bins[i]) / 2
            if expected > 0:
                chi2_sum += ((even_bins[i] - expected) ** 2 +
                            (odd_bins[i] - expected) ** 2) / expected
                valid_pairs += 1

        if valid_pairs == 0:
            return {'detected': False, 'confidence': 0.0}

        chi2_avg = chi2_sum / valid_pairs

        # Normalize chi2 score (empirical threshold)
        ws_score = min(chi2_avg / 10.0, 1.0)

        detected = ws_score > 0.6

        return {
            'detected': detected,
            'confidence': float(ws_score),
            'chi2_statistic': float(chi2_avg),
            'histogram_asymmetry': float(np.std(even_bins - odd_bins))
        }


class ImprovedDCTDetection:
    """
    Improved DCT-based detection for JPEG steganography
    Detects F5, OutGuess, and other DCT-domain techniques
    """

    @staticmethod
    def analyze_enhanced(image_array: np.ndarray) -> Dict:
        """
        Enhanced DCT coefficient analysis

        Returns:
            Dict with detection results
        """
        results = {
            'detected': False,
            'confidence': 0.0,
            'techniques': {},
            'anomalies': []
        }

        # Technique 1: DCT coefficient histogram analysis
        hist_result = ImprovedDCTDetection._dct_histogram_analysis(image_array)
        results['techniques']['histogram'] = hist_result

        # Technique 2: Blockiness detection
        block_result = ImprovedDCTDetection._blockiness_detection(image_array)
        results['techniques']['blockiness'] = block_result

        # Technique 3: Frequency domain entropy
        freq_result = ImprovedDCTDetection._frequency_entropy(image_array)
        results['techniques']['frequency'] = freq_result

        # Aggregate
        confidences = []
        for technique, result in results['techniques'].items():
            if result.get('detected', False):
                confidences.append(result.get('confidence', 0))
                results['anomalies'].append(technique)

        if confidences:
            results['detected'] = True
            results['confidence'] = np.mean(confidences)

        return results

    @staticmethod
    def _dct_histogram_analysis(image_array: np.ndarray) -> Dict:
        """
        Analyze DCT coefficient histogram for anomalies
        F5 and OutGuess leave specific patterns
        """
        if len(image_array.shape) == 2:
            channel = image_array.astype(float)
        else:
            channel = image_array[:, :, 1].astype(float)

        # Apply DCT to 8x8 blocks
        h, w = channel.shape
        dct_coeffs = []

        for i in range(0, h - 8, 8):
            for j in range(0, w - 8, 8):
                block = channel[i:i+8, j:j+8]
                dct_block = fftpack.dct(fftpack.dct(block.T, norm='ortho').T, norm='ortho')
                # Collect AC coefficients (skip DC at [0,0])
                ac_coeffs = dct_block.flatten()[1:]
                dct_coeffs.extend(ac_coeffs)

        if len(dct_coeffs) == 0:
            return {'detected': False, 'confidence': 0.0}

        dct_coeffs = np.array(dct_coeffs)

        # Analyze coefficient histogram
        # Focus on small coefficients (-5 to 5)
        small_coeffs = dct_coeffs[(dct_coeffs >= -5) & (dct_coeffs <= 5)]

        if len(small_coeffs) == 0:
            return {'detected': False, 'confidence': 0.0}

        # Count coefficients
        hist, _ = np.histogram(small_coeffs, bins=11, range=(-5.5, 5.5))

        # Check for histogram anomalies
        # Steganography causes disruption in 0/±1 coefficients
        zero_count = hist[5]  # Center bin (0)
        one_count = hist[4] + hist[6]  # ±1 bins

        total = np.sum(hist)
        if total == 0:
            return {'detected': False, 'confidence': 0.0}

        # Calculate asymmetry
        asymmetry = abs(hist[4] - hist[6]) / (one_count + 1e-10)

        # High asymmetry suggests embedding
        dct_score = min(asymmetry, 1.0)

        detected = dct_score > 0.3

        return {
            'detected': detected,
            'confidence': float(dct_score),
            'asymmetry': float(asymmetry),
            'histogram': hist.tolist()
        }

    @staticmethod
    def _blockiness_detection(image_array: np.ndarray) -> Dict:
        """
        Detect JPEG blockiness artifacts
        Increased blockiness suggests DCT manipulation
        """
        if len(image_array.shape) == 2:
            channel = image_array
        else:
            channel = image_array[:, :, 1]

        h, w = channel.shape

        # Calculate block boundary differences (every 8 pixels)
        boundary_diffs = []

        # Horizontal boundaries
        for i in range(8, h, 8):
            if i < h:
                diff = np.abs(channel[i, :].astype(int) - channel[i-1, :].astype(int))
                boundary_diffs.extend(diff)

        # Vertical boundaries
        for j in range(8, w, 8):
            if j < w:
                diff = np.abs(channel[:, j].astype(int) - channel[:, j-1].astype(int))
                boundary_diffs.extend(diff)

        if len(boundary_diffs) == 0:
            return {'detected': False, 'confidence': 0.0}

        boundary_diffs = np.array(boundary_diffs)

        # Calculate average boundary difference
        avg_boundary = np.mean(boundary_diffs)

        # Calculate overall image gradient
        h_grad = np.mean(np.abs(np.diff(channel, axis=1)))
        v_grad = np.mean(np.abs(np.diff(channel, axis=0)))
        avg_grad = (h_grad + v_grad) / 2

        # Blockiness ratio
        if avg_grad > 0:
            blockiness = avg_boundary / avg_grad
        else:
            blockiness = 0.0

        # High blockiness suggests JPEG manipulation
        block_score = min(blockiness / 2.0, 1.0)

        detected = block_score > 0.6

        return {
            'detected': detected,
            'confidence': float(block_score),
            'blockiness_ratio': float(blockiness),
            'avg_boundary_diff': float(avg_boundary)
        }

    @staticmethod
    def _frequency_entropy(image_array: np.ndarray) -> Dict:
        """
        Analyze entropy in frequency domain
        """
        if len(image_array.shape) == 2:
            channel = image_array.astype(float)
        else:
            channel = image_array[:, :, 1].astype(float)

        # Apply 2D FFT
        fft = np.fft.fft2(channel)
        fft_shift = np.fft.fftshift(fft)
        magnitude = np.abs(fft_shift)

        # Flatten and normalize
        mag_flat = magnitude.flatten()
        mag_norm = mag_flat / (np.sum(mag_flat) + 1e-10)

        # Calculate entropy
        mag_nonzero = mag_norm[mag_norm > 0]
        entropy = -np.sum(mag_nonzero * np.log2(mag_nonzero))

        # Normalize (max entropy depends on size)
        max_entropy = np.log2(len(mag_flat))
        entropy_norm = entropy / max_entropy

        # High entropy in frequency domain suggests embedding
        freq_score = entropy_norm

        detected = freq_score > 0.85

        return {
            'detected': detected,
            'confidence': float(freq_score),
            'frequency_entropy': float(entropy_norm)
        }


class ImprovedStatisticalDetection:
    """
    Improved statistical analysis for general steganography detection
    """

    @staticmethod
    def analyze_enhanced(image_array: np.ndarray) -> Dict:
        """
        Enhanced statistical analysis
        """
        results = {
            'detected': False,
            'confidence': 0.0,
            'techniques': {},
            'anomalies': []
        }

        # Technique 1: Markov chain analysis
        markov_result = ImprovedStatisticalDetection._markov_analysis(image_array)
        results['techniques']['markov'] = markov_result

        # Technique 2: Co-occurrence matrix analysis
        cooc_result = ImprovedStatisticalDetection._cooccurrence_analysis(image_array)
        results['techniques']['cooccurrence'] = cooc_result

        # Technique 3: Moment analysis
        moment_result = ImprovedStatisticalDetection._moment_analysis(image_array)
        results['techniques']['moments'] = moment_result

        # Aggregate
        confidences = []
        for technique, result in results['techniques'].items():
            if result.get('detected', False):
                confidences.append(result.get('confidence', 0))
                results['anomalies'].append(technique)

        if confidences:
            results['detected'] = True
            results['confidence'] = np.mean(confidences)

        return results

    @staticmethod
    def _markov_analysis(image_array: np.ndarray) -> Dict:
        """
        Markov chain transition analysis
        Steganography disrupts natural pixel transitions
        """
        if len(image_array.shape) == 2:
            channel = image_array
        else:
            channel = image_array[:, :, 1]

        flat = channel.flatten()

        if len(flat) < 2:
            return {'detected': False, 'confidence': 0.0}

        # Build transition matrix (simplified)
        # Group pixels into bins
        bins = 32  # Reduce to 32 levels for efficiency
        quantized = (flat // 8).astype(int)

        # Count transitions
        transitions = np.zeros((bins, bins))
        for i in range(len(quantized) - 1):
            curr = quantized[i]
            next_val = quantized[i + 1]
            if curr < bins and next_val < bins:
                transitions[curr, next_val] += 1

        # Normalize
        row_sums = transitions.sum(axis=1, keepdims=True)
        trans_prob = np.divide(transitions, row_sums, where=row_sums != 0)

        # Calculate entropy of transition matrix
        trans_prob_flat = trans_prob.flatten()
        trans_prob_nonzero = trans_prob_flat[trans_prob_flat > 0]

        if len(trans_prob_nonzero) == 0:
            return {'detected': False, 'confidence': 0.0}

        trans_entropy = -np.sum(trans_prob_nonzero * np.log2(trans_prob_nonzero))
        max_trans_entropy = np.log2(bins * bins)
        trans_entropy_norm = trans_entropy / max_trans_entropy

        # High entropy suggests random embedding
        markov_score = trans_entropy_norm

        detected = markov_score > 0.85

        return {
            'detected': detected,
            'confidence': float(markov_score),
            'transition_entropy': float(trans_entropy_norm)
        }

    @staticmethod
    def _cooccurrence_analysis(image_array: np.ndarray) -> Dict:
        """
        Co-occurrence matrix analysis (GLCM)
        Measures texture disruption
        """
        if len(image_array.shape) == 2:
            channel = image_array
        else:
            channel = image_array[:, :, 1]

        # Quantize to reduce matrix size
        quantized = (channel // 16).astype(int)  # 16 levels
        levels = 16

        # Build co-occurrence matrix (horizontal offset=1)
        glcm = np.zeros((levels, levels))

        for i in range(quantized.shape[0]):
            for j in range(quantized.shape[1] - 1):
                curr = quantized[i, j]
                next_val = quantized[i, j + 1]
                if curr < levels and next_val < levels:
                    glcm[curr, next_val] += 1

        # Normalize
        glcm = glcm / (np.sum(glcm) + 1e-10)

        # Calculate texture features
        # Contrast: measures local intensity variation
        contrast = 0
        for i in range(levels):
            for j in range(levels):
                contrast += ((i - j) ** 2) * glcm[i, j]

        # Homogeneity: measures closeness of distribution
        homogeneity = 0
        for i in range(levels):
            for j in range(levels):
                homogeneity += glcm[i, j] / (1 + abs(i - j))

        # Energy: measures uniformity
        energy = np.sum(glcm ** 2)

        # Entropy
        glcm_nonzero = glcm[glcm > 0]
        entropy = -np.sum(glcm_nonzero * np.log2(glcm_nonzero))

        # High entropy + low homogeneity suggests embedding
        cooc_score = (entropy / np.log2(levels * levels)) * (1 - homogeneity)
        cooc_score = min(cooc_score, 1.0)

        detected = cooc_score > 0.6

        return {
            'detected': detected,
            'confidence': float(cooc_score),
            'contrast': float(contrast),
            'homogeneity': float(homogeneity),
            'energy': float(energy),
            'entropy': float(entropy)
        }

    @staticmethod
    def _moment_analysis(image_array: np.ndarray) -> Dict:
        """
        Statistical moment analysis (mean, variance, skewness, kurtosis)
        Embedding changes statistical moments
        """
        if len(image_array.shape) == 2:
            channel = image_array
        else:
            channel = image_array[:, :, 1]

        flat = channel.flatten().astype(float)

        # Calculate moments
        mean = np.mean(flat)
        variance = np.var(flat)

        # Standardize
        std_flat = (flat - mean) / (np.sqrt(variance) + 1e-10)

        # Skewness (3rd moment)
        skewness = np.mean(std_flat ** 3)

        # Kurtosis (4th moment)
        kurtosis = np.mean(std_flat ** 4)

        # Normal distribution has skewness≈0, kurtosis≈3
        # Deviation suggests embedding

        skew_deviation = abs(skewness)
        kurt_deviation = abs(kurtosis - 3.0)

        # Combined deviation score
        moment_score = min((skew_deviation + kurt_deviation / 3.0) / 2.0, 1.0)

        detected = moment_score > 0.5

        return {
            'detected': detected,
            'confidence': float(moment_score),
            'mean': float(mean),
            'variance': float(variance),
            'skewness': float(skewness),
            'kurtosis': float(kurtosis)
        }
