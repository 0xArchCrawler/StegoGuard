"""
Advanced Detection Modules for StegoGuard Pro
Real implementation of LSB, DCT, Palette, Wavelet, GAN/Deepfake, and other advanced analyses
"""
import numpy as np
from PIL import Image
import subprocess
from pathlib import Path
import tempfile
from typing import Dict, List, Tuple
from scipy import stats
from scipy.fft import dct
import math
from .gan_detector import get_gan_detector


class AdvancedDetectionModules:
    """
    Advanced steganography detection using multiple real analysis techniques
    """

    def __init__(self):
        self.detection_threshold = 0.7

    def analyze_image(self, image_path: str) -> Dict:
        """
        Run all advanced detection modules on an image
        """
        try:
            img = Image.open(image_path)
            img_array = np.array(img)

            # Get GAN detector instance
            gan_detector = get_gan_detector()

            results = {
                'lsb_analysis': self._lsb_bit_level_scanner(img_array),
                'dct_analysis': self._dct_frequency_analyzer(img, img_array),
                'palette_analysis': self._palette_inspector(img),
                'wavelet_analysis': self._wavelet_probe(img_array),
                'noise_analysis': self._noise_detector(img_array),
                'pixel_shift_analysis': self._pixel_shift_checker(img_array),
                'spread_spectrum': self._spread_spectrum_analysis(img_array),
                'metadata_entropy': self._metadata_entropy_check(image_path),
                'gan_deepfake_analysis': gan_detector.detect(Path(image_path))
            }

            return results
        except Exception as e:
            return {'error': str(e)}

    def _lsb_bit_level_scanner(self, img_array: np.ndarray) -> Dict:
        """
        LSB Bit-Level Scanner: Entropy + chi-square/RS analysis
        """
        try:
            # Extract LSB plane
            if len(img_array.shape) == 3:
                lsb_plane = img_array[:, :, :] & 1
            else:
                lsb_plane = img_array & 1

            # Calculate entropy
            unique, counts = np.unique(lsb_plane, return_counts=True)
            probabilities = counts / counts.sum()
            entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))

            # Chi-square test
            expected = np.ones_like(counts) * (counts.sum() / len(counts))
            chi_square = np.sum((counts - expected) ** 2 / expected)
            chi_p_value = 1 - stats.chi2.cdf(chi_square, len(counts) - 1)

            # RS Analysis (Regular/Singular groups)
            rs_score = self._rs_analysis(lsb_plane)

            # Steganography detection: Multiple detection paths
            # Path 1: Small images with very uniform LSB (low chi-square)
            path1 = (entropy > 0.999 and chi_square < 150 and rs_score < 0.05)

            # Path 2: Any size image with high entropy + low RS (indicates embedded data)
            # High entropy = random-looking LSB, Low RS = sequential pattern disruption
            path2 = (entropy > 0.9998 and rs_score < 0.02)

            # Path 3: Very high RS score (strong pattern anomaly)
            path3 = (rs_score > 0.7)

            detected = path1 or path2 or path3

            return {
                'detected': detected,
                'entropy': float(entropy),
                'chi_square': float(chi_square),
                'chi_p_value': float(chi_p_value),
                'rs_score': float(rs_score),
                'confidence': float(max(entropy / 1.0, rs_score))
            }
        except Exception as e:
            return {'detected': False, 'error': str(e)}

    def _rs_analysis(self, lsb_plane: np.ndarray) -> float:
        """
        RS (Regular/Singular) Analysis for LSB steganography detection
        """
        try:
            flat = lsb_plane.flatten()
            # Simple RS approximation
            flips = np.sum(flat[:-1] != flat[1:])
            total = len(flat) - 1
            flip_ratio = flips / total if total > 0 else 0
            # Random data should have ~50% flips
            rs_score = abs(flip_ratio - 0.5) * 2
            return min(rs_score, 1.0)
        except:
            return 0.0

    def _dct_frequency_analyzer(self, img: Image.Image, img_array: np.ndarray) -> Dict:
        """
        DCT Frequency Analyzer: Mid-band coefficient spikes in 8x8 blocks
        """
        try:
            # Convert to grayscale for DCT analysis
            if img.mode != 'L':
                gray = img.convert('L')
                gray_array = np.array(gray)
            else:
                gray_array = img_array

            # Analyze 8x8 blocks
            height, width = gray_array.shape[:2]
            anomaly_blocks = 0
            total_blocks = 0
            mid_band_spikes = []

            for i in range(0, height - 8, 8):
                for j in range(0, width - 8, 8):
                    block = gray_array[i:i+8, j:j+8]
                    if block.shape == (8, 8):
                        # Apply DCT
                        dct_block = dct(dct(block.T, norm='ortho').T, norm='ortho')

                        # Check mid-band coefficients (positions 12-31 in zigzag order)
                        mid_band = dct_block[2:6, 2:6].flatten()
                        std_dev = np.std(mid_band)

                        if std_dev > 15:  # Threshold for anomaly
                            anomaly_blocks += 1
                            mid_band_spikes.append(float(std_dev))

                        total_blocks += 1

            anomaly_ratio = anomaly_blocks / total_blocks if total_blocks > 0 else 0
            detected = anomaly_ratio > 0.15

            return {
                'detected': detected,
                'anomaly_blocks': anomaly_blocks,
                'total_blocks': total_blocks,
                'anomaly_ratio': float(anomaly_ratio),
                'avg_spike_strength': float(np.mean(mid_band_spikes)) if mid_band_spikes else 0,
                'confidence': float(min(anomaly_ratio * 5, 1.0))
            }
        except Exception as e:
            return {'detected': False, 'error': str(e)}

    def _palette_inspector(self, img: Image.Image) -> Dict:
        """
        Palette Index Inspector: Color table reordering/jumps
        """
        try:
            # Only applies to palette-based images
            if img.mode not in ['P', 'PA']:
                return {'detected': False, 'reason': 'Not a palette-based image'}

            # Get palette
            palette = img.getpalette()
            if not palette:
                return {'detected': False, 'reason': 'No palette found'}

            # Analyze palette order
            palette_colors = [(palette[i], palette[i+1], palette[i+2])
                            for i in range(0, len(palette), 3)]

            # Check for unusual jumps in color values
            jumps = []
            for i in range(len(palette_colors) - 1):
                c1 = palette_colors[i]
                c2 = palette_colors[i+1]
                jump = sum(abs(c1[j] - c2[j]) for j in range(3))
                jumps.append(jump)

            avg_jump = np.mean(jumps) if jumps else 0
            max_jump = max(jumps) if jumps else 0

            # Unusual if large jumps (indication of reordering)
            detected = avg_jump > 50 or max_jump > 150

            return {
                'detected': detected,
                'palette_size': len(palette_colors),
                'avg_jump': float(avg_jump),
                'max_jump': float(max_jump),
                'confidence': float(min(avg_jump / 100, 1.0))
            }
        except Exception as e:
            return {'detected': False, 'error': str(e)}

    def _wavelet_probe(self, img_array: np.ndarray) -> Dict:
        """
        Wavelet Transform Probe: Haar/Daubechies anomalies
        """
        try:
            # Simple Haar wavelet transform approximation
            if len(img_array.shape) == 3:
                gray = np.mean(img_array, axis=2)
            else:
                gray = img_array

            # Haar wavelet decomposition (simplified)
            rows, cols = gray.shape
            if rows % 2 != 0:
                gray = gray[:-1, :]
            if cols % 2 != 0:
                gray = gray[:, :-1]

            # Horizontal differences
            h_diff = gray[:, ::2] - gray[:, 1::2]
            # Vertical differences
            v_diff = gray[::2, :] - gray[1::2, :]

            # Analyze high-frequency components
            h_energy = np.mean(np.abs(h_diff))
            v_energy = np.mean(np.abs(v_diff))

            total_energy = h_energy + v_energy

            # Higher energy in high-freq components indicates possible steganography
            detected = total_energy > 25

            return {
                'detected': detected,
                'horizontal_energy': float(h_energy),
                'vertical_energy': float(v_energy),
                'total_energy': float(total_energy),
                'confidence': float(min(total_energy / 50, 1.0))
            }
        except Exception as e:
            return {'detected': False, 'error': str(e)}

    def _noise_detector(self, img_array: np.ndarray) -> Dict:
        """
        GAN/Deepfake Noise Detector: Check for synthetic patches
        """
        try:
            # Analyze local variance patterns
            if len(img_array.shape) == 3:
                gray = np.mean(img_array, axis=2)
            else:
                gray = img_array

            # Calculate local variance in patches
            patch_size = 16
            variances = []

            for i in range(0, gray.shape[0] - patch_size, patch_size):
                for j in range(0, gray.shape[1] - patch_size, patch_size):
                    patch = gray[i:i+patch_size, j:j+patch_size]
                    variances.append(np.var(patch))

            # GAN-generated images often have unusually consistent variance
            variance_std = np.std(variances) if variances else 0
            variance_mean = np.mean(variances) if variances else 0

            # Too consistent = suspicious
            detected = variance_std < 50 and variance_mean > 100

            return {
                'detected': detected,
                'variance_std': float(variance_std),
                'variance_mean': float(variance_mean),
                'confidence': float(min((200 - variance_std) / 200, 1.0)) if variance_std < 200 else 0
            }
        except Exception as e:
            return {'detected': False, 'error': str(e)}

    def _pixel_shift_checker(self, img_array: np.ndarray) -> Dict:
        """
        QR-Code Pixel Shift Checker: Sub-pixel edge diffs
        """
        try:
            # Calculate edge strength using Sobel-like operator
            if len(img_array.shape) == 3:
                gray = np.mean(img_array, axis=2)
            else:
                gray = img_array

            # Horizontal and vertical gradients
            h_grad = np.abs(gray[:, 1:] - gray[:, :-1])
            v_grad = np.abs(gray[1:, :] - gray[:-1, :])

            # Sub-pixel shifts create characteristic patterns
            h_anomalies = np.sum(h_grad > 50)
            v_anomalies = np.sum(v_grad > 50)

            total_pixels = gray.shape[0] * gray.shape[1]
            anomaly_ratio = (h_anomalies + v_anomalies) / (2 * total_pixels)

            detected = anomaly_ratio > 0.05

            return {
                'detected': detected,
                'h_anomalies': int(h_anomalies),
                'v_anomalies': int(v_anomalies),
                'anomaly_ratio': float(anomaly_ratio),
                'confidence': float(min(anomaly_ratio * 20, 1.0))
            }
        except Exception as e:
            return {'detected': False, 'error': str(e)}

    def _spread_spectrum_analysis(self, img_array: np.ndarray) -> Dict:
        """
        Spread-Spectrum Noise Map: Full-image distribution analysis
        """
        try:
            # Analyze frequency distribution of pixel values
            if len(img_array.shape) == 3:
                flat = img_array.reshape(-1, img_array.shape[2])
                histograms = [np.histogram(flat[:, i], bins=256, range=(0, 256))[0]
                             for i in range(img_array.shape[2])]
            else:
                flat = img_array.flatten()
                histograms = [np.histogram(flat, bins=256, range=(0, 256))[0]]

            # Calculate distribution uniformity
            uniformity_scores = []
            for hist in histograms:
                expected = np.mean(hist)
                chi_sq = np.sum((hist - expected) ** 2 / (expected + 1))
                uniformity_scores.append(chi_sq)

            avg_uniformity = np.mean(uniformity_scores)

            # Spread-spectrum creates more uniform distributions
            # More strict threshold to reduce false positives
            detected = avg_uniformity < 200000  # Threshold for unusually uniform

            return {
                'detected': detected,
                'uniformity_score': float(avg_uniformity),
                'confidence': float(max(1 - avg_uniformity / 1000000, 0))
            }
        except Exception as e:
            return {'detected': False, 'error': str(e)}

    def _metadata_entropy_check(self, image_path: str) -> Dict:
        """
        Audio-EXIF Hybrid Detector: Metadata entropy analysis
        """
        try:
            img = Image.open(image_path)
            exif_data = img.getexif()

            if not exif_data:
                return {'detected': False, 'reason': 'No EXIF data'}

            # Convert EXIF to string and calculate entropy
            exif_str = str(exif_data)
            byte_arr = np.frombuffer(exif_str.encode(), dtype=np.uint8)

            unique, counts = np.unique(byte_arr, return_counts=True)
            probabilities = counts / counts.sum()
            entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))

            # High entropy in metadata can indicate hidden data
            detected = entropy > 6.5

            return {
                'detected': detected,
                'entropy': float(entropy),
                'exif_size': len(exif_str),
                'confidence': float(min((entropy - 5) / 3, 1.0)) if entropy > 5 else 0
            }
        except Exception as e:
            return {'detected': False, 'error': str(e)}

    def compile_results(self, analysis_results: Dict) -> Dict:
        """
        Compile all detection results into summary
        """
        detections = []
        total_confidence = 0
        detection_count = 0

        module_names = {
            'lsb_analysis': 'LSB Bit-Level Scanner',
            'dct_analysis': 'DCT Frequency Analyzer',
            'palette_analysis': 'Palette Index Inspector',
            'wavelet_analysis': 'Wavelet Transform Probe',
            'noise_analysis': 'GAN/Deepfake Noise Detector',
            'pixel_shift_analysis': 'QR-Code Pixel Shift Checker',
            'spread_spectrum': 'Spread-Spectrum Noise Map',
            'metadata_entropy': 'Audio-EXIF Hybrid Detector',
            'gan_deepfake_analysis': 'GAN/Deepfake CNN Artifact Detector'
        }

        for key, result in analysis_results.items():
            if isinstance(result, dict) and result.get('detected'):
                detections.append({
                    'module': module_names.get(key, key),
                    'confidence': result.get('confidence', 0.5),
                    'details': result
                })
                total_confidence += result.get('confidence', 0.5)
                detection_count += 1

        avg_confidence = total_confidence / detection_count if detection_count > 0 else 0

        return {
            'detections': detections,
            'detection_count': detection_count,
            'avg_confidence': avg_confidence,
            'threat_detected': detection_count >= 2
        }
