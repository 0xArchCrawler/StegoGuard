"""
GAN/Deepfake Artifact Detector
Detects AI-generated images using frequency domain analysis and CNN-inspired features
Zero dependencies beyond NumPy/SciPy (already in Kali Linux)
"""
import numpy as np
from pathlib import Path
from PIL import Image
import logging
from typing import Dict, Tuple, Optional
import warnings
warnings.filterwarnings('ignore')

try:
    from scipy import fftpack, ndimage
    from scipy.signal import convolve2d
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False
    logging.warning("SciPy not available - GAN detector will use NumPy fallback")


class GANDetector:
    """
    GAN/Deepfake artifact detector using frequency domain analysis
    Detects common GAN signatures: checkerboard patterns, spectral anomalies, upsampling artifacts
    """

    def __init__(self):
        """Initialize GAN detector with pre-computed thresholds"""
        self.name = "GAN/Deepfake Artifact Detector"

        # Pre-trained thresholds (derived from GAN artifact research)
        self.thresholds = {
            'checkerboard_power': 0.15,      # Checkerboard pattern power threshold
            'high_freq_ratio': 0.25,          # High frequency to low frequency ratio
            'spectral_regularity': 0.12,      # Spectral pattern regularity
            'upsampling_score': 0.18,         # Upsampling artifact score
            'combined_score': 0.35            # Combined confidence threshold
        }

        # CNN-inspired filter bank (Gabor-like filters for texture analysis)
        self.filter_bank = self._create_filter_bank()

    def _create_filter_bank(self) -> list:
        """Create CNN-inspired Gabor filter bank for texture detection"""
        filters = []

        # Multiple scales and orientations (mimics CNN conv layers)
        scales = [3, 5, 7]
        orientations = [0, 45, 90, 135]

        for scale in scales:
            for angle in orientations:
                # Create Gabor-like filter
                filter_kernel = self._gabor_kernel(scale, angle)
                filters.append(filter_kernel)

        return filters

    def _gabor_kernel(self, size: int, angle: float, frequency: float = 0.5) -> np.ndarray:
        """Create Gabor filter kernel (CNN-like convolutional filter)"""
        angle_rad = np.deg2rad(angle)
        cos_angle = np.cos(angle_rad)
        sin_angle = np.sin(angle_rad)

        # Create coordinate grid
        y, x = np.meshgrid(np.arange(-size//2, size//2+1), np.arange(-size//2, size//2+1))

        # Rotate coordinates
        x_rot = x * cos_angle + y * sin_angle
        y_rot = -x * sin_angle + y * cos_angle

        # Gabor function
        sigma = size / 6.0
        gaussian = np.exp(-(x_rot**2 + y_rot**2) / (2 * sigma**2))
        sinusoid = np.cos(2 * np.pi * frequency * x_rot)

        gabor = gaussian * sinusoid
        return gabor / np.sum(np.abs(gabor))

    def detect(self, image_path: Path) -> Dict:
        """
        Detect GAN/Deepfake artifacts in image
        Returns detection result with confidence score
        """
        try:
            # Load image
            img = Image.open(image_path)

            # Convert to RGB if needed
            if img.mode != 'RGB':
                img = img.convert('RGB')

            img_array = np.array(img)

            # Extract features using multiple detection methods
            checkerboard_score = self._detect_checkerboard_pattern(img_array)
            frequency_score = self._analyze_frequency_domain(img_array)
            texture_score = self._analyze_texture_artifacts(img_array)
            upsampling_score = self._detect_upsampling_artifacts(img_array)

            # Combine scores (CNN-like weighted combination)
            combined_score = (
                checkerboard_score * 0.3 +
                frequency_score * 0.3 +
                texture_score * 0.2 +
                upsampling_score * 0.2
            )

            # Determine if GAN-generated
            is_gan_generated = combined_score > self.thresholds['combined_score']

            # Calculate confidence
            confidence = min(combined_score / self.thresholds['combined_score'], 1.0)

            result = {
                'detected': is_gan_generated,
                'confidence': float(confidence),
                'combined_score': float(combined_score),
                'details': {
                    'checkerboard_score': float(checkerboard_score),
                    'frequency_score': float(frequency_score),
                    'texture_score': float(texture_score),
                    'upsampling_score': float(upsampling_score)
                },
                'artifacts_found': []
            }

            # Document detected artifacts
            if checkerboard_score > self.thresholds['checkerboard_power']:
                result['artifacts_found'].append('Checkerboard pattern detected (common in GANs)')

            if frequency_score > self.thresholds['high_freq_ratio']:
                result['artifacts_found'].append('Spectral anomalies in frequency domain')

            if upsampling_score > self.thresholds['upsampling_score']:
                result['artifacts_found'].append('Upsampling artifacts detected')

            if texture_score > self.thresholds['spectral_regularity']:
                result['artifacts_found'].append('Unnatural texture regularity')

            return result

        except Exception as e:
            logging.error(f"GAN detection error: {e}")
            return {
                'detected': False,
                'confidence': 0.0,
                'error': str(e)
            }

    def _detect_checkerboard_pattern(self, img: np.ndarray) -> float:
        """
        Detect checkerboard artifacts (common in GANs due to deconvolution)
        Uses frequency domain analysis to find periodic patterns
        """
        # Convert to grayscale
        if len(img.shape) == 3:
            gray = np.mean(img, axis=2)
        else:
            gray = img

        # Apply 2D FFT
        if SCIPY_AVAILABLE:
            freq_domain = fftpack.fft2(gray)
            freq_shifted = fftpack.fftshift(freq_domain)
        else:
            # NumPy fallback
            freq_domain = np.fft.fft2(gray)
            freq_shifted = np.fft.fftshift(freq_domain)

        magnitude = np.abs(freq_shifted)

        # Focus on mid-frequency range where checkerboard appears
        h, w = magnitude.shape
        center_y, center_x = h // 2, w // 2

        # Define checkerboard frequency regions (typically at Nyquist/2)
        y_range = slice(center_y - h//8, center_y + h//8)
        x_range = slice(center_x - w//8, center_x + w//8)

        mid_freq_region = magnitude[y_range, x_range]

        # Calculate checkerboard pattern power
        # Look for peaks at specific frequencies
        mean_power = np.mean(magnitude)
        max_mid_freq = np.max(mid_freq_region)

        # Normalize
        checkerboard_power = (max_mid_freq / mean_power) if mean_power > 0 else 0

        # Scale to 0-1 range
        return min(checkerboard_power / 10.0, 1.0)

    def _analyze_frequency_domain(self, img: np.ndarray) -> float:
        """
        Analyze frequency domain for GAN signatures
        Real images have natural frequency distribution, GANs show anomalies
        """
        # Convert to grayscale
        if len(img.shape) == 3:
            gray = np.mean(img, axis=2)
        else:
            gray = img

        # Apply DCT (Discrete Cosine Transform) - more efficient than FFT
        if SCIPY_AVAILABLE:
            dct_coeffs = fftpack.dct(fftpack.dct(gray, axis=0, norm='ortho'),
                                     axis=1, norm='ortho')
        else:
            # NumPy fallback with basic DCT approximation
            from numpy.fft import rfft2
            dct_coeffs = np.abs(rfft2(gray))

        # Split into frequency bands
        h, w = dct_coeffs.shape

        # Low frequency (top-left)
        low_freq = dct_coeffs[:h//4, :w//4]

        # High frequency (bottom-right)
        high_freq = dct_coeffs[3*h//4:, 3*w//4:]

        # Calculate power ratio
        low_power = np.sum(np.abs(low_freq)**2)
        high_power = np.sum(np.abs(high_freq)**2)

        # GANs often have unusual high-to-low frequency ratios
        ratio = high_power / low_power if low_power > 0 else 0

        # Normalize to 0-1 range
        return min(ratio * 5.0, 1.0)

    def _analyze_texture_artifacts(self, img: np.ndarray) -> float:
        """
        Apply CNN-inspired filter bank to detect texture artifacts
        GANs produce unnaturally regular textures
        """
        # Convert to grayscale
        if len(img.shape) == 3:
            gray = np.mean(img, axis=2)
        else:
            gray = img

        # Resize for faster processing
        from PIL import Image as PILImage
        gray_img = PILImage.fromarray(gray.astype(np.uint8))
        gray_resized = gray_img.resize((256, 256))
        gray_array = np.array(gray_resized)

        # Apply filter bank (CNN-like convolution)
        responses = []

        for filter_kernel in self.filter_bank:
            if SCIPY_AVAILABLE:
                response = convolve2d(gray_array, filter_kernel, mode='valid')
            else:
                # NumPy fallback
                response = self._numpy_convolve2d(gray_array, filter_kernel)

            responses.append(np.std(response))

        # Calculate regularity score
        # Natural images: high variance in filter responses
        # GAN images: low variance (too regular)
        response_variance = np.var(responses)
        regularity_score = 1.0 / (1.0 + response_variance)  # Inverse - high regularity = high score

        return min(regularity_score * 2.0, 1.0)

    def _numpy_convolve2d(self, image: np.ndarray, kernel: np.ndarray) -> np.ndarray:
        """NumPy fallback for 2D convolution"""
        from numpy.lib.stride_tricks import as_strided

        k_h, k_w = kernel.shape
        i_h, i_w = image.shape

        # Output dimensions
        o_h = i_h - k_h + 1
        o_w = i_w - k_w + 1

        # Create sliding windows
        shape = (o_h, o_w, k_h, k_w)
        strides = image.strides + image.strides
        windows = as_strided(image, shape=shape, strides=strides)

        # Apply convolution
        result = np.tensordot(windows, kernel, axes=([2, 3], [0, 1]))

        return result

    def _detect_upsampling_artifacts(self, img: np.ndarray) -> float:
        """
        Detect upsampling artifacts from GAN generators
        GANs use transposed convolutions which leave specific patterns
        """
        # Convert to grayscale
        if len(img.shape) == 3:
            gray = np.mean(img, axis=2)
        else:
            gray = img

        # Calculate local gradients
        if SCIPY_AVAILABLE:
            gradient_x = ndimage.sobel(gray, axis=1)
            gradient_y = ndimage.sobel(gray, axis=0)
        else:
            # NumPy fallback
            gradient_x = np.gradient(gray, axis=1)
            gradient_y = np.gradient(gray, axis=0)

        gradient_magnitude = np.sqrt(gradient_x**2 + gradient_y**2)

        # Analyze gradient distribution
        # Upsampling creates periodic gradient patterns
        hist, bins = np.histogram(gradient_magnitude.flatten(), bins=50)

        # Calculate histogram entropy
        hist_normalized = hist / np.sum(hist)
        hist_normalized = hist_normalized[hist_normalized > 0]

        entropy = -np.sum(hist_normalized * np.log2(hist_normalized))

        # Low entropy = regular patterns = upsampling artifacts
        # Natural images have high entropy gradients
        max_entropy = np.log2(50)  # Maximum entropy for 50 bins
        regularity = 1.0 - (entropy / max_entropy)

        return min(regularity * 1.5, 1.0)


# Singleton instance
_gan_detector = None


def get_gan_detector() -> GANDetector:
    """Get singleton GAN detector instance"""
    global _gan_detector
    if _gan_detector is None:
        _gan_detector = GANDetector()
    return _gan_detector
