"""
Weighted Confidence Scoring System for StegoGuard Pro
Real confidence calculation based on detection quality and extraction success
"""
import logging
from typing import Dict, List, Any


class ConfidenceScorer:
    """
    Calculate weighted confidence scores for steganography detection

    Weighting:
    - Tool-based detections: 40%
    - Advanced module detections: 35%
    - Extraction success: 25%
    """

    def __init__(self):
        self.weights = {
            'tools': 0.40,           # 40% - External tool detections (steghide, zsteg, etc.)
            'advanced': 0.35,        # 35% - Advanced modules (LSB, DCT, GAN, etc.)
            'extraction': 0.25       # 25% - Successful data extraction
        }

        # Tool confidence scores (based on reliability and specificity)
        self.tool_scores = {
            'steghide': 0.95,        # Very reliable, specific to steganography
            'zsteg': 0.90,           # Highly reliable for LSB
            'stegdetect': 0.90,      # Specific JPEG stego detector
            'binwalk': 0.70,         # General purpose, can have false positives
            'foremost': 0.75,        # File carving, moderately specific
            'exiftool': 0.60,        # Metadata analysis, less specific
            'strings': 0.50,         # Very general, high false positive rate
            'statistical': 0.85      # Statistical analysis, quite reliable
        }

        # Advanced module confidence scores
        self.module_scores = {
            'LSB Bit-Level Scanner': 0.90,
            'DCT Frequency Analyzer': 0.85,
            'Palette Index Inspector': 0.80,
            'Wavelet Transform Probe': 0.85,
            'GAN/Deepfake Noise Detector': 0.75,
            'QR-Code Pixel Shift Checker': 0.70,
            'Spread-Spectrum Noise Map': 0.80,
            'Audio-EXIF Hybrid Detector': 0.75,
            'GAN/Deepfake CNN Artifact Detector': 0.85
        }

    def calculate_confidence(self,
                            detected_tools: List[str],
                            advanced_detections: Dict,
                            extraction_results: Dict,
                            detailed_findings: List[Dict]) -> Dict[str, Any]:
        """
        Calculate weighted confidence score

        Args:
            detected_tools: List of tool names that detected steganography
            advanced_detections: Results from advanced detection modules
            extraction_results: Results from data extraction attempts
            detailed_findings: Detailed findings with confidence scores

        Returns:
            Dictionary with confidence breakdown
        """
        # Component 1: Tool-based detections (40%)
        tool_score = self._calculate_tool_score(detected_tools, detailed_findings)

        # Component 2: Advanced module detections (35%)
        advanced_score = self._calculate_advanced_score(advanced_detections)

        # Component 3: Extraction success (25%)
        extraction_score = self._calculate_extraction_score(extraction_results)

        # Calculate weighted confidence
        weighted_confidence = (
            tool_score * self.weights['tools'] +
            advanced_score * self.weights['advanced'] +
            extraction_score * self.weights['extraction']
        )

        # Convert to percentage
        confidence_percentage = weighted_confidence * 100.0

        return {
            'overall_confidence': round(confidence_percentage, 2),
            'weighted_score': round(weighted_confidence, 4),
            'breakdown': {
                'tool_based': {
                    'score': round(tool_score * 100, 2),
                    'weight': self.weights['tools'] * 100,
                    'contribution': round(tool_score * self.weights['tools'] * 100, 2)
                },
                'advanced_modules': {
                    'score': round(advanced_score * 100, 2),
                    'weight': self.weights['advanced'] * 100,
                    'contribution': round(advanced_score * self.weights['advanced'] * 100, 2)
                },
                'extraction': {
                    'score': round(extraction_score * 100, 2),
                    'weight': self.weights['extraction'] * 100,
                    'contribution': round(extraction_score * self.weights['extraction'] * 100, 2)
                }
            },
            'quality_metrics': {
                'detection_diversity': self._calculate_diversity(detected_tools, advanced_detections),
                'high_confidence_detections': self._count_high_confidence(detailed_findings, advanced_detections)
            }
        }

    def _calculate_tool_score(self, detected_tools: List[str], detailed_findings: List[Dict]) -> float:
        """
        Calculate score from tool-based detections

        Uses weighted average based on tool reliability
        Maximum score: 1.0 (100%)
        """
        if not detected_tools and not any(f.get('tool') in self.tool_scores for f in detailed_findings):
            return 0.0

        tool_confidences = []

        # Check detected_tools list
        for tool in detected_tools:
            if tool in self.tool_scores:
                tool_confidences.append(self.tool_scores[tool])

        # Check detailed findings for tool-specific confidence
        for finding in detailed_findings:
            tool_name = finding.get('tool', '')
            if tool_name in self.tool_scores:
                # Use finding's confidence if available
                confidence = finding.get('confidence', self.tool_scores[tool_name])
                tool_confidences.append(confidence)

        if not tool_confidences:
            return 0.0

        # Use max confidence (best detection wins)
        # Also consider count (multiple tools increase confidence)
        max_confidence = max(tool_confidences)
        count_bonus = min(len(tool_confidences) * 0.05, 0.20)  # Up to +20% for multiple tools

        score = min(max_confidence + count_bonus, 1.0)
        return score

    def _calculate_advanced_score(self, advanced_detections: Dict) -> float:
        """
        Calculate score from advanced detection modules

        Uses weighted average of module confidences
        Maximum score: 1.0 (100%)
        """
        detections = advanced_detections.get('detections', [])

        if not detections:
            return 0.0

        module_confidences = []

        for detection in detections:
            module_name = detection.get('module', '')
            confidence = detection.get('confidence', 0.5)

            # Weight by module reliability
            module_weight = self.module_scores.get(module_name, 0.5)
            weighted_confidence = confidence * module_weight

            module_confidences.append(weighted_confidence)

        if not module_confidences:
            return 0.0

        # Use average confidence
        avg_confidence = sum(module_confidences) / len(module_confidences)

        # Bonus for multiple detections
        count_bonus = min(len(module_confidences) * 0.03, 0.15)  # Up to +15%

        score = min(avg_confidence + count_bonus, 1.0)
        return score

    def _calculate_extraction_score(self, extraction_results: Dict) -> float:
        """
        Calculate score from data extraction success

        Factors:
        - Extraction success: +0.6
        - Data integrity: +0.2
        - Meaningful content: +0.2
        - Successful decryption: +0.25 BONUS (can exceed 1.0 for weighted calculation)

        Maximum score: 1.25 (125%) - allows decryption to boost overall confidence significantly
        """
        if not extraction_results:
            return 0.0

        score = 0.0

        # Check if extraction was successful
        if extraction_results.get('success', False):
            score += 0.6

            # Check data integrity
            integrity = extraction_results.get('integrity', {})
            if integrity.get('valid', False):
                score += 0.2

            # Check if data is meaningful (not just random bytes)
            extracted_data = extraction_results.get('data', '')
            if extracted_data and len(extracted_data) > 10:
                # Check for printable content
                printable_ratio = sum(c.isprintable() or c.isspace() for c in extracted_data[:1000]) / min(len(extracted_data), 1000)
                if printable_ratio > 0.3:
                    score += 0.2
                else:
                    # Even binary data counts if it has low entropy (structured)
                    entropy = integrity.get('entropy', 8.0)
                    if entropy < 7.0:
                        score += 0.1

        # MAJOR BOOST: Successful decryption is strong evidence of steganography
        # This can push the score above 1.0, which is intentional for the weighted calculation
        if extraction_results.get('decryption_successful', False):
            score += 0.25  # +25% boost for proven encrypted payload

            # Additional boost if we know the decryption method
            method = extraction_results.get('decryption_method', '')
            if method:
                # Known strong encryption methods warrant higher confidence
                strong_methods = ['AES-256-GCM', 'ChaCha20', 'AES-256-GCM-PBKDF2',
                                 'ChaCha20-PBKDF2', 'AES-256-GCM-Scrypt']
                if any(strong in method for strong in strong_methods):
                    score += 0.10  # Additional +10% for strong encryption

        return min(score, 1.35)  # Cap at 135% to allow significant confidence boost

    def _calculate_diversity(self, detected_tools: List[str], advanced_detections: Dict) -> float:
        """
        Calculate detection diversity score

        Higher diversity = detections from multiple different sources
        More reliable than single-source detections
        """
        diversity_count = 0

        # Tool detections
        if detected_tools:
            diversity_count += 1

        # Advanced modules
        detections = advanced_detections.get('detections', [])
        if detections:
            diversity_count += 1

        # Multiple tools
        if len(detected_tools) >= 3:
            diversity_count += 1

        # Multiple advanced modules
        if len(detections) >= 3:
            diversity_count += 1

        # Normalize to 0-1
        return min(diversity_count / 4.0, 1.0)

    def _count_high_confidence(self, detailed_findings: List[Dict], advanced_detections: Dict) -> int:
        """
        Count number of high-confidence detections (>0.85)
        """
        count = 0

        # Check detailed findings
        for finding in detailed_findings:
            if finding.get('confidence', 0) >= 0.85:
                count += 1

        # Check advanced detections
        for detection in advanced_detections.get('detections', []):
            if detection.get('confidence', 0) >= 0.85:
                count += 1

        return count

    def get_confidence_level(self, confidence_percentage: float) -> str:
        """
        Convert confidence percentage to human-readable level

        Args:
            confidence_percentage: 0-100 confidence score

        Returns:
            Confidence level string
        """
        if confidence_percentage >= 90:
            return 'VERY HIGH'
        elif confidence_percentage >= 75:
            return 'HIGH'
        elif confidence_percentage >= 60:
            return 'MEDIUM-HIGH'
        elif confidence_percentage >= 45:
            return 'MEDIUM'
        elif confidence_percentage >= 30:
            return 'MEDIUM-LOW'
        elif confidence_percentage >= 15:
            return 'LOW'
        else:
            return 'VERY LOW'


# Singleton instance
_confidence_scorer = None


def get_confidence_scorer() -> ConfidenceScorer:
    """Get singleton confidence scorer instance"""
    global _confidence_scorer
    if _confidence_scorer is None:
        _confidence_scorer = ConfidenceScorer()
    return _confidence_scorer
