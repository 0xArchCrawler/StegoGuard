"""
StegoGuard Advanced Analyzer
Enhanced steganography detection with advanced capabilities
"""

import asyncio
from pathlib import Path
from typing import Dict, Optional, Callable
from datetime import datetime
import hashlib
import json
import sys
import os
import logging
import numpy as np
from PIL import Image
from functools import lru_cache

# Configure logger
logger = logging.getLogger(__name__)

from .threat_intel import ThreatIntelligence
from .apt_pattern_analyzer import APTPatternAnalyzer
from .advanced_detection_modules import AdvancedDetectionModules
from .hardened_decryption_engine import HardenedDecryptionEngine
from .reliability_manager import get_reliability_manager
from .confidence_scorer import get_confidence_scorer


class AdvancedAnalyzer:
    """
    Advanced steganography analysis with integrated threat intelligence
    and enhanced detection capabilities
    """

    def __init__(self):
        # Initialize threat intelligence
        self.threat_intel = ThreatIntelligence()

        # Initialize APT pattern analyzer
        self.apt_analyzer = APTPatternAnalyzer()

        # Initialize advanced detection modules
        self.advanced_detection = AdvancedDetectionModules()

        # Initialize hardened decryption engine
        self.hardened_decryption = None  # Lazy initialization

        # Initialize reliability manager
        self.reliability = get_reliability_manager()

        # Initialize confidence scorer
        self.confidence_scorer = get_confidence_scorer()

        # Detection modules cache
        self._detectors_cache = {}

    async def analyze_image(
        self,
        file_path: str,
        options: Optional[Dict] = None,
        progress_callback: Optional[Callable] = None
    ) -> Dict:
        """
        Perform advanced steganography analysis on image

        Args:
            file_path: Path to image file
            options: Analysis options
            progress_callback: Optional progress callback function

        Returns:
            Comprehensive analysis results with threat intelligence
        """
        if options is None:
            options = {}

        if progress_callback:
            progress_callback(0)

        # Step 1: Basic file analysis (10%)
        file_info = self._get_file_info(file_path)
        if progress_callback:
            progress_callback(10)

        # Step 2: Run real steganography detection (40%)
        quick_mode = options.get('quick_mode', False)
        base_results = await self._run_real_detection(file_path, file_info, quick_mode=quick_mode)
        if progress_callback:
            progress_callback(50)

        # Step 2.5: Hardened decryption engine (auto-activates on 3+ anomalies)
        # New advanced decryption with 7 intelligent probing techniques
        if options.get('enable_decryption', True):
            try:
                anomaly_count = base_results.get('anomaly_count', 0)

                # Initialize hardened decryption engine
                if self.hardened_decryption is None or self.hardened_decryption.detection_count != anomaly_count:
                    self.hardened_decryption = HardenedDecryptionEngine(
                        image_path=file_path,
                        detection_count=anomaly_count
                    )

                # Run hardened decryption (auto-activates on 3+ anomalies)
                decryption_results = await self.hardened_decryption.decrypt()
                base_results['decryption_results'] = decryption_results

                # V2.7: Recalculate confidence with decryption boost if successful
                if decryption_results.get('decryption_successful'):
                    # Prepare extraction_results with decryption data
                    extraction_results = {}

                    # Check if there was tool-based extraction
                    tool_extraction = base_results.get('tool_extraction', {})
                    if tool_extraction.get('extracted'):
                        extraction_results = {
                            'success': True,
                            'data': tool_extraction.get('data'),
                            'integrity': {'valid': True}
                        }

                    # Add decryption success flags for confidence boost
                    extraction_results['decryption_successful'] = True
                    extraction_results['decryption_method'] = decryption_results.get('decryption_method', '')

                    # If no tool extraction but decryption worked, use decryption data
                    if not tool_extraction.get('extracted') and decryption_results.get('extracted_data'):
                        extraction_results['success'] = True
                        extraction_results['data'] = decryption_results.get('extracted_data')

                    # Recalculate confidence with decryption boost
                    confidence_result = self.confidence_scorer.calculate_confidence(
                        detected_tools=base_results.get('detected_tools', []),
                        advanced_detections={},  # Already factored into original score
                        extraction_results=extraction_results,
                        detailed_findings=base_results.get('detailed_findings', [])
                    )

                    # Update base_results with boosted confidence
                    base_results['confidence'] = confidence_result['overall_confidence']
                    base_results['confidence_breakdown'] = confidence_result
                    base_results['confidence_level'] = self.confidence_scorer.get_confidence_level(
                        confidence_result['overall_confidence']
                    )

            except Exception as e:
                # Gracefully handle decryption errors
                base_results['decryption_results'] = {
                    'activated': False,
                    'error': str(e),
                    'detection_count': base_results.get('anomaly_count', 0)
                }

        if progress_callback:
            progress_callback(70)

        # Step 3: Enhanced threat analysis (15%) - skip in quick mode
        if not quick_mode:
            threat_analysis = await self._analyze_threats(base_results, file_info)
        else:
            threat_analysis = {'threat_assessment': {'level': 'MINIMAL'}, 'risk_score': 0}

        if progress_callback:
            progress_callback(85)

        # Step 4: Advanced pattern analysis (10%) - skip in quick mode
        if not quick_mode:
            pattern_analysis = await self._analyze_patterns(base_results, file_path)
        else:
            pattern_analysis = {}

        # Step 4.5: Phase 2 & 3 Advanced Detectors (4%) - skip in quick mode
        if not quick_mode:
            phase2_detections = await self._run_phase2_detectors(base_results, file_path)
            phase3_enhancements = await self._run_phase3_enhancements(base_results, phase2_detections, file_path)
        else:
            phase2_detections = {}
            phase3_enhancements = {}

        if progress_callback:
            progress_callback(95)

        # Step 5: Compile comprehensive results (5%)
        results = self._compile_results(
            base_results,
            file_info,
            threat_analysis,
            pattern_analysis,
            phase2_detections,
            phase3_enhancements
        )
        if progress_callback:
            progress_callback(100)

        return results

    async def analyze_batch(
        self,
        file_paths: list,
        options: Optional[Dict] = None,
        progress_callback: Optional[Callable] = None
    ) -> Dict:
        """Analyze multiple images in batch (uses quick mode for speed)"""
        results = []
        total = len(file_paths)

        # Use quick mode for batch processing
        if options is None:
            options = {}
        options['quick_mode'] = True
        options['enable_decryption'] = False  # Skip decryption in batch for speed

        for i, file_path in enumerate(file_paths):
            try:
                result = await self.analyze_image(file_path, options)
                results.append(result)

                if progress_callback:
                    progress_callback((i + 1) / total * 100)

            except Exception as e:
                results.append({
                    'file_path': file_path,
                    'error': str(e),
                    'status': 'failed'
                })

        return {
            'total': total,
            'completed': len([r for r in results if r.get('status') != 'failed']),
            'failed': len([r for r in results if r.get('status') == 'failed']),
            'results': results
        }

    async def _run_real_detection(self, file_path: str, file_info: Dict, quick_mode: bool = False) -> Dict:
        """Run real steganography detection using multiple professional tools"""
        import tempfile

        try:
            img = Image.open(file_path)
            dimensions = f"{img.width}×{img.height}"
            img_format = img.format or 'Unknown'
            img_data = np.array(img)
        except:
            dimensions = 'Unknown'
            img_format = 'Unknown'
            img_data = None

        detection_results = {}
        anomaly_count = 0
        tools_results = []
        detailed_findings = []

        # 1. steghide signature detection (only for supported formats)
        # Use extraction attempt for reliable detection with reliability manager
        if img_format in ['JPEG', 'JPG', 'BMP'] and self.reliability.is_tool_available('steghide'):
            try:
                # Try extraction with empty password using reliability manager
                data_bytes = self.reliability.safe_temp_extraction(
                    ['steghide', 'extract', '-sf', str(file_path), '-xf', 'temp', '-p', '', '-f'],
                    timeout=5
                )

                if data_bytes and len(data_bytes) > 0:
                    # Verify extraction integrity
                    integrity = self.reliability.verify_extraction_integrity(data_bytes)

                    if integrity['valid']:
                        # Format data safely
                        extracted_data = self.reliability.format_data_safely(data_bytes, max_length=2000)

                        tools_results.append('steghide')
                        anomaly_count += 1
                        detailed_findings.append({
                            'tool': 'steghide',
                            'finding': 'Steghide embedded data detected',
                            'confidence': 0.95,
                            'extracted_data': extracted_data,
                            'extraction_integrity': integrity
                        })
            except Exception as e:
                # Graceful failure - log but continue
                import logging
                logging.debug(f"Steghide detection failed: {e}")

        # 2. zsteg for PNG/BMP LSB analysis (strict detection)
        if img_format in ['PNG', 'BMP'] and self.reliability.is_tool_available('zsteg'):
            try:
                result = self.reliability.run_with_retry(
                    ['zsteg', '-a', str(file_path)],
                    timeout=10,
                    tool_name='zsteg'
                )
                # Look for actual embedded text/data, not just metadata
                suspicious_patterns = ['text: "', 'file:', 'zlib:', 'openssl']
                has_real_data = any(pattern in result.stdout for pattern in suspicious_patterns)

                # Or check for multiple LSB layers with data
                data_layers = result.stdout.count('b1,')  + result.stdout.count('b2,') + result.stdout.count('b3,')

                if has_real_data or data_layers > 3:
                    tools_results.append('zsteg')
                    anomaly_count += 1
                    detailed_findings.append({
                        'tool': 'zsteg',
                        'finding': 'LSB steganography confirmed',
                        'confidence': 0.91
                    })
            except:
                pass

        # 3. stegdetect for JPEG
        if img_format in ['JPEG', 'JPG'] and self.reliability.is_tool_available('stegdetect'):
            try:
                result = self.reliability.run_with_retry(
                    ['stegdetect', str(file_path)],
                    timeout=10,
                    tool_name='stegdetect'
                )
                methods = ['jsteg', 'jphide', 'outguess', 'f5']
                found = [m for m in methods if m in result.stdout.lower()]
                if found:
                    tools_results.append('stegdetect')
                    anomaly_count += 1
                    detailed_findings.append({
                        'tool': 'stegdetect',
                        'finding': f'JPEG stego: {", ".join(found)}',
                        'confidence': 0.90
                    })
            except:
                pass

        # 4. binwalk firmware/archive detection (strict - skip normal compression)
        if self.reliability.is_tool_available('binwalk'):
            try:
                result = self.reliability.run_with_retry(
                    ['binwalk', str(file_path)],
                    timeout=10,
                    tool_name='binwalk'
                )
                # Count actual findings, not just the image header or normal compression
                lines = result.stdout.split('\n')
                findings = [l for l in lines if any(x in l.lower() for x in ['compressed', 'archive', 'filesystem', 'encrypted'])]

                # Filter out normal image components
                normal_patterns = ['png image', 'jpeg image', 'gif image', 'zlib compressed data, default', 'zlib compressed data, best']
                real_findings = [f for f in findings if not any(x in f.lower() for x in normal_patterns)]

                # Also check that there are meaningful findings (not just offset 41 zlib in PNG)
                if len(real_findings) > 0 and any('zip' in f.lower() or 'rar' in f.lower() or 'tar' in f.lower() or 'filesystem' in f.lower() for f in real_findings):
                    tools_results.append('binwalk')
                    anomaly_count += 1
                    detailed_findings.append({
                        'tool': 'binwalk',
                        'finding': f'Suspicious embedded files detected: {len(real_findings)} items',
                        'confidence': 0.87
                    })
            except:
                pass

        # 5. foremost file carving (skip in quick mode for speed)
        if not quick_mode and self.reliability.is_tool_available('foremost'):
            try:
                with tempfile.TemporaryDirectory() as temp_dir:
                    result = self.reliability.run_with_retry(
                        ['foremost', '-t', 'zip,rar,pdf,exe', '-o', temp_dir, '-q', str(file_path)],
                        timeout=8,
                        tool_name='foremost'
                    )
                    # Count only real files, not directories or audit.txt
                    carved_files = [f for f in Path(temp_dir).rglob('*') if f.is_file() and f.name != 'audit.txt']

                    if len(carved_files) > 0:
                        tools_results.append('foremost')
                        anomaly_count += 1
                        detailed_findings.append({
                            'tool': 'foremost',
                            'finding': f'Recovered {len(carved_files)} hidden files',
                            'confidence': 0.83
                        })
            except:
                pass

        # 6. exiftool metadata analysis (improved to reduce false positives)
        if self.reliability.is_tool_available('exiftool'):
            try:
                result = self.reliability.run_with_retry(
                    ['exiftool', '-a', '-G', str(file_path)],
                    timeout=5,
                    tool_name='exiftool'
                )
                # Look for REALLY suspicious metadata, not just normal fields
                very_suspicious = ['base64', 'encrypted', 'payload', 'shellcode', 'BEGIN PGP']
                found_very_suspicious = [tag for tag in very_suspicious if tag in result.stdout]

                # Or unusually long metadata fields (>2000 chars in a single field)
                lines = result.stdout.split('\n')
                long_fields = [line for line in lines if len(line) > 2000]

                if found_very_suspicious or long_fields:
                    tools_results.append('exiftool')
                    anomaly_count += 1
                    detailed_findings.append({
                        'tool': 'exiftool',
                        'finding': 'Highly suspicious metadata detected',
                        'confidence': 0.82
                    })
            except:
                pass

        # 7. strings analysis for hidden data
        if self.reliability.is_tool_available('strings'):
            try:
                result = self.reliability.run_with_retry(
                    ['strings', '-n', '10', str(file_path)],
                    timeout=5,
                    tool_name='strings'
                )
                suspicious = ['password', 'key', 'secret', 'encrypted', 'BEGIN PGP', 'ssh-rsa', 'flag{', 'CTF{']
                found = [s for s in suspicious if s.lower() in result.stdout.lower()]
                if found:
                    tools_results.append('strings')
                    anomaly_count += 1
                    detailed_findings.append({
                        'tool': 'strings',
                        'finding': f'Suspicious strings: {", ".join(found[:3])}',
                        'confidence': 0.70
                    })
            except:
                pass

        # 8. Statistical analysis (optimized and improved for accuracy)
        if img_data is not None and len(img_data.shape) == 3 and img_data.size < 10000000:  # Skip for very large images
            try:
                # Sample-based analysis for speed (use 10% of image)
                h, w = img_data.shape[:2]
                sample_h, sample_w = h // 3, w // 3
                sample_data = img_data[:sample_h, :sample_w, :]

                statistical_anomaly = False

                for channel in range(min(3, sample_data.shape[2])):
                    lsb_layer = sample_data[:,:,channel] & 1
                    hist, _ = np.histogram(lsb_layer.flatten(), bins=2, density=True)

                    # Calculate entropy
                    hist = hist + 1e-10  # Avoid log(0)
                    lsb_entropy = -np.sum(hist * np.log2(hist))

                    # Check chi-square test for randomness
                    expected_count = lsb_layer.size / 2
                    chi_square = np.sum((np.histogram(lsb_layer.flatten(), bins=2)[0] - expected_count)**2 / expected_count)

                    # Very high entropy (close to 1) + high chi-square = likely steganography
                    if lsb_entropy > 0.99 and chi_square > 200:  # Higher threshold
                        statistical_anomaly = True
                        break

                if statistical_anomaly:
                    anomaly_count += 1
                    detailed_findings.append({
                        'tool': 'statistical',
                        'finding': 'LSB randomness anomaly confirmed',
                        'confidence': 0.81
                    })
            except:
                pass

        # 9. Advanced detection modules (LSB, DCT, Palette, Wavelet, GAN, etc.)
        try:
            advanced_results = self.advanced_detection.analyze_image(file_path)
            compiled_advanced = self.advanced_detection.compile_results(advanced_results)

            # Add each detected anomaly from advanced modules
            for detection in compiled_advanced.get('detections', []):
                anomaly_count += 1
                detailed_findings.append({
                    'tool': detection['module'],
                    'finding': f"Advanced detection: {detection['module']}",
                    'confidence': detection.get('confidence', 0.75),
                    'details': detection.get('details', {})
                })
        except Exception as e:
            # Advanced detection failure shouldn't stop analysis
            pass

        # Check if any tools extracted data (needed for confidence calculation)
        tool_extracted_data = None
        for finding in detailed_findings:
            if finding.get('extracted_data'):
                tool_extracted_data = finding.get('extracted_data')
                break  # Use first extraction found

        # Calculate weighted confidence score using advanced scoring system
        # Prepare extraction results for confidence calculation
        extraction_results = {}
        if tool_extracted_data:
            extraction_results = {
                'success': True,
                'data': tool_extracted_data,
                'integrity': {'valid': True}  # If we extracted it, it's valid
            }

        # Calculate confidence using weighted scorer
        confidence_result = self.confidence_scorer.calculate_confidence(
            detected_tools=tools_results,
            advanced_detections=compiled_advanced,
            extraction_results=extraction_results,
            detailed_findings=detailed_findings
        )

        # Extract overall confidence percentage
        confidence = confidence_result['overall_confidence']

        # Determine threat level
        if anomaly_count == 0:
            threat_level = 'MINIMAL'
        elif anomaly_count <= 2:
            threat_level = 'LOW'
        elif anomaly_count <= 4:
            threat_level = 'MEDIUM'
        elif anomaly_count <= 6:
            threat_level = 'HIGH'
        else:
            threat_level = 'CRITICAL'

        result = {
            'anomaly_count': anomaly_count,
            'detected_tools': tools_results,
            'detection_results': detection_results,
            'detailed_findings': detailed_findings,
            'metadata': {'format': img_format, 'dimensions': dimensions},
            'confidence': confidence,
            'confidence_breakdown': confidence_result,  # Add detailed breakdown
            'confidence_level': self.confidence_scorer.get_confidence_level(confidence),  # Add level
            'threat_level': threat_level
        }

        # Add tool-based extraction if available
        if tool_extracted_data:
            result['tool_extraction'] = {
                'extracted': True,
                'data': tool_extracted_data,
                'method': 'tool_based_detection'
            }

        return result

    def _get_file_info(self, file_path: str) -> Dict:
        """Get comprehensive file information"""
        path = Path(file_path)

        # Calculate file hash
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        return {
            'filename': path.name,
            'path': str(path.absolute()),
            'size': path.stat().st_size,
            'modified': datetime.fromtimestamp(path.stat().st_mtime).isoformat(),
            'sha256': file_hash
        }

    async def _analyze_threats(self, base_results: Dict, file_info: Dict) -> Dict:
        """
        Enhanced threat analysis using integrated capabilities and APT pattern analysis
        """
        try:
            # Simplified threat assessment based on anomaly count
            anomaly_count = base_results.get('anomaly_count', 0)

            if anomaly_count == 0:
                level = 'MINIMAL'
                risk_score = 0
            elif anomaly_count == 1:
                level = 'LOW'
                risk_score = 25
            elif anomaly_count <= 3:
                level = 'MEDIUM'
                risk_score = 50
            elif anomaly_count <= 5:
                level = 'HIGH'
                risk_score = 75
            else:
                level = 'CRITICAL'
                risk_score = 95

            # APT pattern analysis (only if significant detections)
            apt_attribution = None
            if anomaly_count >= 2:
                apt_result = self.apt_analyzer.analyze_patterns(
                    base_results,
                    base_results.get('metadata', {})
                )
                if apt_result.get('likely_apt'):
                    apt_attribution = {
                        'likely_actor': apt_result['likely_apt'],
                        'confidence': apt_result['confidence'],
                        'reasoning': apt_result['reasoning'],
                        'matched_tools': apt_result.get('matched_tools', [])
                    }

            return {
                'threat_assessment': {'level': level},
                'malicious_indicators': [],
                'apt_attribution': apt_attribution,
                'apt_indicators': [],
                'risk_score': risk_score
            }

        except Exception as e:
            return {
                'error': str(e),
                'threat_assessment': {'level': 'MINIMAL'},
                'apt_attribution': None,
                'risk_score': 0
            }

    async def _analyze_patterns(self, base_results: Dict, file_path: str) -> Dict:
        """Advanced pattern analysis (simplified)"""
        try:
            # Simplified pattern analysis
            detected_tools = base_results.get('detected_tools', [])

            patterns = {
                'tool_signatures': detected_tools,
                'encryption_patterns': {},
                'stealth_indicators': {},
                'exfiltration_markers': {}
            }

            return patterns

        except Exception as e:
            return {'error': str(e)}

    def _compile_results(
        self,
        base_results: Dict,
        file_info: Dict,
        threat_analysis: Dict,
        pattern_analysis: Dict,
        phase2_detections: Dict,
        phase3_enhancements: Dict
    ) -> Dict:
        """Compile comprehensive analysis results"""
        return {
            'analysis_id': self._generate_analysis_id(),
            'timestamp': datetime.now().isoformat(),
            'file_info': file_info,
            'detection': {
                'anomaly_count': base_results.get('anomaly_count', 0),
                'threat_level': base_results.get('threat_level', 'UNKNOWN'),
                'confidence_score': base_results.get('confidence', 0),
                'confidence_level': base_results.get('confidence_level', 'UNKNOWN'),
                'confidence_breakdown': base_results.get('confidence_breakdown', {}),
                'modules': base_results.get('detection_results', {}),
                'detected_tools': base_results.get('detected_tools', []),
                'detailed_findings': base_results.get('detailed_findings', []),
                'tool_extraction': base_results.get('tool_extraction', {})  # Add tool-based extraction
            },
            'threat_analysis': threat_analysis,
            'pattern_analysis': pattern_analysis,
            'decryption': base_results.get('decryption_results', {}),
            'metadata': base_results.get('metadata', {}),
            'recommendations': self._generate_recommendations(
                base_results,
                threat_analysis,
                pattern_analysis
            ),
            'phase2_detections': phase2_detections,
            'phase3_enhancements': phase3_enhancements,
            'status': 'completed'
        }

    def _check_malicious_indicators(self, results: Dict) -> list:
        """Check for known malicious indicators"""
        indicators = []

        # Check for high anomaly count
        if results.get('anomaly_count', 0) >= 5:
            indicators.append({
                'type': 'high_anomaly_count',
                'severity': 'HIGH',
                'description': 'Multiple steganography techniques detected'
            })

        # Check for encryption
        if results.get('decryption_results', {}).get('encrypted'):
            indicators.append({
                'type': 'encryption_detected',
                'severity': 'MEDIUM',
                'description': 'Encrypted data found in image'
            })

        # Check for suspicious metadata
        metadata = results.get('metadata', {})
        if metadata.get('suspicious_exif'):
            indicators.append({
                'type': 'suspicious_metadata',
                'severity': 'MEDIUM',
                'description': 'Anomalous metadata patterns detected'
            })

        return indicators

    def _check_apt_indicators(self, results: Dict) -> list:
        """Check for Advanced Persistent Threat indicators"""
        indicators = []

        # Check for sophisticated techniques
        detection_results = results.get('detection_results', {})

        sophisticated_modules = ['gan_detector', 'wavelet_detector', 'spectrum_detector']
        detected_sophisticated = [
            mod for mod in sophisticated_modules
            if detection_results.get(mod, {}).get('detected')
        ]

        if len(detected_sophisticated) >= 2:
            indicators.append({
                'type': 'sophisticated_techniques',
                'severity': 'HIGH',
                'description': 'Multiple advanced steganography techniques detected',
                'modules': detected_sophisticated
            })

        # Check for multi-layer steganography
        if results.get('anomaly_count', 0) >= 4:
            indicators.append({
                'type': 'multi_layer_steganography',
                'severity': 'CRITICAL',
                'description': 'Possible multi-layer steganography indicating APT activity'
            })

        return indicators

    def _calculate_risk_score(
        self,
        threat_assessment: Dict,
        malicious_indicators: list,
        apt_indicators: list
    ) -> int:
        """Calculate overall risk score (0-100)"""
        score = 0

        # Base threat level
        threat_level = threat_assessment.get('threat_assessment', {}).get('level', 'LOW')
        level_scores = {'LOW': 20, 'MEDIUM': 40, 'HIGH': 70, 'CRITICAL': 90}
        score += level_scores.get(threat_level, 30)

        # Malicious indicators
        score += len(malicious_indicators) * 5

        # APT indicators (weighted higher)
        score += len(apt_indicators) * 10

        # Cap at 100
        return min(score, 100)

    def _detect_tool_signatures(self, results: Dict) -> Dict:
        """Detect signatures of known steganography tools"""
        signatures = {}

        detection_results = results.get('detection_results', {})

        # Check pattern detector
        pattern_det = detection_results.get('pattern_detector', {})
        if pattern_det.get('detected'):
            signatures['known_tools'] = pattern_det.get('details', {}).get('tools', [])

        return signatures

    def _detect_encryption_patterns(self, results: Dict) -> Dict:
        """Detect encryption patterns"""
        patterns = {}

        decryption = results.get('decryption_results', {})
        if decryption:
            patterns['encrypted'] = decryption.get('encrypted', False)
            patterns['encryption_type'] = decryption.get('encryption_type', 'unknown')

        return patterns

    def _detect_stealth_indicators(self, results: Dict) -> Dict:
        """Detect stealth/evasion indicators"""
        indicators = {}

        # Check for low-level bit manipulation
        detection_results = results.get('detection_results', {})
        lsb_det = detection_results.get('lsb_detector', {})

        if lsb_det.get('detected'):
            details = lsb_det.get('details', {})
            if details.get('entropy', 0) < 0.3:
                indicators['low_entropy_stealth'] = True

        return indicators

    def _detect_exfiltration_markers(self, results: Dict) -> Dict:
        """Detect data exfiltration markers"""
        markers = {}

        decryption = results.get('decryption_results', {})
        if decryption.get('extracted_data'):
            data = decryption.get('extracted_data', '')

            # Check for common exfiltration patterns
            exfil_keywords = ['exfil', 'target', 'owned', 'complete', 'payload', 'c2', 'beacon']
            found_keywords = [kw for kw in exfil_keywords if kw.lower() in data.lower()]

            if found_keywords:
                markers['exfiltration_likely'] = True
                markers['keywords_found'] = found_keywords

        return markers

    def _generate_recommendations(
        self,
        base_results: Dict,
        threat_analysis: Dict,
        pattern_analysis: Dict
    ) -> list:
        """Generate security recommendations"""
        recommendations = []

        # Based on threat level
        threat_level = base_results.get('threat_level', 'UNKNOWN')

        if threat_level in ['HIGH', 'CRITICAL']:
            recommendations.append({
                'priority': 'CRITICAL',
                'action': 'Immediate forensic investigation recommended',
                'details': 'High threat level detected - escalate to security team'
            })

        # Based on APT indicators
        apt_indicators = threat_analysis.get('apt_indicators', [])
        if apt_indicators:
            recommendations.append({
                'priority': 'HIGH',
                'action': 'APT investigation required',
                'details': 'Sophisticated techniques detected - possible APT activity'
            })

        # Based on encryption
        if pattern_analysis.get('encryption_patterns', {}).get('encrypted'):
            recommendations.append({
                'priority': 'MEDIUM',
                'action': 'Cryptanalysis recommended',
                'details': 'Encrypted data detected - may require advanced decryption'
            })

        # Based on exfiltration markers
        if pattern_analysis.get('exfiltration_markers', {}).get('exfiltration_likely'):
            recommendations.append({
                'priority': 'CRITICAL',
                'action': 'Data exfiltration investigation',
                'details': 'Possible data exfiltration detected - trace source and destination'
            })

        # Default recommendation
        if not recommendations:
            recommendations.append({
                'priority': 'LOW',
                'action': 'Continue monitoring',
                'details': 'No immediate threats detected - maintain normal security posture'
            })

        return recommendations

    def _generate_analysis_id(self) -> str:
        """Generate unique analysis ID"""
        timestamp = datetime.now().isoformat()
        return hashlib.md5(timestamp.encode()).hexdigest()[:12].upper()

    def generate_report(self, results: Dict, format: str = 'pdf') -> Path:
        """Generate analysis report"""
        # Use base StegoGuard report generation
        output_path = f"/tmp/stegoguard_report_{results['analysis_id']}.{format}"
        self.stegoguard.generate_report(results, format, output_path)
        return Path(output_path)

    async def _run_phase2_detectors(self, base_results: Dict, file_path: str) -> Dict:
        """
        Run Phase 2 Advanced Detectors:
        - PQC (Post-Quantum Cryptography) detector
        - Blockchain payload scanner
        - AI-Stego pattern recognizer
        """
        logger.info("Starting Phase 2 advanced detection")

        try:
            phase2_results = {}

            # PQC Detector
            try:
                logger.debug("Initializing PQC detector")
                from .pqc_detector import PQCDetector
                pqc_detector = PQCDetector()

                # Extract LSB data for analysis
                lsb_data = base_results.get('lsb_extraction', {}).get('data', b'')
                if not lsb_data:
                    # Try to extract from file directly
                    logger.debug(f"Reading file for PQC analysis: {file_path}")
                    with open(file_path, 'rb') as f:
                        file_data = f.read()
                    # ASYNC OPTIMIZATION: Run CPU-bound detection in thread pool
                    pqc_result = await asyncio.to_thread(pqc_detector.detect, file_data)
                else:
                    logger.debug(f"Using LSB data for PQC analysis: {len(lsb_data)} bytes")
                    # ASYNC OPTIMIZATION: Run CPU-bound detection in thread pool
                    pqc_result = await asyncio.to_thread(pqc_detector.detect, lsb_data)

                # Validate result
                if not isinstance(pqc_result, dict) or 'confidence' not in pqc_result:
                    logger.warning("PQC detector returned invalid result format")
                    pqc_result = {'pqc_detected': False, 'confidence': 0.0, 'error': 'Invalid result format'}

                if pqc_result.get('pqc_detected'):
                    logger.info(f"PQC detected: {pqc_result.get('algorithm', 'Unknown')} with {pqc_result.get('confidence', 0)*100:.1f}% confidence")
                else:
                    logger.debug("No PQC signatures detected")

                phase2_results['pqc_analysis'] = pqc_result
            except ImportError as e:
                logger.warning(f"PQC detector module not available: {e}")
                phase2_results['pqc_analysis'] = {
                    'pqc_detected': False,
                    'confidence': 0.0,
                    'error': f'Import failed: {str(e)}'
                }
            except Exception as e:
                logger.error(f"PQC detection failed: {e}", exc_info=True)
                phase2_results['pqc_analysis'] = {
                    'pqc_detected': False,
                    'confidence': 0.0,
                    'error': str(e)
                }

            # Blockchain Detector
            try:
                logger.debug("Initializing Blockchain detector")
                from .blockchain_stego_detector import BlockchainStegoDetector
                blockchain_detector = BlockchainStegoDetector()

                # Extract LSB data for analysis
                lsb_data = base_results.get('lsb_extraction', {}).get('data', b'')
                if not lsb_data:
                    logger.debug(f"Reading file for blockchain analysis: {file_path}")
                    with open(file_path, 'rb') as f:
                        file_data = f.read()
                    # ASYNC OPTIMIZATION: Run CPU-bound detection in thread pool
                    blockchain_result = await asyncio.to_thread(blockchain_detector.detect, file_data)
                else:
                    logger.debug(f"Using LSB data for blockchain analysis: {len(lsb_data)} bytes")
                    # ASYNC OPTIMIZATION: Run CPU-bound detection in thread pool
                    blockchain_result = await asyncio.to_thread(blockchain_detector.detect, lsb_data)

                # Validate result
                if not isinstance(blockchain_result, dict) or 'blockchain_detected' not in blockchain_result:
                    logger.warning("Blockchain detector returned invalid result format")
                    blockchain_result = {'blockchain_detected': False, 'addresses': {}, 'confidence': 0.0, 'error': 'Invalid result format'}

                # Count total addresses from all cryptocurrencies
                addresses_dict = blockchain_result.get('addresses', {})
                total_addresses = sum(len(addrs) for addrs in addresses_dict.values() if isinstance(addrs, list))

                if blockchain_result.get('blockchain_detected') or total_addresses > 0:
                    logger.info(f"Blockchain addresses found: {total_addresses} address(es)")
                else:
                    logger.debug("No blockchain addresses detected")

                phase2_results['blockchain_analysis'] = blockchain_result
            except ImportError as e:
                logger.warning(f"Blockchain detector module not available: {e}")
                phase2_results['blockchain_analysis'] = {
                    'addresses_found': [],
                    'confidence': 0.0,
                    'error': f'Import failed: {str(e)}'
                }
            except Exception as e:
                logger.error(f"Blockchain detection failed: {e}", exc_info=True)
                phase2_results['blockchain_analysis'] = {
                    'addresses_found': [],
                    'confidence': 0.0,
                    'error': str(e)
                }

            # AI-Stego Detector
            try:
                logger.debug("Initializing AI-Stego detector")
                from .ai_stego_detector import AIStegoDetector
                ai_stego_detector = AIStegoDetector()

                logger.debug(f"Running AI-Stego detection on: {file_path}")
                # ASYNC OPTIMIZATION: Run CPU-bound detection in thread pool
                ai_stego_result = await asyncio.to_thread(ai_stego_detector.detect, file_path)

                # Validate result
                if not isinstance(ai_stego_result, dict) or 'confidence' not in ai_stego_result:
                    logger.warning("AI-Stego detector returned invalid result format")
                    ai_stego_result = {'ai_generated': False, 'confidence': 0.0, 'error': 'Invalid result format'}

                if ai_stego_result.get('ai_generated'):
                    logger.info(f"AI-generated steganography detected with {ai_stego_result.get('confidence', 0)*100:.1f}% confidence")
                else:
                    logger.debug("No AI-generated steganography detected")

                phase2_results['ai_stego_patterns'] = ai_stego_result
            except ImportError as e:
                logger.warning(f"AI-Stego detector module not available: {e}")
                phase2_results['ai_stego_patterns'] = {
                    'ai_generated': False,
                    'confidence': 0.0,
                    'error': f'Import failed: {str(e)}'
                }
            except Exception as e:
                logger.error(f"AI-Stego detection failed: {e}", exc_info=True)
                phase2_results['ai_stego_patterns'] = {
                    'ai_generated': False,
                    'confidence': 0.0,
                    'error': str(e)
                }

            logger.info("Phase 2 detection completed")
            return phase2_results

        except Exception as e:
            # Graceful degradation - return empty results
            logger.error(f"Phase 2 detection failed catastrophically: {e}", exc_info=True)
            return {
                'error': str(e),
                'pqc_analysis': {'pqc_detected': False, 'confidence': 0.0},
                'blockchain_analysis': {'addresses_found': [], 'confidence': 0.0},
                'ai_stego_patterns': {'ai_generated': False, 'confidence': 0.0}
            }

    async def _run_phase3_enhancements(self, base_results: Dict, phase2_results: Dict, file_path: str = None) -> Dict:
        """
        Run Phase 3 Enhancements:
        - Advanced algorithm detector
        - Confidence aggregator
        - Probes 11 & 12 results extraction

        Args:
            base_results: Phase 1 detection results
            phase2_results: Phase 2 detection results
            file_path: Path to the image file for advanced algorithm detection
        """
        logger.info("Starting Phase 3 enhancements")

        try:
            phase3_results = {}

            # Advanced Algorithm Detector
            try:
                logger.debug("Initializing Advanced Algorithm detector")
                from .advanced_stego_algorithm_detector import AdvancedStegoAlgorithmDetector
                algo_detector = AdvancedStegoAlgorithmDetector()

                # Run advanced algorithm detection on the image file
                logger.debug(f"Running advanced algorithm detection on: {file_path}")
                # ASYNC OPTIMIZATION: Run CPU-bound detection in thread pool
                algo_result = await asyncio.to_thread(algo_detector.detect, file_path)

                # Validate result
                if not isinstance(algo_result, dict) or 'confidence' not in algo_result:
                    logger.warning("Advanced algorithm detector returned invalid result format")
                    algo_result = {'algorithm_detected': False, 'confidence': 0.0, 'error': 'Invalid result format'}

                if algo_result.get('algorithm_detected'):
                    logger.info(f"Algorithm detected: {algo_result.get('algorithm', 'Unknown')} with {algo_result.get('confidence', 0)*100:.1f}% confidence")
                else:
                    logger.debug("No specific algorithm detected")

                phase3_results['advanced_algorithm'] = algo_result
            except ImportError as e:
                logger.warning(f"Advanced algorithm detector module not available: {e}")
                phase3_results['advanced_algorithm'] = {
                    'algorithm_detected': False,
                    'confidence': 0.0,
                    'error': f'Import failed: {str(e)}'
                }
            except Exception as e:
                logger.error(f"Advanced algorithm detection failed: {e}", exc_info=True)
                phase3_results['advanced_algorithm'] = {
                    'algorithm_detected': False,
                    'confidence': 0.0,
                    'error': str(e)
                }

            # Confidence Aggregator
            try:
                logger.debug("Initializing Confidence Aggregator")
                from .confidence_aggregator import ConfidenceAggregator
                conf_aggregator = ConfidenceAggregator()

                # Compile all detection findings
                detailed_findings = []

                # Add Phase 1 detections
                for tool in base_results.get('detected_tools', []):
                    detailed_findings.append({
                        'detector': tool,
                        'confidence': 0.85,
                        'details': {}
                    })

                # Add Phase 2 detections
                if phase2_results.get('pqc_analysis', {}).get('pqc_detected'):
                    detailed_findings.append({
                        'detector': 'pqc_detector',
                        'confidence': phase2_results['pqc_analysis'].get('confidence', 0.0),
                        'details': phase2_results['pqc_analysis']
                    })

                # Check blockchain detection
                blockchain_analysis = phase2_results.get('blockchain_analysis', {})
                addresses_dict = blockchain_analysis.get('addresses', {})
                total_addresses = sum(len(addrs) for addrs in addresses_dict.values() if isinstance(addrs, list))

                if blockchain_analysis.get('blockchain_detected') or total_addresses > 0:
                    detailed_findings.append({
                        'detector': 'blockchain_detector',
                        'confidence': blockchain_analysis.get('confidence', 0.0),
                        'details': blockchain_analysis
                    })

                if phase2_results.get('ai_stego_patterns', {}).get('ai_generated'):
                    detailed_findings.append({
                        'detector': 'ai_stego_detector',
                        'confidence': phase2_results['ai_stego_patterns'].get('confidence', 0.0),
                        'details': phase2_results['ai_stego_patterns']
                    })

                # Add Advanced Algorithm detection
                if phase3_results.get('advanced_algorithm', {}).get('algorithm_detected'):
                    detailed_findings.append({
                        'detector': 'advanced_algorithm_detector',
                        'confidence': phase3_results['advanced_algorithm'].get('confidence', 0.0),
                        'details': phase3_results['advanced_algorithm']
                    })

                # Aggregate confidence
                anomaly_count = base_results.get('anomaly_count', 0)
                logger.debug(f"Aggregating confidence from {len(detailed_findings)} detections")
                aggregated = conf_aggregator.aggregate(detailed_findings, anomaly_count)

                logger.info(f"Confidence aggregated: {aggregated.get('final_confidence', 0)*100:.1f}% from {aggregated.get('detections_count', 0)} detections")
                phase3_results['confidence_aggregation'] = aggregated
            except ImportError as e:
                logger.warning(f"Confidence aggregator module not available: {e}")
                phase3_results['confidence_aggregation'] = {
                    'error': f'Import failed: {str(e)}',
                    'final_confidence': base_results.get('confidence', 0.0)
                }
            except Exception as e:
                logger.error(f"Confidence aggregation failed: {e}", exc_info=True)
                phase3_results['confidence_aggregation'] = {
                    'error': str(e),
                    'final_confidence': base_results.get('confidence', 0.0)
                }

            # Extract Probe 11 & 12 results from decryption
            logger.debug("Extracting Probe 11 & 12 results from decryption")
            decryption = base_results.get('decryption_results', {})
            probes = decryption.get('probes', [])

            # Find Probe 11 (PQC)
            probe_11 = next((p for p in probes if p.get('name') == 'pqc_lattice_decode'), None)
            if probe_11:
                logger.debug(f"Probe 11 (PQC) executed: {probe_11.get('success', False)}")
                phase3_results['probe_11_results'] = probe_11
            else:
                logger.debug("Probe 11 (PQC) not executed")
                phase3_results['probe_11_results'] = {'executed': False}

            # Find Probe 12 (Blockchain)
            probe_12 = next((p for p in probes if p.get('name') == 'blockchain_payload_extract'), None)
            if probe_12:
                logger.debug(f"Probe 12 (Blockchain) executed: {probe_12.get('success', False)}")
                phase3_results['probe_12_results'] = probe_12
            else:
                logger.debug("Probe 12 (Blockchain) not executed")
                phase3_results['probe_12_results'] = {'executed': False}

            logger.info("Phase 3 enhancements completed")
            return phase3_results

        except Exception as e:
            # Graceful degradation
            logger.error(f"Phase 3 enhancements failed catastrophically: {e}", exc_info=True)
            return {
                'error': str(e),
                'advanced_algorithm': {'algorithm_detected': False, 'confidence': 0.0},
                'confidence_aggregation': {},
                'probe_11_results': {'executed': False},
                'probe_12_results': {'executed': False}
            }
