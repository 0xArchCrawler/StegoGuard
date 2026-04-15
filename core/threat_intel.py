"""
StegoGuard Threat Intelligence Engine
Advanced 2026 APT detection and threat analysis
"""

import asyncio
from typing import Dict, List, Optional
from datetime import datetime
import json
import hashlib
import base64


class ThreatIntelligence:
    """
    Advanced threat intelligence with 2026 APT detection capabilities
    Detects latest steganography techniques used by threat actors
    """

    def __init__(self):
        self._threat_database = {}
        self._analysis_cache = {}
        self._apt_signatures = self._load_apt_signatures()

    def _load_apt_signatures(self) -> Dict:
        """
        Load comprehensive threat intelligence signatures
        Includes 68 threat actors (46 APT + 22 non-APT) with full MITRE ATT&CK mappings
        Updated: April 2026
        """
        return {
            # ===== RUSSIAN APT GROUPS =====
            'apt29': {
                'name': 'APT29 (Cozy Bear)',
                'aliases': ['Cozy Bear', 'The Dukes', 'YTTRIUM'],
                'country': 'Russia',
                'organization': 'SVR (Foreign Intelligence Service)',
                'mitre_techniques': ['T1041', 'T1027', 'T1573.001', 'T1071.001', 'T1564'],
                'mitre_tactics': ['TA0011', 'TA0010', 'TA0005'],
                'steganography_techniques': ['hybrid_dct_lsb', 'lattice_crypto', 'gan_synthetic'],
                'preferred_containers': ['JPEG', 'PNG', 'PDF'],
                'encryption_methods': ['AES-256', 'ChaCha20', 'Post-Quantum'],
                'keywords': ['exfil', 'target owned', 'next phase', 'diplomatic'],
                'c2_patterns': ['domain_fronting', 'steganography', 'cloud_abuse'],
                'tools': ['Cobalt Strike', 'WellMess', 'SUNBURST'],
                'targeting': {
                    'sectors': ['Government', 'Defense', 'Think Tanks', 'Healthcare'],
                    'regions': ['North America', 'Europe', 'Middle East']
                },
                'first_observed': '2008-01-01',
                'last_confirmed': '2026-03-15',
                'activity_status': 'ACTIVE',
                'complexity': 'CRITICAL',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 50
            },
            'apt28': {
                'name': 'APT28 (Fancy Bear)',
                'aliases': ['Fancy Bear', 'Sofacy', 'Sednit', 'Pawn Storm'],
                'country': 'Russia',
                'organization': 'GRU (Military Intelligence)',
                'mitre_techniques': ['T1071.001', 'T1048', 'T1132', 'T1027', 'T1041'],
                'mitre_tactics': ['TA0011', 'TA0010', 'TA0005'],
                'steganography_techniques': ['spread_spectrum', 'qr_manipulation', 'audio_exif'],
                'preferred_containers': ['JPEG', 'PNG', 'GIF'],
                'encryption_methods': ['AES-256', 'RC4'],
                'keywords': ['beacon', 'c2', 'payload', 'military'],
                'c2_patterns': ['dns_tunneling', 'steganography', 'legitimate_services'],
                'tools': ['X-Agent', 'Sofacy', 'Komplex'],
                'targeting': {
                    'sectors': ['Military', 'Government', 'Media', 'Energy'],
                    'regions': ['Europe', 'Middle East', 'Central Asia']
                },
                'first_observed': '2007-01-01',
                'last_confirmed': '2026-02-28',
                'activity_status': 'ACTIVE',
                'complexity': 'HIGH',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 50
            },
            'apt44': {
                'name': 'APT44 (Sandworm)',
                'aliases': ['Sandworm', 'Voodoo Bear', 'IRIDIUM'],
                'country': 'Russia',
                'organization': 'GRU Unit 74455',
                'mitre_techniques': ['T1486', 'T1485', 'T1490', 'T1082', 'T1027'],
                'mitre_tactics': ['TA0040', 'TA0005', 'TA0007'],
                'steganography_techniques': ['multi_layer', 'lsb_advanced', 'metadata_abuse'],
                'preferred_containers': ['JPEG', 'PNG', 'BMP'],
                'encryption_methods': ['AES-256', 'RSA-2048'],
                'keywords': ['wiper', 'ics', 'scada', 'critical infrastructure'],
                'c2_patterns': ['tor', 'proxy_chains', 'legitimate_services'],
                'tools': ['BlackEnergy', 'NotPetya', 'Industroyer'],
                'targeting': {
                    'sectors': ['Energy', 'ICS/OT', 'Critical Infrastructure', 'Government'],
                    'regions': ['Ukraine', 'Europe', 'Middle East']
                },
                'first_observed': '2009-01-01',
                'last_confirmed': '2026-01-20',
                'activity_status': 'ACTIVE',
                'complexity': 'CRITICAL',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 50
            },
            'gamaredon': {
                'name': 'Gamaredon',
                'aliases': ['Primitive Bear', 'ACTINIUM', 'Armageddon'],
                'country': 'Russia',
                'organization': 'FSB',
                'mitre_techniques': ['T1566.001', 'T1027', 'T1071.001', 'T1564'],
                'mitre_tactics': ['TA0001', 'TA0005', 'TA0011'],
                'steganography_techniques': ['lsb_advanced', 'metadata_abuse', 'deepfake_noise'],
                'preferred_containers': ['JPEG', 'PNG', 'DOC', 'XLS'],
                'encryption_methods': ['AES-128', 'Base64'],
                'keywords': ['ukraine', 'government', 'military', 'document'],
                'c2_patterns': ['http', 'https', 'cloud_storage'],
                'tools': ['Pterodo', 'custom VBS scripts', 'PowerShell'],
                'targeting': {
                    'sectors': ['Government', 'Military', 'Law Enforcement'],
                    'regions': ['Ukraine', 'Eastern Europe']
                },
                'first_observed': '2013-01-01',
                'last_confirmed': '2026-03-10',
                'activity_status': 'ACTIVE',
                'complexity': 'MEDIUM',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 45
            },
            'dragonfly': {
                'name': 'Dragonfly (Energetic Bear)',
                'aliases': ['Energetic Bear', 'DYMALLOY', 'Crouching Yeti'],
                'country': 'Russia',
                'organization': 'FSB',
                'mitre_techniques': ['T1195', 'T1021', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0001', 'TA0008', 'TA0011'],
                'steganography_techniques': ['hybrid_dct_lsb', 'metadata_abuse', 'spread_spectrum'],
                'preferred_containers': ['JPEG', 'PNG', 'PDF'],
                'encryption_methods': ['AES-256', 'Blowfish'],
                'keywords': ['energy', 'ics', 'aviation', 'supply chain'],
                'c2_patterns': ['watering_hole', 'legitimate_services', 'steganography'],
                'tools': ['Havex', 'Karagany', 'Goodor'],
                'targeting': {
                    'sectors': ['Energy', 'Aviation', 'Manufacturing', 'ICS/OT'],
                    'regions': ['North America', 'Europe', 'Turkey']
                },
                'first_observed': '2010-01-01',
                'last_confirmed': '2025-11-15',
                'activity_status': 'ACTIVE',
                'complexity': 'HIGH',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 50
            },
            'turla': {
                'name': 'Turla',
                'aliases': ['Snake', 'Uroburos', 'Waterbug'],
                'country': 'Russia',
                'organization': 'FSB',
                'mitre_techniques': ['T1071', 'T1048', 'T1564', 'T1027', 'T1573'],
                'mitre_tactics': ['TA0011', 'TA0010', 'TA0005'],
                'steganography_techniques': ['satellite_comms', 'lsb_advanced', 'metadata_abuse'],
                'preferred_containers': ['JPEG', 'PNG', 'GIF'],
                'encryption_methods': ['AES-256', 'CAST-128', 'Custom'],
                'keywords': ['satellite', 'diplomatic', 'intel', 'government'],
                'c2_patterns': ['satellite_internet', 'compromised_websites', 'steganography'],
                'tools': ['Turla', 'Snake', 'Carbon', 'Kazuar'],
                'targeting': {
                    'sectors': ['Government', 'Diplomatic', 'Military', 'Education'],
                    'regions': ['Europe', 'Middle East', 'Asia']
                },
                'first_observed': '1996-01-01',
                'last_confirmed': '2026-02-20',
                'activity_status': 'ACTIVE',
                'complexity': 'HIGH',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 50
            },

            # ===== CHINESE APT GROUPS =====
            'apt1': {
                'name': 'APT1 (Comment Crew)',
                'aliases': ['Comment Crew', 'Comment Panda', 'Byzantine Candor'],
                'country': 'China',
                'organization': 'PLA Unit 61398',
                'mitre_techniques': ['T1041', 'T1560', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0010', 'TA0009', 'TA0011'],
                'steganography_techniques': ['lsb_advanced', 'hybrid_dct_lsb', 'metadata_abuse'],
                'preferred_containers': ['JPEG', 'PNG', 'RAR'],
                'encryption_methods': ['AES-128', 'RC4'],
                'keywords': ['exfil', 'intellectual property', 'trade secrets'],
                'c2_patterns': ['http', 'https', 'custom_protocols'],
                'tools': ['WEBC2', 'BACKDOOR.BARKIOFORK', 'Seasalt'],
                'targeting': {
                    'sectors': ['Technology', 'Aerospace', 'Energy', 'Manufacturing'],
                    'regions': ['North America', 'Europe']
                },
                'first_observed': '2006-01-01',
                'last_confirmed': '2024-06-30',
                'activity_status': 'DORMANT',
                'complexity': 'MEDIUM',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 45
            },
            'apt10': {
                'name': 'APT10 (MenuPass)',
                'aliases': ['MenuPass', 'Stone Panda', 'Red Apollo', 'CVNX'],
                'country': 'China',
                'organization': 'MSS',
                'mitre_techniques': ['T1199', 'T1078', 'T1027', 'T1071.001', 'T1041'],
                'mitre_tactics': ['TA0001', 'TA0011', 'TA0010'],
                'steganography_techniques': ['multi_layer', 'qr_manipulation', 'hybrid_dct_lsb'],
                'preferred_containers': ['JPEG', 'PNG', 'GIF'],
                'encryption_methods': ['AES-256', 'RSA-2048'],
                'keywords': ['msp', 'supply chain', 'cloud', 'telecom'],
                'c2_patterns': ['cloud_services', 'compromised_msp', 'steganography'],
                'tools': ['PlugX', 'Poison Ivy', 'QuasarRAT', 'RedLeaves'],
                'targeting': {
                    'sectors': ['MSPs', 'Telecommunications', 'IT Services', 'Government'],
                    'regions': ['Global']
                },
                'first_observed': '2009-01-01',
                'last_confirmed': '2026-01-15',
                'activity_status': 'ACTIVE',
                'complexity': 'HIGH',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 50
            },
            'apt30': {
                'name': 'APT30 (Naikon)',
                'aliases': ['Naikon', 'Override Panda'],
                'country': 'China',
                'organization': 'PLA',
                'mitre_techniques': ['T1053', 'T1057', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0003', 'TA0007', 'TA0011'],
                'steganography_techniques': ['palette_reorder', 'audio_exif', 'lsb_advanced'],
                'preferred_containers': ['JPEG', 'PNG', 'BMP'],
                'encryption_methods': ['AES-128', 'XOR'],
                'keywords': ['maritime', 'military', 'asean', 'political'],
                'c2_patterns': ['http', 'custom_protocols', 'steganography'],
                'tools': ['Naikon RAT', 'SysUpdate', 'RarStar'],
                'targeting': {
                    'sectors': ['Government', 'Military', 'Maritime', 'Political'],
                    'regions': ['Southeast Asia', 'ASEAN']
                },
                'first_observed': '2005-01-01',
                'last_confirmed': '2025-09-20',
                'activity_status': 'ACTIVE',
                'complexity': 'HIGH',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 50
            },
            'apt40': {
                'name': 'APT40 (Leviathan)',
                'aliases': ['Leviathan', 'TEMP.Periscope', 'TEMP.Jumper'],
                'country': 'China',
                'organization': 'MSS Hainan',
                'mitre_techniques': ['T1190', 'T1505', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0001', 'TA0003', 'TA0011'],
                'steganography_techniques': ['lsb_advanced', 'metadata_abuse', 'hybrid_dct_lsb'],
                'preferred_containers': ['JPEG', 'PNG', 'Satellite Images'],
                'encryption_methods': ['AES-256'],
                'keywords': ['naval', 'maritime', 'south china sea', 'shipping'],
                'c2_patterns': ['web_shells', 'dns_tunneling', 'steganography'],
                'tools': ['NanHaiShu', 'Murkytop', 'China Chopper'],
                'targeting': {
                    'sectors': ['Maritime', 'Naval', 'Shipping', 'Research'],
                    'regions': ['Global', 'South China Sea region']
                },
                'first_observed': '2013-01-01',
                'last_confirmed': '2026-02-10',
                'activity_status': 'ACTIVE',
                'complexity': 'HIGH',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 50
            },
            'winnti': {
                'name': 'Winnti Group',
                'aliases': ['APT41 overlap', 'BARIUM', 'Wicked Panda'],
                'country': 'China',
                'organization': 'MSS',
                'mitre_techniques': ['T1553.002', 'T1195.002', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0005', 'TA0042', 'TA0011'],
                'steganography_techniques': ['multi_layer', 'gan_synthetic', 'lsb_advanced'],
                'preferred_containers': ['PNG', 'DDS', 'Game Assets'],
                'encryption_methods': ['AES-256', 'Custom'],
                'keywords': ['gaming', 'supply chain', 'code signing', 'certificate'],
                'c2_patterns': ['https', 'steganography', 'gaming_protocols'],
                'tools': ['Winnti', 'PortReuse', 'ShadowPad'],
                'targeting': {
                    'sectors': ['Gaming', 'Technology', 'Software Publishers', 'Healthcare'],
                    'regions': ['Global']
                },
                'first_observed': '2010-01-01',
                'last_confirmed': '2026-03-05',
                'activity_status': 'ACTIVE',
                'complexity': 'CRITICAL',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 50
            },
            'mustang_panda': {
                'name': 'MUSTANG PANDA',
                'aliases': ['Bronze President', 'TA416', 'Red Delta'],
                'country': 'China',
                'organization': 'MSS',
                'mitre_techniques': ['T1574.002', 'T1091', 'T1027', 'T1566.001'],
                'mitre_tactics': ['TA0001', 'TA0008', 'TA0005'],
                'steganography_techniques': ['lsb_advanced', 'multi_layer', 'metadata_abuse'],
                'preferred_containers': ['JPEG', 'PNG', 'USB Images'],
                'encryption_methods': ['AES-128', 'RC4'],
                'keywords': ['usb', 'southeast asia', 'government', 'ngo'],
                'c2_patterns': ['http', 'https', 'cloud_storage'],
                'tools': ['PlugX', 'Cobalt Strike', 'custom loaders'],
                'targeting': {
                    'sectors': ['Government', 'NGOs', 'Religious', 'Political'],
                    'regions': ['Southeast Asia', 'Mongolia', 'Europe']
                },
                'first_observed': '2012-01-01',
                'last_confirmed': '2026-02-25',
                'activity_status': 'ACTIVE',
                'complexity': 'MEDIUM',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 45
            },
            'apt31': {
                'name': 'APT31 (Zirconium)',
                'aliases': ['Zirconium', 'Judgment Panda'],
                'country': 'China',
                'organization': 'MSS',
                'mitre_techniques': ['T1133', 'T1190', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0001', 'TA0011', 'TA0006'],
                'steganography_techniques': ['hybrid_dct_lsb', 'metadata_abuse', 'spread_spectrum'],
                'preferred_containers': ['JPEG', 'PNG', 'PDF'],
                'encryption_methods': ['AES-256', 'RSA-4096'],
                'keywords': ['government', 'political', 'vpn', 'zero-day'],
                'c2_patterns': ['vpn_compromise', 'steganography', 'https'],
                'tools': ['Zirconium toolset', 'custom exploits'],
                'targeting': {
                    'sectors': ['Government', 'Defense', 'Aerospace', 'Think Tanks'],
                    'regions': ['North America', 'Europe']
                },
                'first_observed': '2016-01-01',
                'last_confirmed': '2026-01-30',
                'activity_status': 'ACTIVE',
                'complexity': 'HIGH',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 50
            },
            'apt27': {
                'name': 'APT27 (Emissary Panda)',
                'aliases': ['Emissary Panda', 'Bronze Union', 'Iron Tiger'],
                'country': 'China',
                'organization': 'PLA',
                'mitre_techniques': ['T1203', 'T1055', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0002', 'TA0004', 'TA0011'],
                'steganography_techniques': ['lsb_advanced', 'dct', 'metadata_abuse'],
                'preferred_containers': ['JPEG', 'PNG', 'Corporate Logos'],
                'encryption_methods': ['AES-128', 'RC4'],
                'keywords': ['intellectual property', 'trade secrets', 'aerospace'],
                'c2_patterns': ['http', 'https', 'steganography'],
                'tools': ['HyperBro', 'ZxShell', 'custom RATs'],
                'targeting': {
                    'sectors': ['Technology', 'Aerospace', 'Defense', 'Manufacturing'],
                    'regions': ['North America', 'Europe', 'Middle East']
                },
                'first_observed': '2010-01-01',
                'last_confirmed': '2025-12-15',
                'activity_status': 'ACTIVE',
                'complexity': 'MEDIUM',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 45
            },
            'earth_lusca': {
                'name': 'Earth Lusca',
                'aliases': ['TAG-22'],
                'country': 'China',
                'organization': 'Unknown',
                'mitre_techniques': ['T1505.003', 'T1071.001', 'T1027', 'T1041'],
                'mitre_tactics': ['TA0003', 'TA0011', 'TA0010'],
                'steganography_techniques': ['lsb_advanced', 'metadata_abuse', 'hybrid_dct_lsb'],
                'preferred_containers': ['JPEG', 'PNG', 'GIF'],
                'encryption_methods': ['AES-256', 'ChaCha20'],
                'keywords': ['web shell', 'cobalt strike', 'government', 'telecom'],
                'c2_patterns': ['web_shells', 'steganography', 'cloud_services'],
                'tools': ['Cobalt Strike', 'China Chopper', 'ShadowPad'],
                'targeting': {
                    'sectors': ['Government', 'Telecommunications', 'Technology', 'Media'],
                    'regions': ['Asia', 'Middle East', 'Latin America']
                },
                'first_observed': '2019-01-01',
                'last_confirmed': '2026-02-05',
                'activity_status': 'ACTIVE',
                'complexity': 'HIGH',
                'intelligence_confidence': 'MEDIUM',
                'attribution_threshold': 45
            },
            'hafnium': {
                'name': 'Hafnium',
                'aliases': ['Operation Exchange Marauder'],
                'country': 'China',
                'organization': 'MSS',
                'mitre_techniques': ['T1190', 'T1003', 'T1505.003', 'T1027'],
                'mitre_tactics': ['TA0001', 'TA0006', 'TA0003'],
                'steganography_techniques': ['lsb_advanced', 'metadata_abuse'],
                'preferred_containers': ['JPEG', 'PNG', 'Exchange data'],
                'encryption_methods': ['AES-256'],
                'keywords': ['exchange', 'proxylogon', 'proxyshell', 'web shell'],
                'c2_patterns': ['web_shells', 'https', 'steganography'],
                'tools': ['China Chopper', 'Nishang', 'PowerCat'],
                'targeting': {
                    'sectors': ['Defense', 'Research', 'Law Firms', 'Infectious Disease'],
                    'regions': ['United States', 'Europe']
                },
                'first_observed': '2021-01-01',
                'last_confirmed': '2025-08-10',
                'activity_status': 'ACTIVE',
                'complexity': 'HIGH',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 50
            },

            # ===== NORTH KOREAN APT GROUPS =====
            'lazarus': {
                'name': 'Lazarus Group',
                'aliases': ['Hidden Cobra', 'TEMP.Hermit', 'Labyrinth Chollima'],
                'country': 'North Korea',
                'organization': 'RGB (Reconnaissance General Bureau)',
                'mitre_techniques': ['T1486', 'T1005', 'T1027', 'T1071.001', 'T1041'],
                'mitre_tactics': ['TA0040', 'TA0009', 'TA0010'],
                'steganography_techniques': ['wavelet_transform', 'palette_reorder', 'deepfake_noise', 'multi_layer'],
                'preferred_containers': ['JPEG', 'PNG', 'BMP'],
                'encryption_methods': ['AES-256', 'RSA-2048', 'Custom'],
                'keywords': ['bank', 'swift', 'transfer', 'cryptocurrency', 'wiper'],
                'c2_patterns': ['tor', 'proxy_chains', 'steganography', 'cloud_services'],
                'tools': ['Destover', 'WannaCry', 'FASTCash', 'AppleJeus'],
                'targeting': {
                    'sectors': ['Financial', 'Cryptocurrency', 'Defense', 'Media'],
                    'regions': ['Global']
                },
                'first_observed': '2009-01-01',
                'last_confirmed': '2026-03-20',
                'activity_status': 'ACTIVE',
                'complexity': 'CRITICAL',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 50
            },
            'kimsuky': {
                'name': 'Kimsuky',
                'aliases': ['Velvet Chollima', 'Black Banshee', 'THALLIUM'],
                'country': 'North Korea',
                'organization': 'RGB',
                'mitre_techniques': ['T1566.001', 'T1056.001', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0001', 'TA0006', 'TA0009'],
                'steganography_techniques': ['lsb_advanced', 'metadata_abuse', 'deepfake_noise'],
                'preferred_containers': ['JPEG', 'PNG', 'HWP', 'DOC'],
                'encryption_methods': ['AES-128', 'RC4'],
                'keywords': ['think tank', 'nuclear', 'policy', 'intelligence'],
                'c2_patterns': ['http', 'https', 'email', 'cloud_storage'],
                'tools': ['BabyShark', 'Gold Dragon', 'AppleSeed'],
                'targeting': {
                    'sectors': ['Think Tanks', 'Policy', 'Academia', 'Research'],
                    'regions': ['South Korea', 'United States', 'Europe']
                },
                'first_observed': '2012-01-01',
                'last_confirmed': '2026-03-01',
                'activity_status': 'ACTIVE',
                'complexity': 'MEDIUM',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 45
            },
            'andariel': {
                'name': 'Andariel',
                'aliases': ['Silent Chollima', 'Onyx Sleet'],
                'country': 'North Korea',
                'organization': 'RGB Lab 110',
                'mitre_techniques': ['T1486', 'T1005', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0040', 'TA0009', 'TA0011'],
                'steganography_techniques': ['lsb_advanced', 'hybrid_dct_lsb', 'metadata_abuse'],
                'preferred_containers': ['JPEG', 'PNG', 'PDF'],
                'encryption_methods': ['AES-256', 'RSA'],
                'keywords': ['atm', 'financial', 'military', 'south korea'],
                'c2_patterns': ['http', 'https', 'steganography'],
                'tools': ['Gh0st RAT', 'Rifdoor', 'Andarat'],
                'targeting': {
                    'sectors': ['Financial', 'Military', 'Defense', 'Critical Infrastructure'],
                    'regions': ['South Korea', 'Global Financial']
                },
                'first_observed': '2015-01-01',
                'last_confirmed': '2026-02-15',
                'activity_status': 'ACTIVE',
                'complexity': 'MEDIUM',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 45
            },
            'bluenoroff': {
                'name': 'Bluenoroff (APT38)',
                'aliases': ['APT38', 'Stardust Chollima'],
                'country': 'North Korea',
                'organization': 'RGB',
                'mitre_techniques': ['T1565.001', 'T1491', 'T1027', 'T1071.001', 'T1041'],
                'mitre_tactics': ['TA0040', 'TA0010', 'TA0011'],
                'steganography_techniques': ['multi_layer', 'lsb_advanced', 'hybrid_dct_lsb'],
                'preferred_containers': ['JPEG', 'PNG', 'PDF'],
                'encryption_methods': ['AES-256', 'Custom'],
                'keywords': ['swift', 'cryptocurrency', 'exchange', 'bank heist'],
                'c2_patterns': ['https', 'tor', 'steganography', 'cryptocurrency_networks'],
                'tools': ['PowerRatankba', 'custom malware'],
                'targeting': {
                    'sectors': ['Banks', 'Cryptocurrency', 'Financial', 'FinTech'],
                    'regions': ['Global']
                },
                'first_observed': '2014-01-01',
                'last_confirmed': '2026-01-25',
                'activity_status': 'ACTIVE',
                'complexity': 'CRITICAL',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 50
            },

            # ===== IRANIAN APT GROUPS =====
            'apt33': {
                'name': 'APT33 (Elfin)',
                'aliases': ['Elfin', 'Holmium', 'Refined Kitten'],
                'country': 'Iran',
                'organization': 'IRGC',
                'mitre_techniques': ['T1485', 'T1078', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0040', 'TA0006', 'TA0011'],
                'steganography_techniques': ['lsb_advanced', 'metadata_abuse', 'hybrid_dct_lsb'],
                'preferred_containers': ['JPEG', 'PNG', 'Aviation Images'],
                'encryption_methods': ['AES-128', 'RC4'],
                'keywords': ['aviation', 'energy', 'petrochemical', 'wiper'],
                'c2_patterns': ['http', 'https', 'dns_tunneling'],
                'tools': ['Shamoon', 'Dropshot', 'Nanocore'],
                'targeting': {
                    'sectors': ['Aviation', 'Energy', 'Petrochemical', 'Government'],
                    'regions': ['Middle East', 'United States']
                },
                'first_observed': '2013-01-01',
                'last_confirmed': '2025-11-20',
                'activity_status': 'ACTIVE',
                'complexity': 'MEDIUM',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 45
            },
            'apt34': {
                'name': 'APT34 (OilRig)',
                'aliases': ['OilRig', 'Helix Kitten', 'Cobalt Gypsy'],
                'country': 'Iran',
                'organization': 'MOIS',
                'mitre_techniques': ['T1071.004', 'T1505.003', 'T1027', 'T1041'],
                'mitre_tactics': ['TA0011', 'TA0003', 'TA0010'],
                'steganography_techniques': ['metadata_abuse', 'dns_stego', 'lsb_advanced'],
                'preferred_containers': ['JPEG', 'PNG', 'DNS Records'],
                'encryption_methods': ['AES-256', 'Base64'],
                'keywords': ['dns', 'web shell', 'middle east', 'government'],
                'c2_patterns': ['dns_tunneling', 'web_shells', 'steganography'],
                'tools': ['TwoFace', 'BondUpdater', 'QUADAGENT'],
                'targeting': {
                    'sectors': ['Government', 'Financial', 'Energy', 'Telecommunications'],
                    'regions': ['Middle East', 'Europe']
                },
                'first_observed': '2014-01-01',
                'last_confirmed': '2026-01-10',
                'activity_status': 'ACTIVE',
                'complexity': 'HIGH',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 50
            },
            'apt35': {
                'name': 'APT35 (Charming Kitten)',
                'aliases': ['Charming Kitten', 'Phosphorus', 'Newscaster'],
                'country': 'Iran',
                'organization': 'IRGC',
                'mitre_techniques': ['T1566.002', 'T1589', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0001', 'TA0043', 'TA0011'],
                'steganography_techniques': ['lsb_advanced', 'metadata_abuse'],
                'preferred_containers': ['JPEG', 'PNG', 'Phishing Images'],
                'encryption_methods': ['AES-128'],
                'keywords': ['phishing', 'credential', 'academic', 'journalist'],
                'c2_patterns': ['fake_websites', 'email', 'https'],
                'tools': ['TOWELROOT', 'PINEFLOWER', 'custom phishing'],
                'targeting': {
                    'sectors': ['Academia', 'Media', 'Government', 'Activists'],
                    'regions': ['Middle East', 'United States', 'Europe']
                },
                'first_observed': '2011-01-01',
                'last_confirmed': '2026-02-20',
                'activity_status': 'ACTIVE',
                'complexity': 'MEDIUM',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 45
            },
            'apt39': {
                'name': 'APT39 (Chafer)',
                'aliases': ['Chafer', 'ITG07'],
                'country': 'Iran',
                'organization': 'MOIS',
                'mitre_techniques': ['T1190', 'T1021.002', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0001', 'TA0008', 'TA0010'],
                'steganography_techniques': ['lsb_advanced', 'metadata_abuse', 'hybrid_dct_lsb'],
                'preferred_containers': ['JPEG', 'PNG'],
                'encryption_methods': ['AES-128', 'RC4'],
                'keywords': ['telecom', 'travel', 'call records', 'sql injection'],
                'c2_patterns': ['http', 'https', 'psexec'],
                'tools': ['SEAWEED', 'CACHEMONEY', 'POWBAT'],
                'targeting': {
                    'sectors': ['Telecommunications', 'Travel', 'IT Services', 'High-Tech'],
                    'regions': ['Middle East', 'Global']
                },
                'first_observed': '2014-01-01',
                'last_confirmed': '2025-10-15',
                'activity_status': 'ACTIVE',
                'complexity': 'MEDIUM',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 45
            },
            'muddywater': {
                'name': 'MuddyWater',
                'aliases': ['SeedWorm', 'TEMP.Zagros', 'Static Kitten'],
                'country': 'Iran',
                'organization': 'MOIS',
                'mitre_techniques': ['T1059.001', 'T1105', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0002', 'TA0011', 'TA0005'],
                'steganography_techniques': ['lsb_advanced', 'metadata_abuse', 'powershell_stego'],
                'preferred_containers': ['JPEG', 'PNG', 'PowerShell Scripts'],
                'encryption_methods': ['Base64', 'XOR'],
                'keywords': ['powershell', 'government', 'telecom', 'oil'],
                'c2_patterns': ['http', 'https', 'dns', 'cloud_services'],
                'tools': ['PowerShell', 'POWERSTATS', 'custom tools'],
                'targeting': {
                    'sectors': ['Government', 'Telecommunications', 'Oil & Gas', 'Defense'],
                    'regions': ['Middle East', 'Asia', 'Europe']
                },
                'first_observed': '2017-01-01',
                'last_confirmed': '2026-03-01',
                'activity_status': 'ACTIVE',
                'complexity': 'MEDIUM',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 45
            },

            # ===== OTHER NATION-STATE GROUPS =====
            'oceanlotus': {
                'name': 'OceanLotus (APT32)',
                'aliases': ['APT32', 'SeaLotus', 'Cobalt Kitty'],
                'country': 'Vietnam',
                'organization': 'Unknown',
                'mitre_techniques': ['T1189', 'T1204', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0001', 'TA0002', 'TA0011'],
                'steganography_techniques': ['multi_layer', 'lsb_advanced', 'hybrid_dct_lsb'],
                'preferred_containers': ['JPEG', 'PNG', 'BMP'],
                'encryption_methods': ['AES-256', 'RSA-2048'],
                'keywords': ['dissident', 'foreign corporation', 'journalist'],
                'c2_patterns': ['https', 'cloud_services', 'steganography'],
                'tools': ['Cobalt Strike', 'Denis', 'Ratsnif'],
                'targeting': {
                    'sectors': ['Foreign Corporations', 'Government', 'Media', 'Activists'],
                    'regions': ['Southeast Asia', 'Europe']
                },
                'first_observed': '2012-01-01',
                'last_confirmed': '2026-01-05',
                'activity_status': 'ACTIVE',
                'complexity': 'HIGH',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 50
            },
            'apt37': {
                'name': 'APT37 (Reaper)',
                'aliases': ['Reaper', 'Group123', 'ScarCruft'],
                'country': 'North Korea',
                'organization': 'RGB',
                'mitre_techniques': ['T1203', 'T1566', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0001', 'TA0002', 'TA0011'],
                'steganography_techniques': ['lsb_advanced', 'metadata_abuse', 'korean_doc_stego'],
                'preferred_containers': ['JPEG', 'PNG', 'HWP', 'DOC'],
                'encryption_methods': ['AES-128', 'Custom'],
                'keywords': ['defector', 'south korea', 'chemical', 'electronics'],
                'c2_patterns': ['http', 'https', 'steganography'],
                'tools': ['SHUTTERSPEED', 'SLOWDRIFT', 'RICECURRY'],
                'targeting': {
                    'sectors': ['Government', 'Chemical', 'Electronics', 'Manufacturing'],
                    'regions': ['South Korea', 'Japan']
                },
                'first_observed': '2012-01-01',
                'last_confirmed': '2025-09-30',
                'activity_status': 'ACTIVE',
                'complexity': 'MEDIUM',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 45
            },
            'equation_group': {
                'name': 'Equation Group',
                'aliases': ['NSA TAO'],
                'country': 'United States',
                'organization': 'NSA',
                'mitre_techniques': ['T1542.003', 'T1495', 'T1027', 'T1573', 'T1041'],
                'mitre_tactics': ['TA0003', 'TA0005', 'TA0011', 'TA0010'],
                'steganography_techniques': ['quantum_resistant', 'multi_layer', 'gan_synthetic', 'firmware_stego'],
                'preferred_containers': ['ALL'],
                'encryption_methods': ['Custom', 'AES-256', 'Post-Quantum'],
                'keywords': ['firmware', 'hard drive', 'sophisticated', 'zero-day'],
                'c2_patterns': ['satellite', 'steganography', 'firmware_implants'],
                'tools': ['STUXNET', 'EternalBlue', 'DoublePulsar', 'STRAITBIZARRE'],
                'targeting': {
                    'sectors': ['Intelligence', 'Government', 'Military', 'High-Value'],
                    'regions': ['Global']
                },
                'first_observed': '2001-01-01',
                'last_confirmed': '2017-01-01',
                'activity_status': 'UNKNOWN',
                'complexity': 'CRITICAL',
                'intelligence_confidence': 'MEDIUM',
                'attribution_threshold': 60
            },

            # ===== FINANCIALLY-MOTIVATED GROUPS =====
            'apt41': {
                'name': 'APT41 (Double Dragon)',
                'aliases': ['Double Dragon', 'Barium', 'Wicked Panda'],
                'country': 'China',
                'organization': 'MSS + Criminal',
                'mitre_techniques': ['T1195', 'T1027', 'T1071.001', 'T1041'],
                'mitre_tactics': ['TA0042', 'TA0011', 'TA0010'],
                'steganography_techniques': ['multi_layer', 'ai_evasion', 'quantum_resistant'],
                'preferred_containers': ['JPEG', 'PNG', 'Game Assets'],
                'encryption_methods': ['AES-256', 'RSA-4096', 'Custom'],
                'keywords': ['supply chain', 'backdoor', 'persistence', 'healthcare', 'gaming'],
                'c2_patterns': ['https', 'cloud_services', 'steganography', 'gaming_protocols'],
                'tools': ['Cobalt Strike', 'Winnti', 'TIDYELF'],
                'targeting': {
                    'sectors': ['Healthcare', 'Gaming', 'Supply Chain', 'Technology'],
                    'regions': ['Global']
                },
                'first_observed': '2012-01-01',
                'last_confirmed': '2026-02-28',
                'activity_status': 'ACTIVE',
                'complexity': 'CRITICAL',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 50
            },
            'fin7': {
                'name': 'FIN7 (Carbanak)',
                'aliases': ['Carbanak', 'Navigator Group'],
                'country': 'Russia',
                'organization': 'Cybercrime',
                'mitre_techniques': ['T1566.001', 'T1204.002', 'T1005', 'T1027'],
                'mitre_tactics': ['TA0001', 'TA0009', 'TA0010'],
                'steganography_techniques': ['lsb_advanced', 'metadata_abuse', 'pos_image_stego'],
                'preferred_containers': ['JPEG', 'PNG', 'Restaurant Images'],
                'encryption_methods': ['AES-256', 'RC4'],
                'keywords': ['pos', 'restaurant', 'hospitality', 'payment card'],
                'c2_patterns': ['https', 'dns', 'steganography'],
                'tools': ['Carbanak', 'GRIFFON', 'PILLOWMINT', 'Cobalt Strike'],
                'targeting': {
                    'sectors': ['Restaurants', 'Hospitality', 'Retail', 'Casinos'],
                    'regions': ['North America', 'Europe']
                },
                'first_observed': '2013-01-01',
                'last_confirmed': '2026-01-15',
                'activity_status': 'ACTIVE',
                'complexity': 'HIGH',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 50
            },
            'fin8': {
                'name': 'FIN8',
                'aliases': [],
                'country': 'Unknown',
                'organization': 'Cybercrime',
                'mitre_techniques': ['T1012', 'T1003', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0007', 'TA0006', 'TA0011'],
                'steganography_techniques': ['lsb_advanced', 'pos_stego', 'metadata_abuse'],
                'preferred_containers': ['JPEG', 'PNG'],
                'encryption_methods': ['AES-128', 'RC4'],
                'keywords': ['pos', 'payment card', 'hospitality', 'retail'],
                'c2_patterns': ['http', 'https', 'steganography'],
                'tools': ['PowerShell', 'BAF RAT', 'PowerSniff'],
                'targeting': {
                    'sectors': ['Hospitality', 'Retail', 'Insurance', 'Technology'],
                    'regions': ['North America']
                },
                'first_observed': '2016-01-01',
                'last_confirmed': '2025-10-20',
                'activity_status': 'ACTIVE',
                'complexity': 'MEDIUM',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 45
            },
            'fin11': {
                'name': 'FIN11',
                'aliases': ['TA505 overlap'],
                'country': 'Unknown',
                'organization': 'Cybercrime',
                'mitre_techniques': ['T1486', 'T1490', 'T1027', 'T1566.001'],
                'mitre_tactics': ['TA0040', 'TA0001', 'TA0011'],
                'steganography_techniques': ['lsb_advanced', 'metadata_abuse'],
                'preferred_containers': ['JPEG', 'PNG'],
                'encryption_methods': ['AES-256', 'RSA-2048'],
                'keywords': ['clop', 'ransomware', 'retail', 'healthcare'],
                'c2_patterns': ['https', 'tor', 'steganography'],
                'tools': ['Clop', 'FLAWEDAMMYY', 'FLAWEDGRACE'],
                'targeting': {
                    'sectors': ['Retail', 'Healthcare', 'Financial', 'Any High-Value'],
                    'regions': ['Global']
                },
                'first_observed': '2017-01-01',
                'last_confirmed': '2025-12-10',
                'activity_status': 'ACTIVE',
                'complexity': 'MEDIUM',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 45
            },
            'evil_corp': {
                'name': 'Evil Corp (Dridex)',
                'aliases': ['Dridex Gang', 'INDRIK SPIDER'],
                'country': 'Russia',
                'organization': 'Cybercrime',
                'mitre_techniques': ['T1539', 'T1021.001', 'T1486', 'T1027'],
                'mitre_tactics': ['TA0006', 'TA0008', 'TA0040'],
                'steganography_techniques': ['lsb_advanced', 'banking_image_stego', 'metadata_abuse'],
                'preferred_containers': ['JPEG', 'PNG', 'Bank Website Images'],
                'encryption_methods': ['AES-256', 'RSA-2048'],
                'keywords': ['dridex', 'bitpaymer', 'banking', 'credential theft'],
                'c2_patterns': ['https', 'tor', 'steganography'],
                'tools': ['Dridex', 'BitPaymer', 'WastedLocker'],
                'targeting': {
                    'sectors': ['Banks', 'Financial Institutions', 'Any High-Value'],
                    'regions': ['North America', 'Europe']
                },
                'first_observed': '2014-01-01',
                'last_confirmed': '2025-11-30',
                'activity_status': 'ACTIVE',
                'complexity': 'HIGH',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 50
            },
            'wizard_spider': {
                'name': 'WIZARD SPIDER',
                'aliases': ['Grim Spider', 'UNC1878'],
                'country': 'Russia',
                'organization': 'Cybercrime',
                'mitre_techniques': ['T1486', 'T1490', 'T1047', 'T1027'],
                'mitre_tactics': ['TA0040', 'TA0011', 'TA0008'],
                'steganography_techniques': ['lsb_advanced', 'multi_layer', 'metadata_abuse'],
                'preferred_containers': ['JPEG', 'PNG'],
                'encryption_methods': ['AES-256', 'RSA-4096'],
                'keywords': ['trickbot', 'conti', 'ryuk', 'ransomware'],
                'c2_patterns': ['https', 'tor', 'steganography'],
                'tools': ['TrickBot', 'Ryuk', 'Conti', 'BazarLoader'],
                'targeting': {
                    'sectors': ['Healthcare', 'Government', 'Education', 'Critical Infrastructure'],
                    'regions': ['Global']
                },
                'first_observed': '2016-01-01',
                'last_confirmed': '2026-02-25',
                'activity_status': 'ACTIVE',
                'complexity': 'CRITICAL',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 50
            },
            'alphv': {
                'name': 'ALPHV (BlackCat)',
                'aliases': ['BlackCat', 'Noberus'],
                'country': 'Russia',
                'organization': 'Cybercrime (RaaS)',
                'mitre_techniques': ['T1486', 'T1567', 'T1027', 'T1059'],
                'mitre_tactics': ['TA0040', 'TA0010', 'TA0002'],
                'steganography_techniques': ['lsb_advanced', 'metadata_abuse'],
                'preferred_containers': ['JPEG', 'PNG'],
                'encryption_methods': ['AES-256', 'ChaCha20'],
                'keywords': ['ransomware', 'rust', 'triple extortion', 'raas'],
                'c2_patterns': ['tor', 'https', 'steganography'],
                'tools': ['BlackCat ransomware', 'Exmatter', 'Fendr'],
                'targeting': {
                    'sectors': ['Any High-Value', 'Healthcare', 'Manufacturing'],
                    'regions': ['Global']
                },
                'first_observed': '2021-11-01',
                'last_confirmed': '2026-01-20',
                'activity_status': 'ACTIVE',
                'complexity': 'HIGH',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 50
            },
            'lockbit': {
                'name': 'LockBit',
                'aliases': ['ABCD Ransomware'],
                'country': 'Russia',
                'organization': 'Cybercrime (RaaS)',
                'mitre_techniques': ['T1486', 'T1490', 'T1027', 'T1567'],
                'mitre_tactics': ['TA0040', 'TA0010', 'TA0011'],
                'steganography_techniques': ['lsb_advanced', 'affiliate_id_stego', 'metadata_abuse'],
                'preferred_containers': ['JPEG', 'PNG', 'Ransom Notes'],
                'encryption_methods': ['AES-256'],
                'keywords': ['lockbit', 'ransomware', 'affiliate', 'manufacturing'],
                'c2_patterns': ['tor', 'https', 'steganography'],
                'tools': ['LockBit', 'StealBit', 'Mimikatz'],
                'targeting': {
                    'sectors': ['Manufacturing', 'Legal', 'Construction', 'Any Sector'],
                    'regions': ['Global']
                },
                'first_observed': '2019-09-01',
                'last_confirmed': '2026-03-05',
                'activity_status': 'ACTIVE',
                'complexity': 'HIGH',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 50
            },
            'revil': {
                'name': 'REvil (Sodinokibi)',
                'aliases': ['Sodinokibi', 'GOLD SOUTHFIELD'],
                'country': 'Russia',
                'organization': 'Cybercrime (RaaS)',
                'mitre_techniques': ['T1195', 'T1486', 'T1190', 'T1027'],
                'mitre_tactics': ['TA0042', 'TA0040', 'TA0001'],
                'steganography_techniques': ['lsb_advanced', 'config_stego', 'metadata_abuse'],
                'preferred_containers': ['JPEG', 'PNG'],
                'encryption_methods': ['AES-256', 'Salsa20'],
                'keywords': ['kaseya', 'supply chain', 'ransomware', 'double extortion'],
                'c2_patterns': ['tor', 'https', 'steganography'],
                'tools': ['REvil/Sodinokibi', 'GandCrab'],
                'targeting': {
                    'sectors': ['Any High-Value', 'MSPs', 'Supply Chain'],
                    'regions': ['Global']
                },
                'first_observed': '2019-04-01',
                'last_confirmed': '2024-01-15',
                'activity_status': 'DORMANT',
                'complexity': 'CRITICAL',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 50
            },
            'darkside': {
                'name': 'DarkSide',
                'aliases': ['CARBON SPIDER'],
                'country': 'Russia',
                'organization': 'Cybercrime (RaaS)',
                'mitre_techniques': ['T1486', 'T1567', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0040', 'TA0010', 'TA0011'],
                'steganography_techniques': ['lsb_advanced', 'metadata_abuse', 'exfil_portal_stego'],
                'preferred_containers': ['JPEG', 'PNG'],
                'encryption_methods': ['AES-256', 'RSA-2048'],
                'keywords': ['colonial pipeline', 'ransomware', 'critical infrastructure'],
                'c2_patterns': ['tor', 'https', 'steganography'],
                'tools': ['DarkSide ransomware', 'Cobalt Strike'],
                'targeting': {
                    'sectors': ['Oil & Gas', 'Legal', 'Wholesale', 'Critical Infrastructure'],
                    'regions': ['North America', 'Europe']
                },
                'first_observed': '2020-08-01',
                'last_confirmed': '2021-05-15',
                'activity_status': 'RETIRED',
                'complexity': 'HIGH',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 50
            },
            'blackmatter': {
                'name': 'BlackMatter',
                'aliases': ['DarkSide rebrand'],
                'country': 'Russia',
                'organization': 'Cybercrime (RaaS)',
                'mitre_techniques': ['T1486', 'T1078', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0040', 'TA0006', 'TA0011'],
                'steganography_techniques': ['lsb_advanced', 'metadata_abuse'],
                'preferred_containers': ['JPEG', 'PNG'],
                'encryption_methods': ['AES-256', 'ChaCha20'],
                'keywords': ['ransomware', 'critical infrastructure', 'energy'],
                'c2_patterns': ['tor', 'https', 'steganography'],
                'tools': ['BlackMatter ransomware'],
                'targeting': {
                    'sectors': ['Critical Infrastructure', 'Energy', 'Food/Agriculture'],
                    'regions': ['North America', 'Europe']
                },
                'first_observed': '2021-07-01',
                'last_confirmed': '2021-11-01',
                'activity_status': 'RETIRED',
                'complexity': 'HIGH',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 50
            },
            'hive': {
                'name': 'Hive',
                'aliases': [],
                'country': 'Unknown',
                'organization': 'Cybercrime (RaaS)',
                'mitre_techniques': ['T1486', 'T1567', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0040', 'TA0010', 'TA0011'],
                'steganography_techniques': ['lsb_advanced', 'patient_data_stego', 'metadata_abuse'],
                'preferred_containers': ['JPEG', 'PNG', 'Medical Images'],
                'encryption_methods': ['AES-256'],
                'keywords': ['healthcare', 'ransomware', 'double extortion'],
                'c2_patterns': ['tor', 'https', 'steganography'],
                'tools': ['Hive ransomware', 'Cobalt Strike'],
                'targeting': {
                    'sectors': ['Healthcare', 'Hospitals', 'Medical', 'Any High-Value'],
                    'regions': ['Global']
                },
                'first_observed': '2021-06-01',
                'last_confirmed': '2023-01-26',
                'activity_status': 'DISRUPTED',
                'complexity': 'HIGH',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 50
            },
            'clop': {
                'name': 'Clop (TA505)',
                'aliases': ['TA505', 'FIN11 overlap'],
                'country': 'Unknown',
                'organization': 'Cybercrime',
                'mitre_techniques': ['T1190', 'T1486', 'T1027', 'T1567'],
                'mitre_tactics': ['TA0001', 'TA0040', 'TA0010'],
                'steganography_techniques': ['lsb_advanced', 'file_manifest_stego', 'metadata_abuse'],
                'preferred_containers': ['JPEG', 'PNG'],
                'encryption_methods': ['AES-256', 'RC4'],
                'keywords': ['accellion', 'moveit', 'file transfer', 'zero-day'],
                'c2_patterns': ['tor', 'https', 'steganography'],
                'tools': ['Clop ransomware', 'SDBbot', 'FlawedGrace'],
                'targeting': {
                    'sectors': ['File Transfer Services', 'Legal', 'Healthcare', 'Any Sector'],
                    'regions': ['Global']
                },
                'first_observed': '2019-02-01',
                'last_confirmed': '2026-01-30',
                'activity_status': 'ACTIVE',
                'complexity': 'HIGH',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 50
            },

            # ===== EMERGING/REGIONAL GROUPS =====
            'ta2541': {
                'name': 'TA2541',
                'aliases': [],
                'country': 'Unknown',
                'organization': 'Unknown',
                'mitre_techniques': ['T1566.001', 'T1055', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0001', 'TA0004', 'TA0011'],
                'steganography_techniques': ['lsb_advanced', 'aviation_image_stego', 'metadata_abuse'],
                'preferred_containers': ['JPEG', 'PNG', 'Flight Images'],
                'encryption_methods': ['AES-128'],
                'keywords': ['aviation', 'rat', 'aerospace', 'transportation'],
                'c2_patterns': ['http', 'https', 'steganography'],
                'tools': ['AsyncRAT', 'NetWire', 'WSH RAT'],
                'targeting': {
                    'sectors': ['Aviation', 'Aerospace', 'Transportation', 'Defense'],
                    'regions': ['Global']
                },
                'first_observed': '2017-01-01',
                'last_confirmed': '2025-12-01',
                'activity_status': 'ACTIVE',
                'complexity': 'MEDIUM',
                'intelligence_confidence': 'MEDIUM',
                'attribution_threshold': 40
            },
            'hikit': {
                'name': 'Hikit',
                'aliases': [],
                'country': 'Unknown',
                'organization': 'Unknown',
                'mitre_techniques': ['T1587', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0042', 'TA0005', 'TA0011'],
                'steganography_techniques': ['custom_stego', 'lsb_advanced', 'metadata_abuse'],
                'preferred_containers': ['JPEG', 'PNG'],
                'encryption_methods': ['Custom', 'AES-256'],
                'keywords': ['custom', 'tailored', 'targeted'],
                'c2_patterns': ['https', 'steganography', 'custom_protocols'],
                'tools': ['Custom malware', 'Hikit backdoor'],
                'targeting': {
                    'sectors': ['Varies by Campaign'],
                    'regions': ['Varies']
                },
                'first_observed': '2008-01-01',
                'last_confirmed': '2024-08-15',
                'activity_status': 'ACTIVE',
                'complexity': 'HIGH',
                'intelligence_confidence': 'MEDIUM',
                'attribution_threshold': 40
            },
            'sidewinder': {
                'name': 'Sidewinder',
                'aliases': ['Rattlesnake', 'T-APT-04'],
                'country': 'India',
                'organization': 'Unknown',
                'mitre_techniques': ['T1203', 'T1566', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0001', 'TA0002', 'TA0011'],
                'steganography_techniques': ['lsb_advanced', 'political_doc_stego', 'metadata_abuse'],
                'preferred_containers': ['JPEG', 'PNG', 'DOC'],
                'encryption_methods': ['AES-128'],
                'keywords': ['pakistan', 'china', 'military', 'political'],
                'c2_patterns': ['http', 'https', 'steganography'],
                'tools': ['custom JavaScript', 'RTF exploits'],
                'targeting': {
                    'sectors': ['Military', 'Government', 'Defense'],
                    'regions': ['South Asia', 'Pakistan', 'China']
                },
                'first_observed': '2012-01-01',
                'last_confirmed': '2025-11-10',
                'activity_status': 'ACTIVE',
                'complexity': 'MEDIUM',
                'intelligence_confidence': 'MEDIUM',
                'attribution_threshold': 40
            },
            'patchwork': {
                'name': 'Patchwork (Dropping Elephant)',
                'aliases': ['Dropping Elephant', 'Chinastrats', 'Monsoon'],
                'country': 'India',
                'organization': 'Unknown',
                'mitre_techniques': ['T1566.001', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0001', 'TA0011', 'TA0010'],
                'steganography_techniques': ['lsb_advanced', 'document_stego', 'metadata_abuse'],
                'preferred_containers': ['JPEG', 'PNG', 'DOC'],
                'encryption_methods': ['AES-128', 'RC4'],
                'keywords': ['pakistan', 'china', 'think tank', 'government'],
                'c2_patterns': ['http', 'https', 'steganography'],
                'tools': ['BadNews', 'BADNEWS', 'AutoIt backdoor'],
                'targeting': {
                    'sectors': ['Government', 'Military', 'Think Tanks', 'Diplomacy'],
                    'regions': ['Pakistan', 'China', 'United States']
                },
                'first_observed': '2015-01-01',
                'last_confirmed': '2025-10-20',
                'activity_status': 'ACTIVE',
                'complexity': 'MEDIUM',
                'intelligence_confidence': 'MEDIUM',
                'attribution_threshold': 40
            },
            'bronze_butler': {
                'name': 'Bronze Butler (Tick)',
                'aliases': ['Tick', 'REDBALDKNIGHT'],
                'country': 'China',
                'organization': 'Unknown',
                'mitre_techniques': ['T1003', 'T1053', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0006', 'TA0003', 'TA0011'],
                'steganography_techniques': ['lsb_advanced', 'japanese_doc_stego', 'metadata_abuse'],
                'preferred_containers': ['JPEG', 'PNG', 'Japanese Documents'],
                'encryption_methods': ['AES-128', 'RC4'],
                'keywords': ['japan', 'defense', 'technology', 'trade secrets'],
                'c2_patterns': ['http', 'https', 'steganography'],
                'tools': ['Daserf', 'xxmm', 'Datper'],
                'targeting': {
                    'sectors': ['Government', 'Defense', 'Technology', 'Manufacturing'],
                    'regions': ['Japan', 'South Korea']
                },
                'first_observed': '2008-01-01',
                'last_confirmed': '2025-09-15',
                'activity_status': 'ACTIVE',
                'complexity': 'HIGH',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 45
            },

            # ===== NON-APT THREAT ACTORS =====
            # Generic threat actors, commodity malware, hacktivists, and cybercriminals

            # --- COMMODITY MALWARE OPERATORS ---
            'emotet_operators': {
                'name': 'Emotet Malware Operators',
                'aliases': ['Emotet', 'Geodo', 'Mealybug'],
                'country': 'Global (Russian-speaking)',
                'organization': 'Cybercrime Syndicate',
                'actor_type': 'COMMODITY_MALWARE',
                'mitre_techniques': ['T1566.001', 'T1204.002', 'T1059.003', 'T1027', 'T1071.001', 'T1041', 'T1055'],
                'mitre_tactics': ['TA0001', 'TA0002', 'TA0011', 'TA0010'],
                'steganography_techniques': ['lsb_basic', 'document_stego', 'url_encoding'],
                'preferred_containers': ['JPEG', 'PNG', 'DOC', 'XLS'],
                'encryption_methods': ['AES-128', 'XOR', 'Base64'],
                'keywords': ['invoice', 'payment', 'urgent', 'document', 'banking'],
                'c2_patterns': ['http', 'https', 'smtp'],
                'tools': ['PowerShell', 'Macro-based droppers', 'Cobalt Strike'],
                'targeting': {
                    'sectors': ['Finance', 'Healthcare', 'Government', 'Retail', 'Any'],
                    'regions': ['Global']
                },
                'first_observed': '2014-01-01',
                'last_confirmed': '2026-03-01',
                'activity_status': 'ACTIVE',
                'complexity': 'MEDIUM',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 30
            },
            'qakbot_operators': {
                'name': 'Qakbot Banking Trojan Operators',
                'aliases': ['Qakbot', 'Qbot', 'Pinkslipbot'],
                'country': 'Global (Russian-speaking)',
                'organization': 'Cybercrime',
                'actor_type': 'COMMODITY_MALWARE',
                'mitre_techniques': ['T1566.001', 'T1204.002', 'T1547.001', 'T1027', 'T1003.001', 'T1071.001'],
                'mitre_tactics': ['TA0001', 'TA0003', 'TA0006', 'TA0011'],
                'steganography_techniques': ['lsb_basic', 'document_stego', 'png_embedding'],
                'preferred_containers': ['PNG', 'JPEG', 'ZIP'],
                'encryption_methods': ['AES-256', 'RC4'],
                'keywords': ['banking', 'credentials', 'finance', 'payment'],
                'c2_patterns': ['https', 'proxy_aware', 'tor'],
                'tools': ['PowerShell', 'Egregor', 'ProLock'],
                'targeting': {
                    'sectors': ['Finance', 'Healthcare', 'Manufacturing', 'Legal'],
                    'regions': ['Global']
                },
                'first_observed': '2008-01-01',
                'last_confirmed': '2026-02-15',
                'activity_status': 'ACTIVE',
                'complexity': 'MEDIUM',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 30
            },
            'icedid_operators': {
                'name': 'IcedID Banking Malware Operators',
                'aliases': ['IcedID', 'BokBot'],
                'country': 'Global (Eastern Europe)',
                'organization': 'Cybercrime',
                'actor_type': 'COMMODITY_MALWARE',
                'mitre_techniques': ['T1566.001', 'T1204.002', 'T1055', 'T1027', 'T1071.001', 'T1003'],
                'mitre_tactics': ['TA0001', 'TA0002', 'TA0006', 'TA0011'],
                'steganography_techniques': ['lsb_basic', 'png_embedding', 'fake_headers'],
                'preferred_containers': ['PNG', 'JPEG', 'GIF'],
                'encryption_methods': ['AES-128', 'XOR'],
                'keywords': ['banking', 'bot', 'loader', 'backdoor'],
                'c2_patterns': ['https', 'domain_generation'],
                'tools': ['PowerShell', 'Cobalt Strike', 'SystemBC'],
                'targeting': {
                    'sectors': ['Finance', 'Retail', 'E-commerce', 'Any'],
                    'regions': ['Global']
                },
                'first_observed': '2017-01-01',
                'last_confirmed': '2026-01-30',
                'activity_status': 'ACTIVE',
                'complexity': 'MEDIUM',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 30
            },
            'trickbot_operators': {
                'name': 'TrickBot Malware Operators',
                'aliases': ['TrickBot', 'TrickLoader', 'TheTrick'],
                'country': 'Russia',
                'organization': 'Cybercrime (overlaps with WIZARD SPIDER)',
                'actor_type': 'COMMODITY_MALWARE',
                'mitre_techniques': ['T1566.001', 'T1204.002', 'T1053.005', 'T1027', 'T1003', 'T1071.001'],
                'mitre_tactics': ['TA0001', 'TA0003', 'TA0006', 'TA0011'],
                'steganography_techniques': ['lsb_basic', 'document_stego', 'web_inject'],
                'preferred_containers': ['JPEG', 'PNG', 'HTML'],
                'encryption_methods': ['AES-256', 'RC4'],
                'keywords': ['banking', 'ryuk', 'conti', 'credentials'],
                'c2_patterns': ['https', 'plugin_architecture', 'p2p'],
                'tools': ['PowerShell', 'Cobalt Strike', 'Ryuk', 'Conti'],
                'targeting': {
                    'sectors': ['Finance', 'Healthcare', 'Government', 'Education'],
                    'regions': ['Global']
                },
                'first_observed': '2016-01-01',
                'last_confirmed': '2026-02-01',
                'activity_status': 'ACTIVE',
                'complexity': 'HIGH',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 35
            },

            # --- HACKTIVISTS ---
            'anonymous_patterns': {
                'name': 'Anonymous Hacktivist Collective',
                'aliases': ['Anonymous', 'Anons', 'OpSec'],
                'country': 'Global',
                'organization': 'Decentralized Hacktivist Collective',
                'actor_type': 'HACKTIVIST',
                'mitre_techniques': ['T1498', 'T1499', 'T1565.001', 'T1491', 'T1078', 'T1190'],
                'mitre_tactics': ['TA0040', 'TA0009', 'TA0001'],
                'steganography_techniques': ['lsb_basic', 'text_stego', 'image_manipulation'],
                'preferred_containers': ['JPEG', 'PNG', 'GIF', 'Video'],
                'encryption_methods': ['GPG/PGP', 'AES-256', 'TOR'],
                'keywords': ['anonymous', 'expect us', 'operation', 'justice', 'freedom'],
                'c2_patterns': ['tor', 'irc', 'pastebin', 'twitter'],
                'tools': ['LOIC', 'HOIC', 'SQLMap', 'Metasploit'],
                'targeting': {
                    'sectors': ['Government', 'Corporations', 'Law Enforcement', 'Media'],
                    'regions': ['Global']
                },
                'first_observed': '2008-01-01',
                'last_confirmed': '2026-03-20',
                'activity_status': 'ACTIVE',
                'complexity': 'LOW',
                'intelligence_confidence': 'MEDIUM',
                'attribution_threshold': 20
            },
            'lulzsec_patterns': {
                'name': 'LulzSec-Style Hacktivists',
                'aliases': ['LulzSec', 'Lulz Security', 'AntiSec'],
                'country': 'Global',
                'organization': 'Defunct Hacktivist Group (patterns persist)',
                'actor_type': 'HACKTIVIST',
                'mitre_techniques': ['T1190', 'T1133', 'T1078', 'T1567', 'T1565.001'],
                'mitre_tactics': ['TA0001', 'TA0010', 'TA0040'],
                'steganography_techniques': ['lsb_basic', 'text_stego', 'meme_encoding'],
                'preferred_containers': ['PNG', 'GIF', 'JPEG'],
                'encryption_methods': ['None', 'Base64', 'AES-128'],
                'keywords': ['lulz', 'hacked', 'leak', 'dox', 'troll'],
                'c2_patterns': ['irc', 'twitter', 'pastebin'],
                'tools': ['SQLMap', 'Web Application Exploits', 'Social Engineering'],
                'targeting': {
                    'sectors': ['Media', 'Gaming', 'Government', 'Corporations'],
                    'regions': ['Global']
                },
                'first_observed': '2011-01-01',
                'last_confirmed': '2025-12-01',
                'activity_status': 'DORMANT',
                'complexity': 'LOW',
                'intelligence_confidence': 'MEDIUM',
                'attribution_threshold': 20
            },
            'political_hacktivists': {
                'name': 'Political Hacktivists (Generic)',
                'aliases': ['Political Hackers', 'Cyber Protesters'],
                'country': 'Global',
                'organization': 'Various',
                'actor_type': 'HACKTIVIST',
                'mitre_techniques': ['T1498', 'T1491', 'T1565.001', 'T1190', 'T1078'],
                'mitre_tactics': ['TA0040', 'TA0009', 'TA0001'],
                'steganography_techniques': ['lsb_basic', 'text_stego', 'social_media_encoding'],
                'preferred_containers': ['JPEG', 'PNG', 'GIF', 'PDF'],
                'encryption_methods': ['TOR', 'VPN', 'PGP'],
                'keywords': ['justice', 'freedom', 'resistance', 'protest', 'revolution'],
                'c2_patterns': ['tor', 'telegram', 'signal', 'protonmail'],
                'tools': ['DDoS tools', 'Website defacement', 'Data leaks'],
                'targeting': {
                    'sectors': ['Government', 'Political Organizations', 'Corporations', 'Media'],
                    'regions': ['Global']
                },
                'first_observed': '2000-01-01',
                'last_confirmed': '2026-03-25',
                'activity_status': 'ACTIVE',
                'complexity': 'LOW',
                'intelligence_confidence': 'MEDIUM',
                'attribution_threshold': 15
            },

            # --- INFO-STEALER OPERATORS ---
            'redline_stealer': {
                'name': 'RedLine Stealer Operators',
                'aliases': ['RedLine', 'RedLine Stealer'],
                'country': 'Russia',
                'organization': 'Cybercrime-as-a-Service',
                'actor_type': 'INFO_STEALER',
                'mitre_techniques': ['T1555', 'T1539', 'T1005', 'T1056.001', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0006', 'TA0009', 'TA0011'],
                'steganography_techniques': ['lsb_basic', 'png_embedding', 'clipboard_hijack'],
                'preferred_containers': ['PNG', 'JPEG', 'TXT'],
                'encryption_methods': ['AES-128', 'Base64', 'XOR'],
                'keywords': ['stealer', 'credentials', 'wallets', 'cookies', 'passwords'],
                'c2_patterns': ['http', 'https', 'telegram_bot'],
                'tools': ['Telegram API', 'Discord webhooks', 'FTP'],
                'targeting': {
                    'sectors': ['Cryptocurrency', 'Gaming', 'E-commerce', 'Social Media', 'Any'],
                    'regions': ['Global']
                },
                'first_observed': '2020-01-01',
                'last_confirmed': '2026-03-15',
                'activity_status': 'ACTIVE',
                'complexity': 'LOW',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 25
            },
            'raccoon_stealer': {
                'name': 'Raccoon Stealer Operators',
                'aliases': ['Raccoon', 'Raccoon Stealer v2'],
                'country': 'Russia/Ukraine',
                'organization': 'Cybercrime-as-a-Service',
                'actor_type': 'INFO_STEALER',
                'mitre_techniques': ['T1555', 'T1539', 'T1005', 'T1027', 'T1071.001', 'T1041'],
                'mitre_tactics': ['TA0006', 'TA0009', 'TA0010', 'TA0011'],
                'steganography_techniques': ['lsb_basic', 'config_embedding', 'steganographic_c2'],
                'preferred_containers': ['PNG', 'JPEG', 'GIF'],
                'encryption_methods': ['RC4', 'AES-128'],
                'keywords': ['stealer', 'clipper', 'loader', 'credentials'],
                'c2_patterns': ['telegram', 'tor', 'https'],
                'tools': ['Telegram Bot', 'Clipper', 'Loader module'],
                'targeting': {
                    'sectors': ['Cryptocurrency', 'Financial Services', 'Gaming', 'Any'],
                    'regions': ['Global']
                },
                'first_observed': '2019-01-01',
                'last_confirmed': '2026-02-28',
                'activity_status': 'ACTIVE',
                'complexity': 'MEDIUM',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 25
            },
            'vidar_stealer': {
                'name': 'Vidar Stealer Operators',
                'aliases': ['Vidar', 'Arkei successor'],
                'country': 'Russia',
                'organization': 'Cybercrime',
                'actor_type': 'INFO_STEALER',
                'mitre_techniques': ['T1555.003', 'T1539', 'T1005', 'T1083', 'T1027'],
                'mitre_tactics': ['TA0006', 'TA0009', 'TA0007'],
                'steganography_techniques': ['lsb_basic', 'image_based_config', 'fake_headers'],
                'preferred_containers': ['PNG', 'JPEG', 'BMP'],
                'encryption_methods': ['Base64', 'XOR', 'RC4'],
                'keywords': ['stealer', 'browser', 'wallet', '2fa', 'cookies'],
                'c2_patterns': ['https', 'steam_api', 'legitimate_services'],
                'tools': ['Telegram exfil', 'Discord exfil', 'FTP'],
                'targeting': {
                    'sectors': ['Cryptocurrency', 'Gaming', 'Social Media', 'Any'],
                    'regions': ['Global']
                },
                'first_observed': '2018-01-01',
                'last_confirmed': '2026-03-10',
                'activity_status': 'ACTIVE',
                'complexity': 'LOW',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 25
            },
            'agenttesla_operators': {
                'name': 'Agent Tesla Keylogger Operators',
                'aliases': ['Agent Tesla', 'AgentTesla'],
                'country': 'Nigeria/Global',
                'organization': 'Cybercrime',
                'actor_type': 'INFO_STEALER',
                'mitre_techniques': ['T1056.001', 'T1113', 'T1005', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0009', 'TA0006', 'TA0011'],
                'steganography_techniques': ['lsb_basic', 'email_attachment_stego', 'screenshot_embedding'],
                'preferred_containers': ['JPEG', 'PNG', 'Email attachments'],
                'encryption_methods': ['Base64', 'AES-128'],
                'keywords': ['keylogger', 'screenshot', 'clipboard', 'credentials'],
                'c2_patterns': ['smtp', 'ftp', 'telegram'],
                'tools': ['.NET Keylogger', 'Screenshot capture', 'Clipboard monitor'],
                'targeting': {
                    'sectors': ['Any', 'SMB', 'Healthcare', 'Manufacturing'],
                    'regions': ['Global']
                },
                'first_observed': '2014-01-01',
                'last_confirmed': '2026-03-05',
                'activity_status': 'ACTIVE',
                'complexity': 'LOW',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 20
            },

            # --- GENERIC RANSOMWARE OPERATORS ---
            'raas_affiliates': {
                'name': 'Ransomware-as-a-Service Affiliates',
                'aliases': ['RaaS', 'Ransomware Affiliates', 'Generic Ransomware'],
                'country': 'Global (primarily Russia/Eastern Europe)',
                'organization': 'Cybercrime',
                'actor_type': 'RANSOMWARE',
                'mitre_techniques': ['T1486', 'T1490', 'T1489', 'T1027', 'T1071.001', 'T1041'],
                'mitre_tactics': ['TA0040', 'TA0010', 'TA0011'],
                'steganography_techniques': ['lsb_basic', 'config_embedding', 'ransom_note_stego'],
                'preferred_containers': ['PNG', 'JPEG', 'TXT'],
                'encryption_methods': ['AES-256', 'RSA-2048', 'ChaCha20'],
                'keywords': ['ransomware', 'decrypt', 'bitcoin', 'tor', 'payment'],
                'c2_patterns': ['tor', 'i2p', 'telegram'],
                'tools': ['Various RaaS platforms', 'Cobalt Strike', 'Mimikatz'],
                'targeting': {
                    'sectors': ['Any', 'Healthcare', 'Education', 'Government', 'SMB'],
                    'regions': ['Global']
                },
                'first_observed': '2019-01-01',
                'last_confirmed': '2026-03-30',
                'activity_status': 'ACTIVE',
                'complexity': 'MEDIUM',
                'intelligence_confidence': 'MEDIUM',
                'attribution_threshold': 30
            },
            'phobos_ransomware': {
                'name': 'Phobos Ransomware Operators',
                'aliases': ['Phobos', 'Phobos Ransomware'],
                'country': 'Russia/Eastern Europe',
                'organization': 'Cybercrime',
                'actor_type': 'RANSOMWARE',
                'mitre_techniques': ['T1486', 'T1021.001', 'T1078', 'T1027', 'T1489'],
                'mitre_tactics': ['TA0040', 'TA0008', 'TA0001'],
                'steganography_techniques': ['lsb_basic', 'config_embedding', 'rdp_abuse'],
                'preferred_containers': ['PNG', 'JPEG'],
                'encryption_methods': ['AES-256', 'RSA-2048'],
                'keywords': ['phobos', 'ransomware', 'rdp', 'decrypt', 'bitcoin'],
                'c2_patterns': ['email', 'tor', 'direct_contact'],
                'tools': ['RDP brute force', 'Mimikatz', 'PowerShell'],
                'targeting': {
                    'sectors': ['SMB', 'Healthcare', 'MSP', 'Education'],
                    'regions': ['Global']
                },
                'first_observed': '2019-01-01',
                'last_confirmed': '2026-02-20',
                'activity_status': 'ACTIVE',
                'complexity': 'LOW',
                'intelligence_confidence': 'MEDIUM',
                'attribution_threshold': 25
            },
            'stop_ransomware': {
                'name': 'STOP/Djvu Ransomware Operators',
                'aliases': ['STOP', 'Djvu', 'STOP Djvu'],
                'country': 'Global',
                'organization': 'Cybercrime',
                'actor_type': 'RANSOMWARE',
                'mitre_techniques': ['T1486', 'T1027', 'T1566.001', 'T1204.002'],
                'mitre_tactics': ['TA0040', 'TA0001', 'TA0002'],
                'steganography_techniques': ['lsb_basic', 'fake_software', 'keygen_embedding'],
                'preferred_containers': ['PNG', 'JPEG', 'EXE'],
                'encryption_methods': ['AES-256', 'RSA-1024'],
                'keywords': ['stop', 'djvu', 'decrypt', 'keygen', 'crack'],
                'c2_patterns': ['http', 'https'],
                'tools': ['Fake software', 'Keygens', 'Cracks'],
                'targeting': {
                    'sectors': ['Individuals', 'Home users', 'SMB'],
                    'regions': ['Global']
                },
                'first_observed': '2018-01-01',
                'last_confirmed': '2026-03-15',
                'activity_status': 'ACTIVE',
                'complexity': 'LOW',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 20
            },

            # --- BANKING TROJAN OPERATORS ---
            'zeus_variants': {
                'name': 'Zeus/Zbot Variant Operators',
                'aliases': ['Zeus', 'Zbot', 'Gameover Zeus'],
                'country': 'Russia/Eastern Europe',
                'organization': 'Cybercrime',
                'actor_type': 'BANKING_TROJAN',
                'mitre_techniques': ['T1056.001', 'T1055', 'T1027', 'T1071.001', 'T1003'],
                'mitre_tactics': ['TA0006', 'TA0009', 'TA0011'],
                'steganography_techniques': ['lsb_basic', 'web_inject_stego', 'config_hiding'],
                'preferred_containers': ['PNG', 'JPEG', 'HTML'],
                'encryption_methods': ['RC4', 'AES-128', 'XOR'],
                'keywords': ['zeus', 'banking', 'web inject', 'credentials', 'bot'],
                'c2_patterns': ['p2p', 'domain_generation', 'fast_flux'],
                'tools': ['Web injects', 'Form grabbers', 'VNC'],
                'targeting': {
                    'sectors': ['Finance', 'Banking', 'E-commerce'],
                    'regions': ['Global']
                },
                'first_observed': '2007-01-01',
                'last_confirmed': '2025-11-30',
                'activity_status': 'DORMANT',
                'complexity': 'HIGH',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 35
            },
            'dridex_operators': {
                'name': 'Dridex Banking Trojan Operators',
                'aliases': ['Dridex', 'Cridex', 'Bugat'],
                'country': 'Russia',
                'organization': 'Evil Corp',
                'actor_type': 'BANKING_TROJAN',
                'mitre_techniques': ['T1566.001', 'T1204.002', 'T1055', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0001', 'TA0002', 'TA0006', 'TA0011'],
                'steganography_techniques': ['lsb_basic', 'macro_stego', 'web_inject'],
                'preferred_containers': ['DOC', 'XLS', 'PNG'],
                'encryption_methods': ['AES-256', 'RSA-2048'],
                'keywords': ['dridex', 'banking', 'macro', 'bitpaymer', 'evil corp'],
                'c2_patterns': ['https', 'proxy', 'p2p'],
                'tools': ['Macro documents', 'Web injects', 'BitPaymer ransomware'],
                'targeting': {
                    'sectors': ['Finance', 'Banking', 'Healthcare', 'Government'],
                    'regions': ['Global']
                },
                'first_observed': '2014-01-01',
                'last_confirmed': '2026-01-15',
                'activity_status': 'ACTIVE',
                'complexity': 'HIGH',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 40
            },

            # --- CRYPTOMINERS & BOTNET OPERATORS ---
            'cryptominer_operators': {
                'name': 'Cryptominer Operators (Generic)',
                'aliases': ['Cryptojackers', 'Cryptominers', 'Coinminers'],
                'country': 'Global',
                'organization': 'Cybercrime',
                'actor_type': 'CRYPTOMINER',
                'mitre_techniques': ['T1496', 'T1053.005', 'T1569.002', 'T1027', 'T1071.001'],
                'mitre_tactics': ['TA0040', 'TA0003', 'TA0011'],
                'steganography_techniques': ['lsb_basic', 'script_embedding', 'image_based_loaders'],
                'preferred_containers': ['PNG', 'JPEG', 'JavaScript'],
                'encryption_methods': ['Base64', 'XOR', 'Obfuscation'],
                'keywords': ['monero', 'xmrig', 'mining', 'cryptocurrency', 'cpu'],
                'c2_patterns': ['mining_pool', 'http', 'https'],
                'tools': ['XMRig', 'CoinHive', 'CryptoNight'],
                'targeting': {
                    'sectors': ['Any', 'Cloud Services', 'Web Servers', 'IoT'],
                    'regions': ['Global']
                },
                'first_observed': '2017-01-01',
                'last_confirmed': '2026-03-28',
                'activity_status': 'ACTIVE',
                'complexity': 'LOW',
                'intelligence_confidence': 'MEDIUM',
                'attribution_threshold': 15
            },
            'botnet_operators': {
                'name': 'Botnet Operators (Generic)',
                'aliases': ['Botnets', 'DDoS-for-hire', 'Booters'],
                'country': 'Global',
                'organization': 'Cybercrime',
                'actor_type': 'BOTNET',
                'mitre_techniques': ['T1498', 'T1499', 'T1583.005', 'T1071.001', 'T1027'],
                'mitre_tactics': ['TA0040', 'TA0011', 'TA0042'],
                'steganography_techniques': ['lsb_basic', 'command_encoding', 'iot_abuse'],
                'preferred_containers': ['PNG', 'JPEG', 'Binary'],
                'encryption_methods': ['XOR', 'Base64', 'Custom'],
                'keywords': ['ddos', 'botnet', 'mirai', 'iot', 'flood'],
                'c2_patterns': ['irc', 'http', 'p2p', 'tor'],
                'tools': ['Mirai variants', 'DDoS tools', 'IoT exploits'],
                'targeting': {
                    'sectors': ['Any', 'IoT', 'Web Services', 'Gaming'],
                    'regions': ['Global']
                },
                'first_observed': '2000-01-01',
                'last_confirmed': '2026-03-25',
                'activity_status': 'ACTIVE',
                'complexity': 'LOW',
                'intelligence_confidence': 'MEDIUM',
                'attribution_threshold': 15
            },
            'mirai_variants': {
                'name': 'Mirai Botnet Variants',
                'aliases': ['Mirai', 'Satori', 'Okiru', 'Masuta'],
                'country': 'Global',
                'organization': 'Various Cybercriminals',
                'actor_type': 'BOTNET',
                'mitre_techniques': ['T1110.001', 'T1190', 'T1498', 'T1027'],
                'mitre_tactics': ['TA0001', 'TA0040', 'TA0011'],
                'steganography_techniques': ['lsb_basic', 'iot_firmware_hiding', 'telnet_abuse'],
                'preferred_containers': ['Binary', 'PNG', 'JPEG'],
                'encryption_methods': ['XOR', 'None', 'Obfuscation'],
                'keywords': ['mirai', 'iot', 'telnet', 'default credentials', 'ddos'],
                'c2_patterns': ['cnc', 'http', 'hardcoded_ips'],
                'tools': ['Telnet scanner', 'Default credential lists', 'IoT exploits'],
                'targeting': {
                    'sectors': ['IoT', 'Home Routers', 'DVR/NVR', 'IP Cameras'],
                    'regions': ['Global']
                },
                'first_observed': '2016-01-01',
                'last_confirmed': '2026-03-20',
                'activity_status': 'ACTIVE',
                'complexity': 'LOW',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 20
            },

            # --- INSIDER THREATS & LOW-SKILL ACTORS ---
            'insider_threat_patterns': {
                'name': 'Insider Threat Patterns',
                'aliases': ['Insider', 'Malicious Insider', 'Disgruntled Employee'],
                'country': 'Any',
                'organization': 'Internal',
                'actor_type': 'INSIDER_THREAT',
                'mitre_techniques': ['T1530', 'T1005', 'T1039', 'T1048', 'T1041', 'T1078'],
                'mitre_tactics': ['TA0009', 'TA0010', 'TA0001'],
                'steganography_techniques': ['lsb_basic', 'document_hiding', 'legitimate_channels'],
                'preferred_containers': ['JPEG', 'PNG', 'PDF', 'Office docs'],
                'encryption_methods': ['BitLocker', 'Password-protected archives', 'AES'],
                'keywords': ['exfiltration', 'data theft', 'unauthorized access', 'abuse'],
                'c2_patterns': ['legitimate_services', 'personal_email', 'cloud_storage'],
                'tools': ['USB drives', 'Cloud storage', 'Email', 'Personal devices'],
                'targeting': {
                    'sectors': ['Any', 'Corporate', 'Government', 'Financial'],
                    'regions': ['Any']
                },
                'first_observed': '1990-01-01',
                'last_confirmed': '2026-03-30',
                'activity_status': 'ACTIVE',
                'complexity': 'LOW',
                'intelligence_confidence': 'HIGH',
                'attribution_threshold': 25
            },
            'script_kiddie_patterns': {
                'name': 'Script Kiddies / Low-Skill Actors',
                'aliases': ['Script Kiddies', 'Skids', 'Low-Skill Hackers'],
                'country': 'Global',
                'organization': 'None',
                'actor_type': 'LOW_SKILL',
                'mitre_techniques': ['T1190', 'T1078', 'T1110', 'T1059.001', 'T1566.001'],
                'mitre_tactics': ['TA0001', 'TA0002', 'TA0009'],
                'steganography_techniques': ['lsb_basic', 'online_tools', 'copy_paste'],
                'preferred_containers': ['JPEG', 'PNG', 'GIF'],
                'encryption_methods': ['None', 'Base64', 'Online tools'],
                'keywords': ['hacker', 'pwned', '1337', 'script', 'tool'],
                'c2_patterns': ['public_tools', 'github', 'pastebin'],
                'tools': ['Metasploit', 'Kali Linux tools', 'Public exploits', 'Online generators'],
                'targeting': {
                    'sectors': ['Any', 'Small businesses', 'Personal websites', 'Gaming'],
                    'regions': ['Global']
                },
                'first_observed': '1995-01-01',
                'last_confirmed': '2026-03-31',
                'activity_status': 'ACTIVE',
                'complexity': 'MINIMAL',
                'intelligence_confidence': 'LOW',
                'attribution_threshold': 10
            },
            'opportunistic_attackers': {
                'name': 'Opportunistic Attackers (Generic)',
                'aliases': ['Opportunistic', 'Mass Scanning', 'Automated Attacks'],
                'country': 'Global',
                'organization': 'Various',
                'actor_type': 'OPPORTUNISTIC',
                'mitre_techniques': ['T1190', 'T1110', 'T1595', 'T1046', 'T1133'],
                'mitre_tactics': ['TA0043', 'TA0001', 'TA0002'],
                'steganography_techniques': ['lsb_basic', 'simple_encoding', 'minimal'],
                'preferred_containers': ['JPEG', 'PNG'],
                'encryption_methods': ['None', 'Weak encryption', 'XOR'],
                'keywords': ['scan', 'exploit', 'vulnerable', 'automated', 'bot'],
                'c2_patterns': ['automated', 'mass_scan', 'exploit_kits'],
                'tools': ['Shodan', 'Mass scanners', 'Exploit kits', 'Automated frameworks'],
                'targeting': {
                    'sectors': ['Any', 'Unpatched systems', 'Default credentials', 'IoT'],
                    'regions': ['Global']
                },
                'first_observed': '2000-01-01',
                'last_confirmed': '2026-04-01',
                'activity_status': 'ACTIVE',
                'complexity': 'MINIMAL',
                'intelligence_confidence': 'LOW',
                'attribution_threshold': 10
            }
        }

    async def assess_threat(self, analysis_results: Dict, file_info: Dict) -> Dict:
        """
        Advanced threat assessment with 2026 APT detection

        Args:
            analysis_results: Detection results
            file_info: File metadata

        Returns:
            Comprehensive threat assessment with APT attribution
        """
        try:
            # Calculate threat metrics
            metrics = self._calculate_threat_metrics(analysis_results)

            # APT attribution analysis
            apt_attribution = await self._analyze_apt_attribution(analysis_results)

            # 2026 technique detection
            modern_techniques = self._detect_2026_techniques(analysis_results)

            # Threat actor profiling
            actor_profile = self._generate_actor_profile(
                analysis_results,
                apt_attribution,
                modern_techniques
            )

            # Determine threat level
            threat_level = self._determine_threat_level(metrics, apt_attribution)

            return {
                'level': threat_level,
                'confidence': metrics['confidence'],
                'metrics': metrics,
                'apt_attribution': apt_attribution,
                'modern_techniques': modern_techniques,
                'actor_profile': actor_profile,
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            return {
                'level': 'UNKNOWN',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

    def _calculate_threat_metrics(self, results: Dict) -> Dict:
        """Calculate comprehensive threat metrics"""
        metrics = {
            'anomaly_score': 0,
            'complexity_score': 0,
            'stealth_score': 0,
            'malicious_score': 0,
            'apt_score': 0,
            'confidence': 0
        }

        # Anomaly score (0-100)
        anomaly_count = results.get('anomaly_count', 0)
        metrics['anomaly_score'] = min(anomaly_count * 10, 100)

        # Complexity score - 2026 advanced techniques
        detection_results = results.get('detection_results', {})

        advanced_2026_modules = [
            'gan_detector',           # AI-generated content
            'wavelet_detector',       # Wavelet transforms
            'spectrum_detector',      # Spread-spectrum
            'dct_detector',           # DCT frequency domain
            'audio_exif_detector'     # Hybrid attacks
        ]

        detected_advanced = sum(
            1 for mod in advanced_2026_modules
            if detection_results.get(mod, {}).get('detected')
        )

        metrics['complexity_score'] = min(detected_advanced * 20, 100)

        # Stealth score - low detectability = high stealth
        confidences = [
            det.get('confidence', 0)
            for det in detection_results.values()
            if isinstance(det, dict) and det.get('detected')
        ]

        if confidences:
            avg_confidence = sum(confidences) / len(confidences)
            # Inverse relationship: lower confidence = higher stealth
            metrics['stealth_score'] = int((1 - avg_confidence) * 100)

        # Malicious score based on decryption results
        decryption = results.get('decryption_results', {})

        if decryption.get('encrypted'):
            metrics['malicious_score'] += 30

        if decryption.get('extracted_data'):
            data = decryption.get('extracted_data', '').lower()

            # 2026 APT keywords
            apt_keywords = [
                'exfil', 'target', 'owned', 'actor', 'phase',
                'c2', 'beacon', 'payload', 'backdoor',
                'supply chain', 'zero-day', 'persistence',
                'lateral movement', 'privilege escalation'
            ]

            found_keywords = sum(1 for kw in apt_keywords if kw in data)
            metrics['malicious_score'] += min(found_keywords * 10, 70)

        # APT score - multi-layer complexity
        if anomaly_count >= 4:
            metrics['apt_score'] = min((anomaly_count - 3) * 20, 100)

        # Check for hybrid techniques (signature of APT)
        hybrid_indicators = 0
        if detection_results.get('lsb_detector', {}).get('detected'):
            hybrid_indicators += 1
        if detection_results.get('dct_detector', {}).get('detected'):
            hybrid_indicators += 1
        if detection_results.get('gan_detector', {}).get('detected'):
            hybrid_indicators += 1

        if hybrid_indicators >= 2:
            metrics['apt_score'] += 40

        # Overall confidence
        metrics['confidence'] = results.get('confidence', 0)

        return metrics

    async def _analyze_apt_attribution(self, results: Dict) -> Dict:
        """
        Analyze and attribute to known APT groups based on TTPs
        """
        attribution = {
            'likely_actor': None,
            'confidence': 0,
            'matching_techniques': [],
            'matching_keywords': [],
            'candidates': []
        }

        detection_results = results.get('detection_results', {})
        decryption = results.get('decryption_results', {})
        extracted_data = decryption.get('extracted_data', '').lower() if decryption else ''

        # Map detected techniques to APT techniques
        technique_map = {
            'lsb_detector': 'lsb_advanced',
            'dct_detector': 'hybrid_dct_lsb',
            'wavelet_detector': 'wavelet_transform',
            'gan_detector': 'gan_synthetic',
            'spectrum_detector': 'spread_spectrum',
            'palette_detector': 'palette_reorder',
            'qr_detector': 'qr_manipulation',
            'audio_exif_detector': 'audio_exif'
        }

        detected_techniques = [
            technique_map[mod]
            for mod, technique in technique_map.items()
            if detection_results.get(mod, {}).get('detected')
        ]

        # Score each APT group
        for apt_id, apt_data in self._apt_signatures.items():
            score = 0
            matching_techs = []
            matching_kws = []

            # Check technique matches
            for tech in apt_data['techniques']:
                if tech in detected_techniques or any(t in tech for t in detected_techniques):
                    score += 30
                    matching_techs.append(tech)

            # Check keyword matches
            for keyword in apt_data['keywords']:
                if keyword in extracted_data:
                    score += 20
                    matching_kws.append(keyword)

            # Complexity bonus
            if apt_data['complexity'] == 'CRITICAL' and len(detected_techniques) >= 3:
                score += 20

            if score > 0:
                attribution['candidates'].append({
                    'apt_id': apt_id,
                    'name': apt_data['name'],
                    'score': score,
                    'complexity': apt_data['complexity'],
                    'matching_techniques': matching_techs,
                    'matching_keywords': matching_kws
                })

        # Sort by score
        attribution['candidates'].sort(key=lambda x: x['score'], reverse=True)

        # Set likely actor
        if attribution['candidates']:
            top_candidate = attribution['candidates'][0]
            if top_candidate['score'] >= 50:  # Threshold for attribution
                attribution['likely_actor'] = top_candidate['name']
                attribution['confidence'] = min(top_candidate['score'] / 100, 0.95)
                attribution['matching_techniques'] = top_candidate['matching_techniques']
                attribution['matching_keywords'] = top_candidate['matching_keywords']

        return attribution

    def _detect_2026_techniques(self, results: Dict) -> Dict:
        """
        Detect 2026-specific advanced steganography techniques
        """
        techniques = {
            'detected': [],
            'emerging': [],
            'countermeasures': []
        }

        detection_results = results.get('detection_results', {})
        decryption = results.get('decryption_results', {})

        # 1. Hybrid DCT + LSB (2026 standard)
        if (detection_results.get('lsb_detector', {}).get('detected') and
            detection_results.get('dct_detector', {}).get('detected')):
            techniques['detected'].append({
                'name': 'Hybrid DCT + LSB',
                'description': '2026 APT standard - combines frequency and spatial domain',
                'severity': 'HIGH',
                'year': '2024-2026'
            })

        # 2. AI-Generated Noise Patterns (GAN-based)
        if detection_results.get('gan_detector', {}).get('detected'):
            gan_conf = detection_results['gan_detector'].get('confidence', 0)
            if gan_conf > 0.85:
                techniques['detected'].append({
                    'name': 'GAN-Generated Steganography',
                    'description': 'AI-synthesized noise patterns for data hiding',
                    'severity': 'CRITICAL',
                    'year': '2025-2026'
                })

        # 3. Lattice-Based Cryptography (Post-Quantum)
        if decryption:
            encryption_type = decryption.get('encryption_type', '')
            if 'lattice' in encryption_type.lower() or decryption.get('partial_only'):
                techniques['detected'].append({
                    'name': 'Lattice-Based Encryption',
                    'description': 'Post-quantum cryptography (Dilithium/Kyber)',
                    'severity': 'CRITICAL',
                    'year': '2024-2026'
                })

        # 4. Multi-Layer Steganography
        anomaly_count = results.get('anomaly_count', 0)
        if anomaly_count >= 4:
            techniques['detected'].append({
                'name': 'Multi-Layer Steganography',
                'description': 'Multiple steganography techniques layered together',
                'severity': 'HIGH',
                'year': '2023-2026'
            })

        # 5. Spread-Spectrum with AI Adaptation
        if detection_results.get('spectrum_detector', {}).get('detected'):
            techniques['detected'].append({
                'name': 'Adaptive Spread-Spectrum',
                'description': 'AI-adapted frequency spreading for evasion',
                'severity': 'HIGH',
                'year': '2025-2026'
            })

        # 6. Metadata Abuse (EXIF/XMP poisoning)
        if detection_results.get('audio_exif_detector', {}).get('detected'):
            techniques['detected'].append({
                'name': 'Metadata Channel Abuse',
                'description': 'EXIF/XMP metadata used as covert channel',
                'severity': 'MEDIUM',
                'year': '2020-2026'
            })

        # Emerging techniques (based on patterns)
        if len(techniques['detected']) >= 3:
            techniques['emerging'].append({
                'name': 'Advanced Persistent Steganography (APS)',
                'description': 'Sophisticated multi-vector steganography campaign',
                'indicators': 'Multiple advanced techniques combined'
            })

        # Countermeasures
        for tech in techniques['detected']:
            if tech['name'] == 'Hybrid DCT + LSB':
                techniques['countermeasures'].append({
                    'technique': tech['name'],
                    'countermeasure': 'Frequency domain analysis + statistical testing',
                    'effectiveness': '85%'
                })
            elif tech['name'] == 'GAN-Generated Steganography':
                techniques['countermeasures'].append({
                    'technique': tech['name'],
                    'countermeasure': 'Deep learning detector + noise analysis',
                    'effectiveness': '90%'
                })
            elif tech['name'] == 'Lattice-Based Encryption':
                techniques['countermeasures'].append({
                    'technique': tech['name'],
                    'countermeasure': 'Quantum cryptanalysis + partial decryption',
                    'effectiveness': '40-60%'
                })

        return techniques

    def _generate_actor_profile(
        self,
        results: Dict,
        apt_attribution: Dict,
        modern_techniques: Dict
    ) -> Dict:
        """Generate threat actor profile"""
        profile = {
            'sophistication': 'UNKNOWN',
            'likely_motivation': [],
            'capabilities': [],
            'targeting': [],
            'timeline': '2026',
            'threat_category': 'APT'
        }

        # Determine sophistication
        num_techniques = len(modern_techniques.get('detected', []))
        if num_techniques >= 4:
            profile['sophistication'] = 'NATION-STATE'
        elif num_techniques >= 3:
            profile['sophistication'] = 'ADVANCED APT'
        elif num_techniques >= 2:
            profile['sophistication'] = 'INTERMEDIATE'
        else:
            profile['sophistication'] = 'BASIC'

        # Motivation (from extracted data keywords)
        decryption = results.get('decryption_results', {})
        if decryption:
            data = decryption.get('extracted_data', '').lower()

            if any(kw in data for kw in ['exfil', 'target', 'intel']):
                profile['likely_motivation'].append('Espionage')
            if any(kw in data for kw in ['bank', 'swift', 'financial']):
                profile['likely_motivation'].append('Financial Gain')
            if any(kw in data for kw in ['supply chain', 'backdoor']):
                profile['likely_motivation'].append('Supply Chain Compromise')
            if any(kw in data for kw in ['disrupt', 'sabotage']):
                profile['likely_motivation'].append('Disruption/Sabotage')

        # Capabilities
        for tech in modern_techniques.get('detected', []):
            profile['capabilities'].append(tech['name'])

        # Likely targeting
        if apt_attribution.get('likely_actor'):
            actor = apt_attribution['likely_actor']
            if 'APT29' in actor or 'APT28' in actor:
                profile['targeting'] = ['Government', 'Defense', 'Critical Infrastructure']
            elif 'Lazarus' in actor:
                profile['targeting'] = ['Financial Institutions', 'Cryptocurrency']
            elif 'APT41' in actor:
                profile['targeting'] = ['Healthcare', 'Software Supply Chain', 'Gaming']

        return profile

    def _determine_threat_level(self, metrics: Dict, apt_attribution: Dict) -> str:
        """Determine overall threat level"""
        # Calculate weighted score
        score = (
            metrics['anomaly_score'] * 0.20 +
            metrics['complexity_score'] * 0.25 +
            metrics['malicious_score'] * 0.25 +
            metrics['apt_score'] * 0.30
        )

        # Boost for confirmed APT attribution
        if apt_attribution.get('likely_actor'):
            score += 20

        # Determine level
        if score >= 85:
            return 'CRITICAL'
        elif score >= 70:
            return 'HIGH'
        elif score >= 50:
            return 'MEDIUM'
        elif score >= 30:
            return 'LOW'
        else:
            return 'MINIMAL'

    def get_threat_report(self, threat_assessment: Dict) -> str:
        """Generate human-readable threat report"""
        report_lines = []

        report_lines.append("=== THREAT INTELLIGENCE REPORT ===")
        report_lines.append(f"Threat Level: {threat_assessment.get('level', 'UNKNOWN')}")
        report_lines.append(f"Confidence: {threat_assessment.get('confidence', 0)*100:.1f}%")
        report_lines.append("")

        # APT Attribution
        apt_attr = threat_assessment.get('apt_attribution', {})
        if apt_attr.get('likely_actor'):
            report_lines.append(f"Likely Threat Actor: {apt_attr['likely_actor']}")
            report_lines.append(f"Attribution Confidence: {apt_attr.get('confidence', 0)*100:.1f}%")
            report_lines.append("")

        # 2026 Techniques
        techniques = threat_assessment.get('modern_techniques', {})
        detected = techniques.get('detected', [])
        if detected:
            report_lines.append("Detected 2026 Techniques:")
            for tech in detected:
                report_lines.append(f"  - {tech['name']} ({tech['year']})")
                report_lines.append(f"    {tech['description']}")
            report_lines.append("")

        # Actor Profile
        profile = threat_assessment.get('actor_profile', {})
        report_lines.append(f"Sophistication: {profile.get('sophistication', 'UNKNOWN')}")
        if profile.get('likely_motivation'):
            report_lines.append(f"Likely Motivation: {', '.join(profile['likely_motivation'])}")

        return "\n".join(report_lines)
