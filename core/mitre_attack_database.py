"""
MITRE ATT&CK Framework Integration for StegoGuard
Maps steganography techniques to MITRE ATT&CK tactics and techniques
Provides professional-grade threat intelligence alignment
"""

from typing import Dict, List, Set, Tuple
from datetime import datetime


class MITREDatabase:
    """
    MITRE ATT&CK database for steganography-focused threat intelligence
    Provides technique mappings, tactic classification, and TTP analysis
    """

    def __init__(self):
        self.techniques = self._load_mitre_techniques()
        self.tactics = self._load_mitre_tactics()
        self.stego_mappings = self._load_stego_to_mitre_mapping()
        self._technique_cache = {}

    def _load_mitre_techniques(self) -> Dict:
        """
        Load 50+ MITRE ATT&CK techniques relevant to steganography operations
        Focuses on C2, Exfiltration, Defense Evasion, and Persistence tactics
        """
        return {
            # ==== EXFILTRATION TECHNIQUES ====
            'T1020': {
                'id': 'T1020',
                'name': 'Automated Exfiltration',
                'tactic': 'Exfiltration',
                'description': 'Data exfiltrated on a scheduled or periodic basis',
                'steganography_relevance': 'PRIMARY',
                'detection_modules': ['lsb_detector', 'dct_detector', 'audio_exif_detector'],
                'indicators': ['periodic_image_uploads', 'scheduled_metadata_changes']
            },
            'T1030': {
                'id': 'T1030',
                'name': 'Data Transfer Size Limits',
                'tactic': 'Exfiltration',
                'description': 'Exfiltration in small chunks to avoid detection',
                'steganography_relevance': 'PRIMARY',
                'detection_modules': ['lsb_detector', 'spectrum_detector'],
                'indicators': ['low_entropy_changes', 'small_data_fragments']
            },
            'T1041': {
                'id': 'T1041',
                'name': 'Exfiltration Over C2 Channel',
                'tactic': 'Exfiltration',
                'description': 'Data exfiltrated over existing C2 channel',
                'steganography_relevance': 'PRIMARY',
                'detection_modules': ['all'],
                'indicators': ['high_entropy_images', 'metadata_anomalies', 'encrypted_payloads'],
                'subtechniques': {
                    'T1041.001': {
                        'name': 'Exfiltration Over Symmetric Encrypted Channel',
                        'description': 'Encrypted data hidden in steganographic containers'
                    }
                }
            },
            'T1048': {
                'id': 'T1048',
                'name': 'Exfiltration Over Alternative Protocol',
                'tactic': 'Exfiltration',
                'description': 'Exfiltration via non-standard protocols',
                'steganography_relevance': 'SECONDARY',
                'detection_modules': ['audio_exif_detector'],
                'indicators': ['unusual_protocol_usage', 'metadata_channels']
            },
            'T1567': {
                'id': 'T1567',
                'name': 'Exfiltration Over Web Service',
                'tactic': 'Exfiltration',
                'description': 'Exfiltration to cloud services',
                'steganography_relevance': 'PRIMARY',
                'detection_modules': ['all'],
                'indicators': ['image_uploads_to_cloud', 'social_media_posts']
            },

            # ==== COMMAND & CONTROL TECHNIQUES ====
            'T1071': {
                'id': 'T1071',
                'name': 'Application Layer Protocol',
                'tactic': 'Command and Control',
                'description': 'C2 over standard application protocols',
                'steganography_relevance': 'PRIMARY',
                'detection_modules': ['spectrum_detector', 'qr_detector'],
                'indicators': ['http_image_traffic', 'dns_txt_records'],
                'subtechniques': {
                    'T1071.001': {
                        'name': 'Web Protocols',
                        'description': 'C2 commands embedded in HTTP/HTTPS image traffic'
                    },
                    'T1071.004': {
                        'name': 'DNS',
                        'description': 'DNS tunneling with steganographic encoding'
                    }
                }
            },
            'T1090': {
                'id': 'T1090',
                'name': 'Proxy',
                'tactic': 'Command and Control',
                'description': 'C2 via proxy to hide source',
                'steganography_relevance': 'SECONDARY',
                'indicators': ['proxy_traffic', 'multi_hop_connections']
            },
            'T1092': {
                'id': 'T1092',
                'name': 'Communication Through Removable Media',
                'tactic': 'Command and Control',
                'description': 'C2 via removable media (USB, SD cards)',
                'steganography_relevance': 'PRIMARY',
                'detection_modules': ['all'],
                'indicators': ['usb_image_files', 'offline_c2']
            },
            'T1095': {
                'id': 'T1095',
                'name': 'Non-Application Layer Protocol',
                'tactic': 'Command and Control',
                'description': 'C2 via non-standard protocols',
                'steganography_relevance': 'SECONDARY',
                'indicators': ['raw_socket_usage', 'icmp_tunneling']
            },
            'T1102': {
                'id': 'T1102',
                'name': 'Web Service',
                'tactic': 'Command and Control',
                'description': 'C2 via web services (social media, cloud)',
                'steganography_relevance': 'PRIMARY',
                'detection_modules': ['all'],
                'indicators': ['social_media_images', 'cloud_storage_abuse'],
                'subtechniques': {
                    'T1102.001': {
                        'name': 'Dead Drop Resolver',
                        'description': 'Instructions hidden in public images'
                    }
                }
            },
            'T1104': {
                'id': 'T1104',
                'name': 'Multi-Stage Channels',
                'tactic': 'Command and Control',
                'description': 'Multiple C2 channels for different stages',
                'steganography_relevance': 'PRIMARY',
                'detection_modules': ['multi_layer'],
                'indicators': ['multi_layer_stego', 'nested_payloads']
            },
            'T1132': {
                'id': 'T1132',
                'name': 'Data Encoding',
                'tactic': 'Command and Control',
                'description': 'Encoded data to evade detection',
                'steganography_relevance': 'PRIMARY',
                'detection_modules': ['all'],
                'indicators': ['base64_in_metadata', 'custom_encoding'],
                'subtechniques': {
                    'T1132.001': {
                        'name': 'Standard Encoding',
                        'description': 'Base64/Hex encoding in steganographic containers'
                    }
                }
            },
            'T1573': {
                'id': 'T1573',
                'name': 'Encrypted Channel',
                'tactic': 'Command and Control',
                'description': 'Encrypted C2 to prevent detection',
                'steganography_relevance': 'PRIMARY',
                'detection_modules': ['all'],
                'indicators': ['encrypted_payload', 'high_entropy', 'crypto_signatures'],
                'subtechniques': {
                    'T1573.001': {
                        'name': 'Symmetric Cryptography',
                        'description': 'AES/ChaCha20 encrypted steganographic payloads'
                    },
                    'T1573.002': {
                        'name': 'Asymmetric Cryptography',
                        'description': 'RSA/ECC encrypted data in images'
                    }
                }
            },

            # ==== DEFENSE EVASION TECHNIQUES ====
            'T1027': {
                'id': 'T1027',
                'name': 'Obfuscated Files or Information',
                'tactic': 'Defense Evasion',
                'description': 'Files obfuscated to avoid detection',
                'steganography_relevance': 'PRIMARY',
                'detection_modules': ['all'],
                'indicators': ['obfuscated_payloads', 'encrypted_data', 'hidden_files'],
                'subtechniques': {
                    'T1027.009': {
                        'name': 'Embedded Payloads',
                        'description': 'Malware/data embedded in legitimate files (steganography)'
                    }
                }
            },
            'T1036': {
                'id': 'T1036',
                'name': 'Masquerading',
                'tactic': 'Defense Evasion',
                'description': 'Files disguised as legitimate content',
                'steganography_relevance': 'PRIMARY',
                'detection_modules': ['gan_detector'],
                'indicators': ['fake_images', 'mimicked_formats']
            },
            'T1055': {
                'id': 'T1055',
                'name': 'Process Injection',
                'tactic': 'Defense Evasion',
                'description': 'Injecting code into processes',
                'steganography_relevance': 'SECONDARY',
                'indicators': ['memory_injection', 'process_hollowing']
            },
            'T1070': {
                'id': 'T1070',
                'name': 'Indicator Removal',
                'tactic': 'Defense Evasion',
                'description': 'Deleting artifacts to cover tracks',
                'steganography_relevance': 'SECONDARY',
                'indicators': ['log_deletion', 'timestamp_modification']
            },
            'T1140': {
                'id': 'T1140',
                'name': 'Deobfuscate/Decode Files or Information',
                'tactic': 'Defense Evasion',
                'description': 'Decoding obfuscated data at runtime',
                'steganography_relevance': 'PRIMARY',
                'detection_modules': ['all'],
                'indicators': ['runtime_decryption', 'payload_extraction']
            },
            'T1497': {
                'id': 'T1497',
                'name': 'Virtualization/Sandbox Evasion',
                'tactic': 'Defense Evasion',
                'description': 'Detects/evades analysis environments',
                'steganography_relevance': 'SECONDARY',
                'indicators': ['sandbox_detection', 'vm_evasion']
            },
            'T1564': {
                'id': 'T1564',
                'name': 'Hide Artifacts',
                'tactic': 'Defense Evasion',
                'description': 'Hiding files, processes, or artifacts',
                'steganography_relevance': 'PRIMARY',
                'detection_modules': ['all'],
                'indicators': ['hidden_files', 'alternate_data_streams', 'metadata_hiding'],
                'subtechniques': {
                    'T1564.001': {
                        'name': 'Hidden Files and Directories',
                        'description': 'Data hidden in file system structures'
                    }
                }
            },

            # ==== PERSISTENCE TECHNIQUES ====
            'T1053': {
                'id': 'T1053',
                'name': 'Scheduled Task/Job',
                'tactic': 'Persistence',
                'description': 'Scheduled tasks for persistence',
                'steganography_relevance': 'SECONDARY',
                'indicators': ['cron_jobs', 'scheduled_tasks']
            },
            'T1098': {
                'id': 'T1098',
                'name': 'Account Manipulation',
                'tactic': 'Persistence',
                'description': 'Account modifications for persistence',
                'steganography_relevance': 'SECONDARY',
                'indicators': ['account_changes', 'privilege_escalation']
            },
            'T1136': {
                'id': 'T1136',
                'name': 'Create Account',
                'tactic': 'Persistence',
                'description': 'Creating accounts for persistence',
                'steganography_relevance': 'SECONDARY',
                'indicators': ['new_accounts', 'backdoor_users']
            },
            'T1547': {
                'id': 'T1547',
                'name': 'Boot or Logon Autostart Execution',
                'tactic': 'Persistence',
                'description': 'Autostart mechanisms',
                'steganography_relevance': 'SECONDARY',
                'indicators': ['registry_keys', 'startup_folders']
            },

            # ==== COLLECTION TECHNIQUES ====
            'T1005': {
                'id': 'T1005',
                'name': 'Data from Local System',
                'tactic': 'Collection',
                'description': 'Collecting data from local system',
                'steganography_relevance': 'SECONDARY',
                'indicators': ['file_access', 'data_staging']
            },
            'T1025': {
                'id': 'T1025',
                'name': 'Data from Removable Media',
                'tactic': 'Collection',
                'description': 'Collecting data from USB/removable media',
                'steganography_relevance': 'PRIMARY',
                'detection_modules': ['all'],
                'indicators': ['usb_scanning', 'removable_media_access']
            },
            'T1039': {
                'id': 'T1039',
                'name': 'Data from Network Shared Drive',
                'tactic': 'Collection',
                'description': 'Collecting data from network shares',
                'steganography_relevance': 'SECONDARY',
                'indicators': ['smb_enumeration', 'share_access']
            },
            'T1074': {
                'id': 'T1074',
                'name': 'Data Staged',
                'tactic': 'Collection',
                'description': 'Staging collected data before exfiltration',
                'steganography_relevance': 'PRIMARY',
                'detection_modules': ['all'],
                'indicators': ['data_archives', 'temporary_files']
            },
            'T1114': {
                'id': 'T1114',
                'name': 'Email Collection',
                'tactic': 'Collection',
                'description': 'Collecting email data',
                'steganography_relevance': 'SECONDARY',
                'indicators': ['mailbox_access', 'email_attachments']
            },

            # ==== DISCOVERY TECHNIQUES ====
            'T1083': {
                'id': 'T1083',
                'name': 'File and Directory Discovery',
                'tactic': 'Discovery',
                'description': 'Enumerating files and directories',
                'steganography_relevance': 'SECONDARY',
                'indicators': ['file_enumeration', 'directory_listing']
            },
            'T1087': {
                'id': 'T1087',
                'name': 'Account Discovery',
                'tactic': 'Discovery',
                'description': 'Enumerating accounts',
                'steganography_relevance': 'SECONDARY',
                'indicators': ['user_enumeration', 'account_queries']
            },
            'T1082': {
                'id': 'T1082',
                'name': 'System Information Discovery',
                'tactic': 'Discovery',
                'description': 'Gathering system information',
                'steganography_relevance': 'SECONDARY',
                'indicators': ['system_queries', 'hardware_enumeration']
            },
            'T1518': {
                'id': 'T1518',
                'name': 'Software Discovery',
                'tactic': 'Discovery',
                'description': 'Enumerating installed software',
                'steganography_relevance': 'SECONDARY',
                'indicators': ['software_enumeration', 'security_tool_detection']
            },
            'T1592': {
                'id': 'T1592',
                'name': 'Gather Victim Host Information',
                'tactic': 'Reconnaissance',
                'description': 'Gathering information about victim hosts',
                'steganography_relevance': 'SECONDARY',
                'indicators': ['reconnaissance', 'target_profiling']
            },

            # ==== CREDENTIAL ACCESS TECHNIQUES ====
            'T1003': {
                'id': 'T1003',
                'name': 'OS Credential Dumping',
                'tactic': 'Credential Access',
                'description': 'Dumping credentials from OS',
                'steganography_relevance': 'SECONDARY',
                'indicators': ['credential_theft', 'password_dumping']
            },
            'T1056': {
                'id': 'T1056',
                'name': 'Input Capture',
                'tactic': 'Credential Access',
                'description': 'Capturing user input (keylogging)',
                'steganography_relevance': 'SECONDARY',
                'indicators': ['keylogger', 'input_monitoring']
            },
            'T1552': {
                'id': 'T1552',
                'name': 'Unsecured Credentials',
                'tactic': 'Credential Access',
                'description': 'Accessing unsecured credentials',
                'steganography_relevance': 'SECONDARY',
                'indicators': ['password_files', 'config_files']
            },

            # ==== LATERAL MOVEMENT TECHNIQUES ====
            'T1021': {
                'id': 'T1021',
                'name': 'Remote Services',
                'tactic': 'Lateral Movement',
                'description': 'Lateral movement via remote services',
                'steganography_relevance': 'SECONDARY',
                'indicators': ['rdp_usage', 'ssh_connections']
            },
            'T1080': {
                'id': 'T1080',
                'name': 'Taint Shared Content',
                'tactic': 'Lateral Movement',
                'description': 'Placing malicious content in shared locations',
                'steganography_relevance': 'PRIMARY',
                'detection_modules': ['all'],
                'indicators': ['malicious_shares', 'poisoned_files']
            },

            # ==== IMPACT TECHNIQUES ====
            'T1485': {
                'id': 'T1485',
                'name': 'Data Destruction',
                'tactic': 'Impact',
                'description': 'Destroying data',
                'steganography_relevance': 'SECONDARY',
                'indicators': ['file_deletion', 'disk_wiping']
            },
            'T1486': {
                'id': 'T1486',
                'name': 'Data Encrypted for Impact',
                'tactic': 'Impact',
                'description': 'Encrypting data (ransomware)',
                'steganography_relevance': 'SECONDARY',
                'indicators': ['ransomware', 'file_encryption']
            },
            'T1565': {
                'id': 'T1565',
                'name': 'Data Manipulation',
                'tactic': 'Impact',
                'description': 'Manipulating data',
                'steganography_relevance': 'PRIMARY',
                'detection_modules': ['palette_detector', 'dct_detector'],
                'indicators': ['data_modification', 'file_tampering']
            },

            # ==== RESOURCE DEVELOPMENT TECHNIQUES ====
            'T1583': {
                'id': 'T1583',
                'name': 'Acquire Infrastructure',
                'tactic': 'Resource Development',
                'description': 'Acquiring infrastructure for operations',
                'steganography_relevance': 'SECONDARY',
                'indicators': ['domain_registration', 'server_setup']
            },
            'T1584': {
                'id': 'T1584',
                'name': 'Compromise Infrastructure',
                'tactic': 'Resource Development',
                'description': 'Compromising infrastructure',
                'steganography_relevance': 'SECONDARY',
                'indicators': ['compromised_servers', 'hijacked_domains']
            },
            'T1587': {
                'id': 'T1587',
                'name': 'Develop Capabilities',
                'tactic': 'Resource Development',
                'description': 'Developing tools and capabilities',
                'steganography_relevance': 'PRIMARY',
                'indicators': ['custom_tools', 'malware_development']
            },
            'T1588': {
                'id': 'T1588',
                'name': 'Obtain Capabilities',
                'tactic': 'Resource Development',
                'description': 'Obtaining tools and capabilities',
                'steganography_relevance': 'PRIMARY',
                'indicators': ['tool_acquisition', 'exploit_purchase']
            }
        }

    def _load_mitre_tactics(self) -> Dict:
        """
        Load MITRE ATT&CK tactics (11 total)
        Organized by phase in the cyber kill chain
        """
        return {
            'TA0043': {
                'id': 'TA0043',
                'name': 'Reconnaissance',
                'description': 'Gathering information about the target',
                'techniques': ['T1592', 'T1589', 'T1590']
            },
            'TA0042': {
                'id': 'TA0042',
                'name': 'Resource Development',
                'description': 'Establishing resources for operations',
                'techniques': ['T1583', 'T1584', 'T1587', 'T1588']
            },
            'TA0001': {
                'id': 'TA0001',
                'name': 'Initial Access',
                'description': 'Getting into the network',
                'techniques': ['T1189', 'T1190', 'T1133']
            },
            'TA0002': {
                'id': 'TA0002',
                'name': 'Execution',
                'description': 'Running malicious code',
                'techniques': ['T1059', 'T1203', 'T1204']
            },
            'TA0003': {
                'id': 'TA0003',
                'name': 'Persistence',
                'description': 'Maintaining foothold',
                'techniques': ['T1053', 'T1098', 'T1136', 'T1547']
            },
            'TA0004': {
                'id': 'TA0004',
                'name': 'Privilege Escalation',
                'description': 'Gaining higher-level permissions',
                'techniques': ['T1548', 'T1055', 'T1068']
            },
            'TA0005': {
                'id': 'TA0005',
                'name': 'Defense Evasion',
                'description': 'Avoiding detection',
                'techniques': ['T1027', 'T1036', 'T1055', 'T1070', 'T1140', 'T1497', 'T1564']
            },
            'TA0006': {
                'id': 'TA0006',
                'name': 'Credential Access',
                'description': 'Stealing account credentials',
                'techniques': ['T1003', 'T1056', 'T1552']
            },
            'TA0007': {
                'id': 'TA0007',
                'name': 'Discovery',
                'description': 'Exploring the environment',
                'techniques': ['T1083', 'T1087', 'T1082', 'T1518']
            },
            'TA0008': {
                'id': 'TA0008',
                'name': 'Lateral Movement',
                'description': 'Moving through the network',
                'techniques': ['T1021', 'T1080']
            },
            'TA0009': {
                'id': 'TA0009',
                'name': 'Collection',
                'description': 'Gathering data of interest',
                'techniques': ['T1005', 'T1025', 'T1039', 'T1074', 'T1114']
            },
            'TA0011': {
                'id': 'TA0011',
                'name': 'Command and Control',
                'description': 'Communicating with compromised systems',
                'techniques': ['T1071', 'T1090', 'T1092', 'T1095', 'T1102', 'T1104', 'T1132', 'T1573']
            },
            'TA0010': {
                'id': 'TA0010',
                'name': 'Exfiltration',
                'description': 'Stealing data',
                'techniques': ['T1020', 'T1030', 'T1041', 'T1048', 'T1567']
            },
            'TA0040': {
                'id': 'TA0040',
                'name': 'Impact',
                'description': 'Disrupting operations',
                'techniques': ['T1485', 'T1486', 'T1565']
            }
        }

    def _load_stego_to_mitre_mapping(self) -> Dict:
        """
        Map StegoGuard's steganography techniques to MITRE ATT&CK IDs
        Enables automatic MITRE technique detection from stego analysis
        """
        return {
            # Core steganography techniques
            'hybrid_dct_lsb': ['T1027', 'T1041', 'T1564'],
            'gan_synthetic': ['T1027.009', 'T1036', 'T1564'],
            'lattice_crypto': ['T1573', 'T1027', 'T1041'],
            'multi_layer': ['T1027', 'T1104', 'T1564'],
            'spread_spectrum': ['T1071.001', 'T1041', 'T1132'],
            'metadata_abuse': ['T1048', 'T1564', 'T1071'],

            # Detection module mappings
            'lsb_advanced': ['T1027', 'T1041', 'T1564.001'],
            'wavelet_transform': ['T1027', 'T1140', 'T1564'],
            'palette_reorder': ['T1027', 'T1565', 'T1564'],
            'qr_manipulation': ['T1071', 'T1102.001', 'T1027'],
            'audio_exif': ['T1048', 'T1564', 'T1132'],
            'deepfake_noise': ['T1036', 'T1027.009', 'T1497'],
            'satellite_comms': ['T1071', 'T1048', 'T1573'],
            'ai_evasion': ['T1497', 'T1027', 'T1036'],
            'quantum_resistant': ['T1573', 'T1027', 'T1587']
        }

    def get_mitre_techniques_for_stego(self, stego_technique: str) -> List[Dict]:
        """
        Get MITRE techniques associated with a steganography technique

        Args:
            stego_technique: Steganography technique name

        Returns:
            List of MITRE technique details
        """
        mitre_ids = self.stego_mappings.get(stego_technique, [])
        techniques = []

        for mitre_id in mitre_ids:
            # Handle subtechniques (e.g., T1027.009)
            base_id = mitre_id.split('.')[0]
            if base_id in self.techniques:
                tech = self.techniques[base_id].copy()
                tech['matched_id'] = mitre_id
                techniques.append(tech)

        return techniques

    def get_tactic_for_technique(self, technique_id: str) -> str:
        """Get the primary tactic for a MITRE technique"""
        base_id = technique_id.split('.')[0]
        if base_id in self.techniques:
            return self.techniques[base_id].get('tactic', 'Unknown')
        return 'Unknown'

    def match_techniques(self, detected_techniques: List[str]) -> List[Dict]:
        """
        Match detected steganography techniques to MITRE ATT&CK

        Args:
            detected_techniques: List of detected steganography technique names

        Returns:
            List of matched MITRE techniques with details
        """
        all_mitre_techniques = []
        seen_ids = set()

        for stego_tech in detected_techniques:
            mitre_techs = self.get_mitre_techniques_for_stego(stego_tech)
            for tech in mitre_techs:
                tech_id = tech['matched_id']
                if tech_id not in seen_ids:
                    seen_ids.add(tech_id)
                    all_mitre_techniques.append(tech)

        return all_mitre_techniques

    def get_tactics_coverage(self, mitre_techniques: List[Dict]) -> Dict:
        """
        Calculate tactic coverage based on matched MITRE techniques

        Returns:
            Dictionary of tactics and their matched techniques
        """
        tactics_coverage = {}

        for tech in mitre_techniques:
            tactic = tech.get('tactic', 'Unknown')
            if tactic not in tactics_coverage:
                tactics_coverage[tactic] = []
            tactics_coverage[tactic].append(tech)

        return tactics_coverage

    def calculate_mitre_score(self, mitre_techniques: List[Dict]) -> int:
        """
        Calculate attribution score based on MITRE technique matches

        Scoring:
        - PRIMARY relevance: +25 points
        - SECONDARY relevance: +15 points
        - Tactic coverage bonus: +5 per unique tactic

        Returns:
            Score (0-100)
        """
        score = 0

        # Score by relevance
        for tech in mitre_techniques:
            relevance = tech.get('steganography_relevance', 'SECONDARY')
            if relevance == 'PRIMARY':
                score += 25
            else:
                score += 15

        # Tactic coverage bonus
        unique_tactics = len(set(t.get('tactic') for t in mitre_techniques))
        score += unique_tactics * 5

        return min(score, 100)


# Global instance for easy access
mitre_db = MITREDatabase()
