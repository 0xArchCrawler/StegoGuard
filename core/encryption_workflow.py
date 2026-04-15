"""
Encryption Workflow Module for StegoGuard Pro
Handles encryption and embedding pipeline for test image generation and E2EE support
"""
import numpy as np
from PIL import Image
from Crypto.Cipher import AES, ChaCha20
from Crypto.Protocol.KDF import PBKDF2, scrypt
from Crypto.Random import get_random_bytes
import hashlib
import hmac
from typing import Dict, Tuple, Optional
import json
from .e2ee_protocol_handler import E2EEProtocolHandler


class EncryptionWorkflow:
    """
    Complete encryption and embedding workflow
    Supports: AES-256-GCM, ChaCha20, with PBKDF2/Scrypt key derivation
    """

    def __init__(self):
        self.supported_algorithms = [
            'AES-256-GCM',
            'AES-256-CBC',
            'ChaCha20',
            'ChaCha20-Poly1305'
        ]

        self.supported_kdf = [
            'PBKDF2',
            'Scrypt',
            'SHA256',
            'SHA512'
        ]

    def encrypt_and_embed(
        self,
        image_path: str,
        data: bytes,
        password: str,
        algorithm: str = 'AES-256-GCM',
        kdf_method: str = 'PBKDF2',
        output_path: Optional[str] = None,
        bit_planes: int = 1
    ) -> Dict:
        """
        Complete pipeline: Encrypt data → Embed in image LSB

        Args:
            image_path: Source image path
            data: Data to encrypt and embed
            password: Encryption password
            algorithm: Encryption algorithm to use
            kdf_method: Key derivation function
            output_path: Output image path
            bit_planes: Number of LSB planes to use (1, 2, or 4)

        Returns:
            Dict with encryption and embedding details
        """
        try:
            # Step 1: Encrypt the data
            encrypted_result = self.encrypt_data(
                data=data,
                password=password,
                algorithm=algorithm,
                kdf_method=kdf_method
            )

            if not encrypted_result['success']:
                return encrypted_result

            # Step 2: Create LSB header + encrypted data
            header = self.create_lsb_header(
                salt=encrypted_result['salt'],
                nonce=encrypted_result['nonce'],
                tag=encrypted_result.get('tag'),
                algorithm=algorithm,
                kdf_method=kdf_method
            )

            # Step 3: Embed in image LSB
            embed_result = self.embed_encrypted_data(
                image_path=image_path,
                header=header,
                encrypted_data=encrypted_result['ciphertext'],
                output_path=output_path or image_path.replace('.', '_encrypted.'),
                bit_planes=bit_planes
            )

            if embed_result['success']:
                embed_result.update({
                    'encryption_algorithm': algorithm,
                    'kdf_method': kdf_method,
                    'data_size': len(data),
                    'encrypted_size': len(encrypted_result['ciphertext']),
                    'total_embedded_size': len(header) + len(encrypted_result['ciphertext'])
                })

            return embed_result

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def encrypt_data(
        self,
        data: bytes,
        password: str,
        algorithm: str = 'AES-256-GCM',
        kdf_method: str = 'PBKDF2'
    ) -> Dict:
        """
        Encrypt data with specified algorithm and key derivation

        Returns:
            Dict with ciphertext, salt, nonce, tag (if applicable)
        """
        try:
            # Convert password to bytes
            if isinstance(password, str):
                password = password.encode('utf-8')

            # Generate random salt
            salt = get_random_bytes(16)

            # Derive encryption key
            key = self.derive_key(
                password=password,
                salt=salt,
                key_length=32,
                method=kdf_method
            )

            # Encrypt based on algorithm
            if algorithm == 'AES-256-GCM':
                return self._encrypt_aes_gcm(data, key, salt)
            elif algorithm == 'AES-256-CBC':
                return self._encrypt_aes_cbc(data, key, salt)
            elif algorithm == 'ChaCha20':
                return self._encrypt_chacha20(data, key, salt)
            elif algorithm == 'ChaCha20-Poly1305':
                return self._encrypt_chacha20_poly1305(data, key, salt)
            else:
                return {'success': False, 'error': f'Unsupported algorithm: {algorithm}'}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def derive_key(
        self,
        password: bytes,
        salt: bytes,
        key_length: int = 32,
        method: str = 'PBKDF2'
    ) -> bytes:
        """
        Derive encryption key from password

        Args:
            password: Input password
            salt: Random salt
            key_length: Output key length (bytes)
            method: KDF method (PBKDF2, Scrypt, SHA256, SHA512)

        Returns:
            Derived key
        """
        if method == 'PBKDF2':
            return PBKDF2(password, salt, dkLen=key_length, count=100000)
        elif method == 'Scrypt':
            return scrypt(password, salt, key_len=key_length, N=2**14, r=8, p=1)
        elif method == 'SHA256':
            return hashlib.sha256(password + salt).digest()[:key_length]
        elif method == 'SHA512':
            return hashlib.sha512(password + salt).digest()[:key_length]
        else:
            raise ValueError(f'Unsupported KDF method: {method}')

    def _encrypt_aes_gcm(self, data: bytes, key: bytes, salt: bytes) -> Dict:
        """Encrypt with AES-256-GCM"""
        nonce = get_random_bytes(12)  # 96-bit nonce for GCM
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        return {
            'success': True,
            'ciphertext': ciphertext,
            'salt': salt,
            'nonce': nonce,
            'tag': tag,
            'algorithm': 'AES-256-GCM'
        }

    def _encrypt_aes_cbc(self, data: bytes, key: bytes, salt: bytes) -> Dict:
        """Encrypt with AES-256-CBC"""
        from Crypto.Util.Padding import pad
        nonce = get_random_bytes(16)  # 128-bit IV for CBC
        cipher = AES.new(key, AES.MODE_CBC, nonce)
        ciphertext = cipher.encrypt(pad(data, AES.block_size))

        return {
            'success': True,
            'ciphertext': ciphertext,
            'salt': salt,
            'nonce': nonce,
            'tag': None,
            'algorithm': 'AES-256-CBC'
        }

    def _encrypt_chacha20(self, data: bytes, key: bytes, salt: bytes) -> Dict:
        """Encrypt with ChaCha20"""
        nonce = get_random_bytes(8)  # 64-bit nonce for ChaCha20
        cipher = ChaCha20.new(key=key, nonce=nonce)
        ciphertext = cipher.encrypt(data)

        return {
            'success': True,
            'ciphertext': ciphertext,
            'salt': salt,
            'nonce': nonce,
            'tag': None,
            'algorithm': 'ChaCha20'
        }

    def _encrypt_chacha20_poly1305(self, data: bytes, key: bytes, salt: bytes) -> Dict:
        """Encrypt with ChaCha20-Poly1305 (AEAD)"""
        from Crypto.Cipher import ChaCha20_Poly1305
        nonce = get_random_bytes(12)  # 96-bit nonce
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        return {
            'success': True,
            'ciphertext': ciphertext,
            'salt': salt,
            'nonce': nonce,
            'tag': tag,
            'algorithm': 'ChaCha20-Poly1305'
        }

    def create_lsb_header(
        self,
        salt: bytes,
        nonce: bytes,
        tag: Optional[bytes],
        algorithm: str,
        kdf_method: str
    ) -> bytes:
        """
        Create LSB header with encryption metadata

        Format: [MAGIC][ALGO][KDF][SALT][NONCE][TAG?]
        """
        magic = b'STEG'  # 4 bytes magic
        algo_byte = self._algorithm_to_byte(algorithm)
        kdf_byte = self._kdf_to_byte(kdf_method)

        header = magic + algo_byte + kdf_byte + salt + nonce

        if tag:
            header += tag

        return header

    def embed_encrypted_data(
        self,
        image_path: str,
        header: bytes,
        encrypted_data: bytes,
        output_path: str,
        bit_planes: int = 1
    ) -> Dict:
        """
        Embed header + encrypted data in image LSB

        Args:
            image_path: Source image
            header: Encryption header
            encrypted_data: Encrypted payload
            output_path: Output image path
            bit_planes: Number of LSB planes (1, 2, or 4)
        """
        try:
            img = Image.open(image_path)
            img_array = np.array(img)

            if len(img_array.shape) < 3:
                height, width = img_array.shape
                channels = 1
                img_array = img_array.reshape(height, width, 1)
            else:
                height, width, channels = img_array.shape

            # Combine header + data + EOF marker
            payload = header + encrypted_data + b'\xFF\xFE'

            # Convert to bits
            bits = []
            for byte in payload:
                for i in range(8):
                    bits.append((byte >> (7 - i)) & 1)

            # Check capacity
            max_capacity = height * width * channels * bit_planes
            if len(bits) > max_capacity:
                return {
                    'success': False,
                    'error': f'Data too large: {len(bits)} bits > {max_capacity} capacity'
                }

            # Embed bits in LSB
            bit_idx = 0
            for y in range(height):
                for x in range(width):
                    for c in range(channels):
                        if bit_idx >= len(bits):
                            break

                        pixel = img_array[y, x, c] if channels > 1 else img_array[y, x]

                        # Modify N least significant bits
                        for plane in range(bit_planes):
                            if bit_idx >= len(bits):
                                break

                            # Clear bit and set new value
                            pixel = (pixel & ~(1 << plane)) | (bits[bit_idx] << plane)
                            bit_idx += 1

                        if channels > 1:
                            img_array[y, x, c] = pixel
                        else:
                            img_array[y, x] = pixel

                    if bit_idx >= len(bits):
                        break
                if bit_idx >= len(bits):
                    break

            # Save modified image
            output_img = Image.fromarray(img_array.squeeze() if channels == 1 else img_array)
            output_img.save(output_path)

            return {
                'success': True,
                'output_path': output_path,
                'bits_embedded': bit_idx,
                'capacity_used_percent': (bit_idx / max_capacity) * 100,
                'bit_planes': bit_planes
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def encrypt_and_embed_e2ee(
        self,
        image_path: str,
        data: bytes,
        peer_public_key: bytes,
        curve: str = 'secp256r1',
        algorithm: str = 'AES-256-GCM',
        kdf: str = 'HKDF-SHA256',
        output_path: Optional[str] = None,
        bit_planes: int = 1
    ) -> Dict:
        """
        Complete E2EE pipeline: Generate keypair → Compute shared secret → Encrypt → Embed

        Args:
            image_path: Source image path
            data: Data to encrypt and embed
            peer_public_key: Recipient's public key (raw bytes)
            curve: Elliptic curve to use (secp256r1, secp384r1, secp521r1, x25519)
            algorithm: Encryption algorithm (AES-256-GCM, ChaCha20)
            kdf: Key derivation function (HKDF-SHA256, HKDF-SHA384, HKDF-SHA512)
            output_path: Output image path
            bit_planes: Number of LSB planes to use (1, 2, or 4)

        Returns:
            Dict with encryption and embedding details, including sender's public key
        """
        try:
            # Step 1: Initialize E2EE handler
            e2ee_handler = E2EEProtocolHandler(curve=curve)

            # Step 2: Generate ephemeral keypair for this session
            private_key, public_key = e2ee_handler.generate_keypair()

            # Step 3: Encrypt data using E2EE
            encryption_result = e2ee_handler.encrypt_with_e2ee(
                plaintext=data,
                peer_public_key=peer_public_key,
                algorithm=algorithm,
                kdf=kdf
            )

            if not encryption_result.get('success'):
                return encryption_result

            # Step 4: Create E2EE header
            e2ee_header = e2ee_handler.create_e2ee_header(
                public_key=public_key,
                algorithm=algorithm,
                kdf=kdf
            )

            # Step 5: Assemble complete payload
            # Format: [E2EE_HEADER][SALT][NONCE][TAG?][CIPHERTEXT][EOF]
            payload = e2ee_header
            payload += encryption_result['salt']
            payload += encryption_result['nonce']

            if encryption_result.get('tag'):
                payload += encryption_result['tag']

            payload += encryption_result['ciphertext']

            # Step 6: Embed in image LSB
            embed_result = self.embed_e2ee_data(
                image_path=image_path,
                payload=payload,
                output_path=output_path or image_path.replace('.', '_e2ee.'),
                bit_planes=bit_planes
            )

            if embed_result['success']:
                embed_result.update({
                    'e2ee_enabled': True,
                    'curve': curve,
                    'algorithm': algorithm,
                    'kdf': kdf,
                    'sender_public_key': public_key.hex(),
                    'sender_public_key_raw': public_key,
                    'data_size': len(data),
                    'encrypted_size': len(encryption_result['ciphertext']),
                    'total_embedded_size': len(payload),
                    'note': 'Recipient must use their private key to decrypt'
                })

            return embed_result

        except Exception as e:
            return {'success': False, 'error': f'E2EE encryption failed: {str(e)}'}

    def embed_e2ee_data(
        self,
        image_path: str,
        payload: bytes,
        output_path: str,
        bit_planes: int = 1
    ) -> Dict:
        """
        Embed E2EE encrypted payload in image LSB

        Args:
            image_path: Source image
            payload: Complete E2EE payload (header + encrypted data)
            output_path: Output image path
            bit_planes: Number of LSB planes (1, 2, or 4)
        """
        try:
            img = Image.open(image_path)
            img_array = np.array(img)

            if len(img_array.shape) < 3:
                height, width = img_array.shape
                channels = 1
                img_array = img_array.reshape(height, width, 1)
            else:
                height, width, channels = img_array.shape

            # Add EOF marker
            payload_with_eof = payload + b'\xFF\xFE'

            # Convert to bits
            bits = []
            for byte in payload_with_eof:
                for i in range(8):
                    bits.append((byte >> (7 - i)) & 1)

            # Check capacity
            max_capacity = height * width * channels * bit_planes
            if len(bits) > max_capacity:
                return {
                    'success': False,
                    'error': f'Data too large: {len(bits)} bits > {max_capacity} capacity'
                }

            # Embed bits in LSB
            bit_idx = 0
            for y in range(height):
                for x in range(width):
                    for c in range(channels):
                        if bit_idx >= len(bits):
                            break

                        pixel = img_array[y, x, c] if channels > 1 else img_array[y, x]

                        # Modify N least significant bits
                        for plane in range(bit_planes):
                            if bit_idx >= len(bits):
                                break

                            # Clear bit and set new value
                            pixel = (pixel & ~(1 << plane)) | (bits[bit_idx] << plane)
                            bit_idx += 1

                        if channels > 1:
                            img_array[y, x, c] = pixel
                        else:
                            img_array[y, x] = pixel

                    if bit_idx >= len(bits):
                        break
                if bit_idx >= len(bits):
                    break

            # Save modified image
            output_img = Image.fromarray(img_array.squeeze() if channels == 1 else img_array)
            output_img.save(output_path)

            return {
                'success': True,
                'output_path': output_path,
                'bits_embedded': bit_idx,
                'capacity_used_percent': (bit_idx / max_capacity) * 100,
                'bit_planes': bit_planes
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _algorithm_to_byte(self, algorithm: str) -> bytes:
        """Convert algorithm name to byte identifier"""
        algo_map = {
            'AES-256-GCM': b'\x01',
            'AES-256-CBC': b'\x02',
            'ChaCha20': b'\x03',
            'ChaCha20-Poly1305': b'\x04'
        }
        return algo_map.get(algorithm, b'\x00')

    def _kdf_to_byte(self, kdf_method: str) -> bytes:
        """Convert KDF method to byte identifier"""
        kdf_map = {
            'PBKDF2': b'\x01',
            'Scrypt': b'\x02',
            'SHA256': b'\x03',
            'SHA512': b'\x04'
        }
        return kdf_map.get(kdf_method, b'\x00')


# Convenience functions for easy import
def create_encrypted_image(
    image_path: str,
    data: bytes,
    password: str,
    output_path: str,
    algorithm: str = 'AES-256-GCM'
) -> Dict:
    """
    Quick helper to create encrypted steganographic image

    Example:
        data = json.dumps({"secret": "message"}).encode()
        result = create_encrypted_image(
            'input.jpg',
            data,
            'password123',
            'output_encrypted.jpg',
            'AES-256-GCM'
        )
    """
    workflow = EncryptionWorkflow()
    return workflow.encrypt_and_embed(
        image_path=image_path,
        data=data,
        password=password,
        algorithm=algorithm,
        output_path=output_path
    )


def create_e2ee_encrypted_image(
    image_path: str,
    data: bytes,
    peer_public_key: bytes,
    output_path: str,
    curve: str = 'secp256r1',
    algorithm: str = 'AES-256-GCM'
) -> Dict:
    """
    Quick helper to create E2EE encrypted steganographic image

    Example:
        from .e2ee_protocol_handler import generate_e2ee_keypair

        # Recipient generates keypair
        recipient_private, recipient_public = generate_e2ee_keypair('secp256r1')

        # Sender encrypts data for recipient
        data = json.dumps({"secret": "message"}).encode()
        result = create_e2ee_encrypted_image(
            'input.png',
            data,
            recipient_public,
            'output_e2ee.png',
            curve='secp256r1',
            algorithm='AES-256-GCM'
        )

        # Sender shares their public key with recipient
        sender_public_key = result['sender_public_key_raw']

        # Recipient can decrypt using their private key
    """
    workflow = EncryptionWorkflow()
    return workflow.encrypt_and_embed_e2ee(
        image_path=image_path,
        data=data,
        peer_public_key=peer_public_key,
        curve=curve,
        algorithm=algorithm,
        output_path=output_path
    )
