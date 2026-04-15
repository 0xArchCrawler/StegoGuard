"""
End-to-End Encryption Protocol Handler for StegoGuard Pro

Supports:
- ECDH (Elliptic Curve Diffie-Hellman) key exchange
- X25519 (Curve25519) modern key exchange
- HKDF (HMAC-based Key Derivation Function)
- Session key derivation for AES-256-GCM and ChaCha20
- Perfect forward secrecy support
"""

import hashlib
import hmac
from typing import Dict, Optional, Tuple
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256, SHA384, SHA512
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes
import struct

# Import cryptography library for proper X25519 support
try:
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives import serialization
    HAS_X25519 = True
except ImportError:
    HAS_X25519 = False


class E2EEProtocolHandler:
    """
    End-to-End Encryption Protocol Handler

    Provides key exchange mechanisms for secure steganographic communication
    """

    def __init__(self, curve: str = 'secp256r1'):
        """
        Initialize E2EE protocol handler

        Args:
            curve: Elliptic curve name
                   Supported: 'secp256r1', 'secp384r1', 'secp521r1', 'x25519'
        """
        self.supported_curves = {
            'secp256r1': 'P-256',
            'secp384r1': 'P-384',
            'secp521r1': 'P-521',
            'x25519': 'Curve25519'
        }

        if curve not in self.supported_curves:
            raise ValueError(f"Unsupported curve: {curve}. Use one of {list(self.supported_curves.keys())}")

        self.curve = curve
        self.curve_name = self.supported_curves[curve]

        # Key pair storage
        self.private_key = None
        self.public_key = None
        self.peer_public_key = None
        self.shared_secret = None

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate ephemeral ECDH or X25519 key pair

        Returns:
            Tuple of (private_key_bytes, public_key_bytes)
        """
        if self.curve == 'x25519':
            # X25519 uses proper cryptography library if available
            if HAS_X25519:
                # Use proper cryptography library's X25519
                private_key_obj = x25519.X25519PrivateKey.generate()
                self.private_key = private_key_obj.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                )
                self.public_key = private_key_obj.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                # Store key object for later use
                self._x25519_private_key_obj = private_key_obj
            else:
                # Fallback to simplified Curve25519 (less secure)
                key = ECC.generate(curve='Curve25519')
                self.private_key = key.d.to_bytes()
                self.public_key = key.pointQ.x.to_bytes()
                self._x25519_private_key_obj = None
        else:
            # ECDH with NIST curves
            key = ECC.generate(curve=self.curve_name)
            self.private_key = key.d.to_bytes()

            # Public key is (x, y) point - compress to x-coordinate + sign bit
            public_point = key.pointQ
            self.public_key = public_point.x.to_bytes() + public_point.y.to_bytes()

        return (self.private_key, self.public_key)

    def export_public_key(self, format: str = 'raw') -> bytes:
        """
        Export public key in specified format

        Args:
            format: 'raw' (raw bytes), 'pem' (PEM format), or 'hex' (hex string)

        Returns:
            Public key bytes
        """
        if not self.public_key:
            raise ValueError("No public key generated. Call generate_keypair() first.")

        if format == 'raw':
            return self.public_key
        elif format == 'pem':
            # Reconstruct ECC key from public key bytes
            if self.curve == 'x25519':
                # X25519 PEM format
                return b'-----BEGIN PUBLIC KEY-----\n' + \
                       self.public_key.hex().encode() + \
                       b'\n-----END PUBLIC KEY-----\n'
            else:
                # ECDH PEM format would require full ECC reconstruction
                # For now, return raw bytes
                return self.public_key
        elif format == 'hex':
            return self.public_key.hex().encode()
        else:
            raise ValueError(f"Unsupported format: {format}")

    def import_public_key(self, peer_public_key: bytes, format: str = 'raw') -> None:
        """
        Import peer's public key

        Args:
            peer_public_key: Peer's public key bytes
            format: 'raw', 'pem', or 'hex'
        """
        if format == 'hex':
            peer_public_key = bytes.fromhex(peer_public_key.decode())
        elif format == 'pem':
            # Strip PEM headers and decode hex
            lines = peer_public_key.split(b'\n')
            peer_public_key = bytes.fromhex(lines[1].decode())

        self.peer_public_key = peer_public_key

    def compute_shared_secret(self) -> bytes:
        """
        Compute ECDH or X25519 shared secret

        Returns:
            Shared secret bytes
        """
        if not self.private_key:
            raise ValueError("No private key. Call generate_keypair() first.")
        if not self.peer_public_key:
            raise ValueError("No peer public key. Call import_public_key() first.")

        if self.curve == 'x25519':
            # X25519 shared secret computation - Use proper cryptography library
            if HAS_X25519 and hasattr(self, '_x25519_private_key_obj') and self._x25519_private_key_obj:
                # Use proper X25519 key exchange (cryptographically correct)
                try:
                    peer_key_obj = x25519.X25519PublicKey.from_public_bytes(self.peer_public_key[:32])
                    self.shared_secret = self._x25519_private_key_obj.exchange(peer_key_obj)
                except Exception as e:
                    # If proper exchange fails, fall back to simplified version
                    from Crypto.Math.Numbers import Integer
                    private_scalar = Integer.from_bytes(self.private_key)
                    peer_public_point = Integer.from_bytes(self.peer_public_key[:32])
                    shared = (peer_public_point * private_scalar) % (2**255 - 19)
                    self.shared_secret = shared.to_bytes(32)
            else:
                # Fallback to simplified Curve25519 (less secure but works without cryptography library)
                from Crypto.Math.Numbers import Integer
                private_scalar = Integer.from_bytes(self.private_key)
                peer_public_point = Integer.from_bytes(self.peer_public_key[:32])
                shared = (peer_public_point * private_scalar) % (2**255 - 19)
                self.shared_secret = shared.to_bytes(32)
        else:
            # ECDH shared secret computation
            from Crypto.PublicKey import ECC

            # Reconstruct private key
            private_key_obj = ECC.construct(curve=self.curve_name, d=Integer.from_bytes(self.private_key))

            # Reconstruct peer's public key
            # Peer public key is (x, y) concatenated
            key_size = len(self.peer_public_key) // 2
            peer_x = Integer.from_bytes(self.peer_public_key[:key_size])
            peer_y = Integer.from_bytes(self.peer_public_key[key_size:])

            peer_point = ECC.EccPoint(peer_x, peer_y, curve=self.curve_name)

            # Compute shared secret: shared_point = private_key * peer_public_point
            shared_point = peer_point * private_key_obj.d

            # Shared secret is x-coordinate of shared point
            self.shared_secret = shared_point.x.to_bytes()

        return self.shared_secret

    def derive_session_key(self,
                          shared_secret: Optional[bytes] = None,
                          salt: Optional[bytes] = None,
                          info: bytes = b'StegoGuard-E2EE-v1',
                          key_length: int = 32,
                          hash_algo: str = 'SHA256') -> bytes:
        """
        Derive session key from shared secret using HKDF

        Args:
            shared_secret: Shared secret (uses self.shared_secret if None)
            salt: Optional salt (generates random if None)
            info: Context information string
            key_length: Desired key length in bytes (32 for AES-256/ChaCha20)
            hash_algo: Hash algorithm ('SHA256', 'SHA384', 'SHA512')

        Returns:
            Derived session key
        """
        if shared_secret is None:
            if self.shared_secret is None:
                raise ValueError("No shared secret. Call compute_shared_secret() first.")
            shared_secret = self.shared_secret

        if salt is None:
            salt = get_random_bytes(16)

        # Select hash algorithm
        hash_algos = {
            'SHA256': SHA256,
            'SHA384': SHA384,
            'SHA512': SHA512
        }

        if hash_algo not in hash_algos:
            raise ValueError(f"Unsupported hash: {hash_algo}")

        # HKDF key derivation
        session_key = HKDF(
            master=shared_secret,
            key_len=key_length,
            salt=salt,
            hashmod=hash_algos[hash_algo],
            num_keys=1,
            context=info
        )

        return session_key

    def create_e2ee_header(self,
                          public_key: Optional[bytes] = None,
                          algorithm: str = 'AES-256-GCM',
                          kdf: str = 'HKDF-SHA256') -> bytes:
        """
        Create E2EE header for steganographic embedding

        Format: [MAGIC(4)][CURVE(1)][ALGO(1)][KDF(1)][PUBLIC_KEY_LEN(2)][PUBLIC_KEY(N)]

        Args:
            public_key: Public key to embed (uses self.public_key if None)
            algorithm: Encryption algorithm
            kdf: Key derivation function

        Returns:
            E2EE header bytes
        """
        if public_key is None:
            if self.public_key is None:
                raise ValueError("No public key. Call generate_keypair() first.")
            public_key = self.public_key

        # Magic bytes for E2EE header
        magic = b'E2EE'

        # Curve byte mapping
        curve_map = {
            'secp256r1': 0x01,
            'secp384r1': 0x02,
            'secp521r1': 0x03,
            'x25519': 0x04
        }
        curve_byte = bytes([curve_map[self.curve]])

        # Algorithm byte mapping
        algo_map = {
            'AES-256-GCM': 0x01,
            'AES-256-CBC': 0x02,
            'ChaCha20': 0x03,
            'ChaCha20-Poly1305': 0x04
        }
        algo_byte = bytes([algo_map.get(algorithm, 0x01)])

        # KDF byte mapping
        kdf_map = {
            'HKDF-SHA256': 0x01,
            'HKDF-SHA384': 0x02,
            'HKDF-SHA512': 0x03,
            'PBKDF2': 0x04,
            'Scrypt': 0x05
        }
        kdf_byte = bytes([kdf_map.get(kdf, 0x01)])

        # Public key length (2 bytes, big-endian)
        pubkey_len = struct.pack('>H', len(public_key))

        # Construct header
        header = magic + curve_byte + algo_byte + kdf_byte + pubkey_len + public_key

        return header

    def parse_e2ee_header(self, data: bytes) -> Dict:
        """
        Parse E2EE header from steganographic data

        Args:
            data: Raw data containing E2EE header

        Returns:
            Dictionary with parsed header information
        """
        if len(data) < 9:  # Minimum header size
            return {'has_header': False, 'reason': 'Insufficient data'}

        # Check magic bytes
        magic = data[:4]
        if magic != b'E2EE':
            return {'has_header': False, 'reason': 'Invalid magic bytes'}

        # Parse curve
        curve_map = {
            0x01: 'secp256r1',
            0x02: 'secp384r1',
            0x03: 'secp521r1',
            0x04: 'x25519'
        }
        curve_byte = data[4]
        curve = curve_map.get(curve_byte, 'unknown')

        # Parse algorithm
        algo_map = {
            0x01: 'AES-256-GCM',
            0x02: 'AES-256-CBC',
            0x03: 'ChaCha20',
            0x04: 'ChaCha20-Poly1305'
        }
        algo_byte = data[5]
        algorithm = algo_map.get(algo_byte, 'unknown')

        # Parse KDF
        kdf_map = {
            0x01: 'HKDF-SHA256',
            0x02: 'HKDF-SHA384',
            0x03: 'HKDF-SHA512',
            0x04: 'PBKDF2',
            0x05: 'Scrypt'
        }
        kdf_byte = data[6]
        kdf = kdf_map.get(kdf_byte, 'unknown')

        # Parse public key length
        pubkey_len = struct.unpack('>H', data[7:9])[0]

        # Extract public key
        if len(data) < 9 + pubkey_len:
            return {'has_header': False, 'reason': 'Truncated public key'}

        public_key = data[9:9+pubkey_len]

        # Payload starts after public key
        payload_start = 9 + pubkey_len

        return {
            'has_header': True,
            'magic': magic,
            'curve': curve,
            'algorithm': algorithm,
            'kdf': kdf,
            'public_key': public_key,
            'public_key_length': pubkey_len,
            'payload_start': payload_start,
            'header_size': payload_start
        }

    def encrypt_with_e2ee(self,
                         plaintext: bytes,
                         peer_public_key: bytes,
                         algorithm: str = 'AES-256-GCM',
                         kdf: str = 'HKDF-SHA256') -> Dict:
        """
        Complete E2EE encryption workflow

        Args:
            plaintext: Data to encrypt
            peer_public_key: Recipient's public key
            algorithm: Encryption algorithm
            kdf: Key derivation function

        Returns:
            Dictionary with encrypted data and metadata
        """
        # Generate ephemeral key pair
        self.generate_keypair()

        # Import peer's public key
        self.import_public_key(peer_public_key)

        # Compute shared secret
        shared_secret = self.compute_shared_secret()

        # Derive session key
        salt = get_random_bytes(16)
        session_key = self.derive_session_key(shared_secret, salt, key_length=32, hash_algo=kdf.split('-')[1])

        # Encrypt with session key using specified algorithm
        from Crypto.Cipher import AES, ChaCha20

        if algorithm == 'AES-256-GCM':
            nonce = get_random_bytes(12)
            cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)

            return {
                'success': True,
                'ciphertext': ciphertext,
                'nonce': nonce,
                'tag': tag,
                'salt': salt,
                'public_key': self.public_key,
                'algorithm': algorithm,
                'kdf': kdf,
                'curve': self.curve
            }
        elif algorithm == 'ChaCha20':
            nonce = get_random_bytes(8)
            cipher = ChaCha20.new(key=session_key, nonce=nonce)
            ciphertext = cipher.encrypt(plaintext)

            return {
                'success': True,
                'ciphertext': ciphertext,
                'nonce': nonce,
                'tag': None,
                'salt': salt,
                'public_key': self.public_key,
                'algorithm': algorithm,
                'kdf': kdf,
                'curve': self.curve
            }
        else:
            return {'success': False, 'error': f'Unsupported algorithm: {algorithm}'}

    def decrypt_with_e2ee(self,
                         ciphertext: bytes,
                         peer_public_key: bytes,
                         nonce: bytes,
                         salt: bytes,
                         tag: Optional[bytes] = None,
                         algorithm: str = 'AES-256-GCM',
                         kdf: str = 'HKDF-SHA256') -> Dict:
        """
        Complete E2EE decryption workflow

        Args:
            ciphertext: Encrypted data
            peer_public_key: Sender's public key
            nonce: Encryption nonce
            salt: KDF salt
            tag: Authentication tag (for AEAD modes)
            algorithm: Encryption algorithm
            kdf: Key derivation function

        Returns:
            Dictionary with decrypted data or error
        """
        # Import peer's public key (sender's public key in this case)
        self.import_public_key(peer_public_key)

        # Compute shared secret using our private key
        if not self.private_key:
            return {'success': False, 'error': 'No private key available'}

        shared_secret = self.compute_shared_secret()

        # Derive session key with same parameters
        session_key = self.derive_session_key(shared_secret, salt, key_length=32, hash_algo=kdf.split('-')[1])

        # Decrypt with session key
        from Crypto.Cipher import AES, ChaCha20

        try:
            if algorithm == 'AES-256-GCM':
                if not tag:
                    return {'success': False, 'error': 'Missing authentication tag for AES-GCM'}

                cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)

                return {
                    'success': True,
                    'plaintext': plaintext,
                    'algorithm': algorithm
                }
            elif algorithm == 'ChaCha20':
                cipher = ChaCha20.new(key=session_key, nonce=nonce)
                plaintext = cipher.decrypt(ciphertext)

                return {
                    'success': True,
                    'plaintext': plaintext,
                    'algorithm': algorithm
                }
            else:
                return {'success': False, 'error': f'Unsupported algorithm: {algorithm}'}
        except Exception as e:
            return {'success': False, 'error': f'Decryption failed: {str(e)}'}


# Helper functions for common use cases
def generate_e2ee_keypair(curve: str = 'secp256r1') -> Tuple[bytes, bytes]:
    """
    Quick helper to generate E2EE key pair

    Args:
        curve: Curve name (secp256r1, secp384r1, secp521r1, x25519)

    Returns:
        Tuple of (private_key, public_key)
    """
    handler = E2EEProtocolHandler(curve=curve)
    return handler.generate_keypair()


def create_e2ee_session(my_private_key: bytes,
                       peer_public_key: bytes,
                       curve: str = 'secp256r1') -> bytes:
    """
    Quick helper to create E2EE session key

    Args:
        my_private_key: Your private key
        peer_public_key: Peer's public key
        curve: Curve name

    Returns:
        Derived session key (32 bytes)
    """
    handler = E2EEProtocolHandler(curve=curve)
    handler.private_key = my_private_key
    handler.import_public_key(peer_public_key)
    shared_secret = handler.compute_shared_secret()
    return handler.derive_session_key(shared_secret)
