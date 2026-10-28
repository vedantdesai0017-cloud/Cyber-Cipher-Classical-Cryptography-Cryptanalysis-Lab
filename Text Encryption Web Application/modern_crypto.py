"""
Cyber Cipher - Modern Cryptography Engine (V2)
Implements industry-standard AES-256-GCM authenticated encryption with
secure PBKDF2-HMAC-SHA256 password-based key derivation.
"""

import os
import base64
from typing import Dict, Any, Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

# Cryptographic Constants
KDF_ALGORITHM = "PBKDF2-HMAC-SHA256"
KDF_ITERATIONS = 600000  # OWASP 2023/2024 recommended iteration count
KEY_LENGTH_BYTES = 32    # 256-bit AES key
SALT_LENGTH_BYTES = 16   # 128-bit CSPRNG salt
NONCE_LENGTH_BYTES = 12  # 96-bit CSPRNG nonce (NIST SP 800-38D standard)
TAG_LENGTH_BYTES = 16    # 128-bit authentication tag
FORMAT_PREFIX = "CYBER1"
ASSOCIATED_DATA = b"CyberCipher-v2-AEAD"


def derive_key(password: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    """
    Derives a 256-bit cryptographic key from a password using PBKDF2-HMAC-SHA256.
    
    Parameters:
        password (str): User-provided secret password.
        salt (bytes): 16-byte cryptographically secure random salt.
        iterations (int): Work factor (default: 600,000).
        
    Returns:
        bytes: 32-byte derived AES key.
    """
    if not password:
        raise ValueError("Please enter a password.")
    if not salt or len(salt) < 16:
        raise ValueError("Invalid cryptographic salt.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH_BYTES,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def aes_encrypt_text(plaintext: str, password: str) -> Dict[str, Any]:
    """
    Encrypts plaintext using AES-256-GCM and a password-derived key.
    
    Parameters:
        plaintext (str): Message to encrypt.
        password (str): Password to derive the AES key.
        
    Returns:
        dict: {
            'result': str (formatted bundle),
            'algorithm': 'AES-256-GCM',
            'kdf': 'PBKDF2-HMAC-SHA256',
            'iterations': int,
            'salt_hex': str,
            'nonce_hex': str,
            'tag_length_bits': 128,
            'ciphertext_length': int,
            'pipeline_steps': list
        }
    """
    if not plaintext:
        raise ValueError("Please enter some text.")
    if not password:
        raise ValueError("Please enter a password.")

    # 1. Generate CSPRNG salt (16 bytes) and nonce (12 bytes)
    salt = os.urandom(SALT_LENGTH_BYTES)
    nonce = os.urandom(NONCE_LENGTH_BYTES)

    # 2. Derive 256-bit AES key via PBKDF2-HMAC-SHA256
    derived_key = derive_key(password, salt, KDF_ITERATIONS)

    # 3. Encrypt and authenticate with AES-256-GCM
    # Note: cryptography's AESGCM.encrypt appends the 16-byte tag to the ciphertext
    aesgcm = AESGCM(derived_key)
    raw_plaintext = plaintext.encode("utf-8")
    ciphertext_with_tag = aesgcm.encrypt(nonce, raw_plaintext, ASSOCIATED_DATA)

    # Split tag from ciphertext for educational inspection
    tag = ciphertext_with_tag[-TAG_LENGTH_BYTES:]
    raw_ciphertext = ciphertext_with_tag[:-TAG_LENGTH_BYTES]

    # 4. Serialize into portable bundle: CYBER1$<salt_hex>$<nonce_hex>$<b64_payload>
    b64_payload = base64.b64encode(ciphertext_with_tag).decode("utf-8")
    salt_hex = salt.hex()
    nonce_hex = nonce.hex()
    tag_hex = tag.hex()

    bundle = f"{FORMAT_PREFIX}${salt_hex}${nonce_hex}${b64_payload}"

    pipeline_steps = [
        {"step": "Plaintext Encoding", "detail": f"UTF-8 encoded {len(raw_plaintext)} bytes."},
        {"step": "CSPRNG Salt Generation", "detail": f"Generated 128-bit random salt ({salt_hex[:8]}...)."},
        {"step": "Key Derivation (KDF)", "detail": f"Derived 256-bit key using {KDF_ALGORITHM} with {KDF_ITERATIONS:,} iterations."},
        {"step": "CSPRNG Nonce Generation", "detail": f"Generated 96-bit single-use nonce ({nonce_hex[:8]}...)."},
        {"step": "AES-256-GCM Encryption", "detail": f"Encrypted payload into {len(raw_ciphertext)} bytes of ciphertext."},
        {"step": "Authentication Tag", "detail": f"Computed 128-bit GMAC authentication tag ({tag_hex[:8]}...)."}
    ]

    return {
        "result": bundle,
        "algorithm": "AES-256-GCM",
        "kdf": KDF_ALGORITHM,
        "iterations": KDF_ITERATIONS,
        "salt_hex": salt_hex,
        "nonce_hex": nonce_hex,
        "tag_hex": tag_hex,
        "tag_length_bits": 128,
        "ciphertext_length": len(raw_ciphertext),
        "pipeline_steps": pipeline_steps
    }


def aes_decrypt_text(encrypted_bundle: str, password: str) -> Dict[str, Any]:
    """
    Authenticates and decrypts a CYBER1 bundle using AES-256-GCM and the password.
    
    Parameters:
        encrypted_bundle (str): Serialized CYBER1 bundle.
        password (str): Password used for encryption.
        
    Returns:
        dict: {'result': str (plaintext), 'algorithm': 'AES-256-GCM', 'pipeline_steps': list}
    """
    if not encrypted_bundle or not encrypted_bundle.strip():
        raise ValueError("Please enter ciphertext to decrypt.")
    if not password:
        raise ValueError("Please enter a password.")

    parts = encrypted_bundle.strip().split("$")
    if len(parts) != 4 or parts[0] != FORMAT_PREFIX:
        raise ValueError("Invalid encrypted data format. Expected CYBER1 bundle.")

    _, salt_hex, nonce_hex, b64_payload = parts

    try:
        salt = bytes.fromhex(salt_hex)
        nonce = bytes.fromhex(nonce_hex)
        ciphertext_with_tag = base64.b64decode(b64_payload.encode("utf-8"))
    except Exception:
        raise ValueError("Invalid encrypted data encoding.")

    if len(salt) != SALT_LENGTH_BYTES or len(nonce) != NONCE_LENGTH_BYTES or len(ciphertext_with_tag) < TAG_LENGTH_BYTES:
        raise ValueError("Invalid cryptographic parameters in encrypted bundle.")

    # 1. Derive identical 256-bit key using provided password and extracted salt
    derived_key = derive_key(password, salt, KDF_ITERATIONS)

    # 2. Authenticate and decrypt with AES-256-GCM
    aesgcm = AESGCM(derived_key)
    try:
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, ASSOCIATED_DATA)
        plaintext = decrypted_bytes.decode("utf-8")
    except InvalidTag:
        # Crucial security rule: Catch authentication failure and report uniform, safe error message
        raise ValueError("Decryption failed: incorrect password or corrupted data.")
    except UnicodeDecodeError:
        raise ValueError("Decryption failed: incorrect password or corrupted data.")
    except Exception:
        raise ValueError("Decryption failed: incorrect password or corrupted data.")

    pipeline_steps = [
        {"step": "Bundle Parsing", "detail": f"Extracted 16-byte salt and 12-byte nonce from {FORMAT_PREFIX} bundle."},
        {"step": "Key Derivation (KDF)", "detail": f"Re-derived 256-bit key with {KDF_ITERATIONS:,} PBKDF2 iterations."},
        {"step": "Authentication Verification", "detail": "Verified 128-bit GMAC authentication tag (ciphertext is genuine and untampered)."},
        {"step": "AES-256-GCM Decryption", "detail": f"Decrypted {len(decrypted_bytes)} bytes into original UTF-8 plaintext."}
    ]

    return {
        "result": plaintext,
        "algorithm": "AES-256-GCM",
        "pipeline_steps": pipeline_steps
    }
