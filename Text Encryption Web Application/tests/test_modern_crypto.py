"""
Cyber Cipher V2 - Modern Cryptography Unit Tests
Tests for AES-256-GCM text encryption, PBKDF2 key derivation, and authentication.
"""

import unittest
import base64
from modern_crypto import (
    aes_encrypt_text,
    aes_decrypt_text,
    derive_key,
    KDF_ITERATIONS,
    KEY_LENGTH_BYTES
)


class TestModernCrypto(unittest.TestCase):
    """Test suite for AES-256-GCM text encryption, decryption, and authentication."""

    def test_derive_key_length(self):
        salt = b"0123456789abcdef"
        key = derive_key("Password123!", salt, iterations=1000)
        self.assertEqual(len(key), KEY_LENGTH_BYTES)

    def test_aes_text_encryption_roundtrip(self):
        plaintext = "Highly confidential intelligence briefing: Alpha Team deployed at 0400."
        password = "SecurePassword#2026!"
        encrypted = aes_encrypt_text(plaintext, password)
        
        self.assertTrue(encrypted["result"].startswith("CYBER1$"))
        self.assertEqual(encrypted["algorithm"], "AES-256-GCM")
        self.assertEqual(encrypted["tag_length_bits"], 128)
        
        decrypted = aes_decrypt_text(encrypted["result"], password)
        self.assertEqual(decrypted["result"], plaintext)

    def test_aes_text_unicode_and_multiline(self):
        plaintext = "Hello 世界 🌍! Special chars: \n\t#@$%^&*()_+~|}{[]:;?><,./"
        password = "Password🔑"
        encrypted = aes_encrypt_text(plaintext, password)
        decrypted = aes_decrypt_text(encrypted["result"], password)
        self.assertEqual(decrypted["result"], plaintext)

    def test_aes_distinct_nonces_and_salts(self):
        # Encrypting the exact same plaintext twice with the same password MUST produce different bundles
        plain = "Consistent plaintext"
        pwd = "SamePassword123"
        enc1 = aes_encrypt_text(plain, pwd)
        enc2 = aes_encrypt_text(plain, pwd)
        
        self.assertNotEqual(enc1["result"], enc2["result"])
        self.assertNotEqual(enc1["salt_hex"], enc2["salt_hex"])
        self.assertNotEqual(enc1["nonce_hex"], enc2["nonce_hex"])

    def test_aes_wrong_password_fails_authentication(self):
        plain = "Secret Message"
        enc = aes_encrypt_text(plain, "CorrectPassword!")
        with self.assertRaises(ValueError) as ctx:
            aes_decrypt_text(enc["result"], "IncorrectPassword!")
        self.assertEqual(str(ctx.exception), "Decryption failed: incorrect password or corrupted data.")

    def test_aes_tampered_ciphertext_fails_tag(self):
        plain = "Financial transfer authorization: $500,000 to Account #8892."
        pwd = "BankerPassword!"
        enc = aes_encrypt_text(plain, pwd)
        
        # Tamper with the base64 ciphertext payload (flip bits)
        prefix, salt_hex, nonce_hex, b64_payload = enc["result"].split("$")
        raw = bytearray(base64.b64decode(b64_payload))
        raw[0] ^= 0xFF  # Invert first byte
        tampered_bundle = f"{prefix}${salt_hex}${nonce_hex}${base64.b64encode(raw).decode()}"
        
        with self.assertRaises(ValueError) as ctx:
            aes_decrypt_text(tampered_bundle, pwd)
        self.assertEqual(str(ctx.exception), "Decryption failed: incorrect password or corrupted data.")

    def test_aes_tampered_nonce_fails_tag(self):
        plain = "Top secret"
        pwd = "Password123"
        enc = aes_encrypt_text(plain, pwd)
        
        prefix, salt_hex, nonce_hex, b64_payload = enc["result"].split("$")
        tampered_nonce = ("0" if nonce_hex[0] != "0" else "1") + nonce_hex[1:]
        tampered_bundle = f"{prefix}${salt_hex}${tampered_nonce}${b64_payload}"
        
        with self.assertRaises(ValueError) as ctx:
            aes_decrypt_text(tampered_bundle, pwd)
        self.assertEqual(str(ctx.exception), "Decryption failed: incorrect password or corrupted data.")

    def test_aes_empty_inputs_validation(self):
        with self.assertRaises(ValueError) as ctx:
            aes_encrypt_text("", "Password")
        self.assertIn("Please enter some text.", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            aes_encrypt_text("Hello", "")
        self.assertIn("Please enter a password.", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            aes_decrypt_text("", "Password")
        self.assertIn("Please enter ciphertext to decrypt.", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            aes_decrypt_text("CYBER1$123$456$789", "")
        self.assertIn("Please enter a password.", str(ctx.exception))

    def test_aes_malformed_bundle(self):
        with self.assertRaises(ValueError) as ctx:
            aes_decrypt_text("NOT_A_CYBER_BUNDLE", "Password")
        self.assertIn("Invalid encrypted data format.", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
