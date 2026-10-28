"""
Cyber Cipher - Unit Tests for Classical Cryptography Algorithms
"""

import unittest
from algorithms import (
    caesar_encrypt,
    caesar_decrypt,
    validate_caesar_key,
    vigenere_encrypt,
    vigenere_decrypt,
    rail_fence_encrypt,
    rail_fence_decrypt,
    playfair_encrypt,
    playfair_decrypt,
    generate_playfair_matrix,
    beaufort_encrypt,
    beaufort_decrypt,
    autokey_encrypt,
    autokey_decrypt
)
from cryptanalysis import (
    caesar_brute_force,
    frequency_analysis
)


class TestCaesarCipher(unittest.TestCase):
    """Test suite for Caesar Cipher encryption, decryption, and key validation."""

    def test_caesar_basic_encryption(self):
        result = caesar_encrypt("HELLO WORLD", 3)
        self.assertEqual(result["result"], "KHOOR ZRUOG")

    def test_caesar_basic_decryption(self):
        result = caesar_decrypt("KHOOR ZRUOG", 3)
        self.assertEqual(result["result"], "HELLO WORLD")

    def test_caesar_roundtrip(self):
        plain = "The Quick Brown Fox Jumps Over 13 Lazy Dogs! @#$"
        shift = 7
        encrypted = caesar_encrypt(plain, shift)["result"]
        decrypted = caesar_decrypt(encrypted, shift)["result"]
        self.assertEqual(decrypted, plain)

    def test_caesar_large_shift(self):
        # Shift 29 is equivalent to shift 3 (29 % 26 == 3)
        result = caesar_encrypt("ABC", 29)
        self.assertEqual(result["result"], "DEF")
        dec = caesar_decrypt("DEF", 29)
        self.assertEqual(dec["result"], "ABC")

    def test_caesar_negative_shift(self):
        # Shift -3 is equivalent to shift 23
        result = caesar_encrypt("DEF", -3)
        self.assertEqual(result["result"], "ABC")
        dec = caesar_decrypt("ABC", -3)
        self.assertEqual(dec["result"], "DEF")

    def test_caesar_preserves_case_and_punctuation(self):
        text = "Hello, World! 12345."
        enc = caesar_encrypt(text, 3)
        self.assertEqual(enc["result"], "Khoor, Zruog! 12345.")
        dec = caesar_decrypt(enc["result"], 3)
        self.assertEqual(dec["result"], text)

    def test_caesar_steps(self):
        res = caesar_encrypt("AB", 1, return_steps=True)
        self.assertIn("steps", res)
        self.assertEqual(len(res["steps"]), 2)
        self.assertEqual(res["steps"][0]["original"], "A")
        self.assertEqual(res["steps"][0]["transformed"], "B")

    def test_caesar_invalid_inputs(self):
        with self.assertRaises(ValueError) as ctx:
            caesar_encrypt("", 3)
        self.assertIn("Please enter some text.", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            caesar_encrypt("HELLO", "not_a_number")
        self.assertIn("Key must be a valid number.", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            caesar_encrypt("HELLO", "")
        self.assertIn("Please enter a key.", str(ctx.exception))


class TestCryptanalysisBasics(unittest.TestCase):
    """Test suite for Caesar Brute Force and Frequency Analysis."""

    def test_caesar_brute_force(self):
        ciphertext = "KHOOR ZRUOG"
        attack = caesar_brute_force(ciphertext)
        self.assertEqual(attack["total_shifts_tested"], 25)
        self.assertEqual(len(attack["candidates"]), 25)
        # Shift 3 must recover HELLO WORLD
        shift_3 = [c for c in attack["candidates"] if c["shift"] == 3][0]
        self.assertEqual(shift_3["plaintext"], "HELLO WORLD")

    def test_frequency_analysis(self):
        text = "EEETTA"
        analysis = frequency_analysis(text)
        self.assertEqual(analysis["total_letters"], 6)
        freq_map = {item["letter"]: item["count"] for item in analysis["frequencies"]}
        self.assertEqual(freq_map["E"], 3)
        self.assertEqual(freq_map["T"], 2)
        self.assertEqual(freq_map["A"], 1)
        self.assertEqual(freq_map["Z"], 0)

    def test_cryptanalysis_invalid_inputs(self):
        with self.assertRaises(ValueError):
            caesar_brute_force("")
        with self.assertRaises(ValueError):
            caesar_brute_force("   ")
        with self.assertRaises(ValueError):
            frequency_analysis("")
        with self.assertRaises(ValueError):
            frequency_analysis("12345!@#$ %^&*")


class TestVigenereCipher(unittest.TestCase):
    """Test suite for Vigenère Cipher encryption, decryption, and key validation."""

    def test_vigenere_basic_encryption(self):
        result = vigenere_encrypt("ATTACK", "LEMON")
        self.assertEqual(result["result"], "LXFOPV")

    def test_vigenere_basic_decryption(self):
        result = vigenere_decrypt("LXFOPV", "LEMON")
        self.assertEqual(result["result"], "ATTACK")

    def test_vigenere_roundtrip(self):
        plain = "Defend The East Wall at 0600 Hours! Confirmed?"
        key = "FORTIFICATION"
        enc = vigenere_encrypt(plain, key)["result"]
        dec = vigenere_decrypt(enc, key)["result"]
        self.assertEqual(dec, plain)

    def test_vigenere_preserves_case_and_punctuation(self):
        text = "Hello, World! Classical Cryptography 101."
        key = "KEY"
        enc = vigenere_encrypt(text, key)["result"]
        dec = vigenere_decrypt(enc, key)["result"]
        self.assertEqual(dec, text)
        # H(7)+K(10)=R(17), e(4)+E(4)=i(8), l(11)+Y(24)=j(35%26=9), l(11)+K(10)=v(21), o(14)+E(4)=s(18)
        self.assertTrue(enc.startswith("Rijvs,"))

    def test_vigenere_invalid_keys(self):
        with self.assertRaises(ValueError):
            vigenere_encrypt("HELLO", "")
        with self.assertRaises(ValueError):
            vigenere_encrypt("HELLO", "12345!@#")
        with self.assertRaises(ValueError):
            vigenere_encrypt("", "KEY")


class TestRailFenceCipher(unittest.TestCase):
    """Test suite for Rail Fence Cipher encryption, decryption, and key validation."""

    def test_rail_fence_basic_encryption(self):
        text = "WE ARE DISCOVERED"
        result = rail_fence_encrypt(text, 3)
        self.assertEqual(result["result"], "WRIVDEAEDSOEE  CR")

    def test_rail_fence_basic_decryption(self):
        cipher = "WRIVDEAEDSOEE  CR"
        result = rail_fence_decrypt(cipher, 3)
        self.assertEqual(result["result"], "WE ARE DISCOVERED")

    def test_rail_fence_roundtrip(self):
        for rails in [2, 3, 4, 5, 7]:
            plain = "THE DEFENSE OF THE REALM DEPENDS ON SECRECY! 123"
            enc = rail_fence_encrypt(plain, rails)["result"]
            dec = rail_fence_decrypt(enc, rails)["result"]
            self.assertEqual(dec, plain, f"Failed at {rails} rails")

    def test_rail_fence_invalid_keys(self):
        with self.assertRaises(ValueError) as ctx:
            rail_fence_encrypt("HELLO", 1)
        self.assertIn("Number of rails must be an integer greater than or equal to 2.", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            rail_fence_encrypt("HELLO", "invalid")
        self.assertIn("Key must be a valid number.", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            rail_fence_encrypt("HELLO", "")
        self.assertIn("Please enter a key.", str(ctx.exception))


class TestPlayfairCipher(unittest.TestCase):
    """Test suite for Playfair Cipher matrix generation, digraph pairing, and reversibility."""

    def test_playfair_matrix_generation(self):
        matrix, pos_map = generate_playfair_matrix("MONARCHY")
        self.assertEqual(len(matrix), 5)
        for row in matrix:
            self.assertEqual(len(row), 5)
        # All 25 characters must be unique and contain no 'J'
        flat = [c for row in matrix for c in row]
        self.assertEqual(len(set(flat)), 25)
        self.assertNotIn("J", flat)
        self.assertIn("I", flat)

    def test_playfair_standard_encryption(self):
        # Plaintext "INSTRUMENTS" with filler X -> pairs IN ST RU ME NT SX -> GATLMZCLRQXA
        result = playfair_encrypt("INSTRUMENTS", "MONARCHY")
        self.assertEqual(result["result"], "GATLMZCLRQXA")

    def test_playfair_standard_decryption(self):
        # Decrypting GATLMZCLRQXA should yield INSTRUMENTSX
        result = playfair_decrypt("GATLMZCLRQXA", "MONARCHY")
        self.assertEqual(result["result"], "INSTRUMENTSX")

        # Classical historical variant with Z filler decodes to INSTRUMENTSZ
        historical = playfair_decrypt("GATLMZCLRQTX", "MONARCHY")
        self.assertEqual(historical["result"], "INSTRUMENTSZ")

    def test_playfair_duplicate_letters_handling(self):
        # "BALLOON" should split double L: BA, LX, LO, ON
        enc = playfair_encrypt("BALLOON", "MONARCHY")
        dec = playfair_decrypt(enc["result"], "MONARCHY")
        # Decrypted text will contain the inserted filler X: BALXLOON
        self.assertEqual(dec["result"], "BALXLOON")

    def test_playfair_roundtrip_digraphs(self):
        key = "SECRETKEY"
        plain = "KNOWLEDGE IS POWER"
        enc = playfair_encrypt(plain, key)["result"]
        dec = playfair_decrypt(enc, key)["result"]
        # Recovered text should correspond to prepared clean digraphs
        self.assertTrue(dec.startswith("KNOW"))

    def test_playfair_invalid_inputs(self):
        with self.assertRaises(ValueError):
            playfair_encrypt("", "KEY")
        with self.assertRaises(ValueError):
            playfair_encrypt("HELLO", "")
        with self.assertRaises(ValueError):
            playfair_encrypt("HELLO", "12345!@#")
        with self.assertRaises(ValueError):
            # Odd number of ciphertext chars
            playfair_decrypt("GATLM", "MONARCHY")


class TestBeaufortCipher(unittest.TestCase):
    """Test suite for Beaufort Cipher encryption, decryption, and self-reciprocity."""

    def test_beaufort_basic_encryption(self):
        result = beaufort_encrypt("DEFEND", "KEY")
        self.assertEqual(result["result"], "HATGRV")

    def test_beaufort_basic_decryption(self):
        result = beaufort_decrypt("HATGRV", "KEY")
        self.assertEqual(result["result"], "DEFEND")

    def test_beaufort_self_reciprocal_property(self):
        plain = "The Beaufort Cipher is mathematically self-inverting! 12345."
        key = "CIPHERKEY"
        # Encrypting twice with the same key returns the original message
        c1 = beaufort_encrypt(plain, key)["result"]
        c2 = beaufort_encrypt(c1, key)["result"]
        self.assertEqual(c2, plain)

    def test_beaufort_preserves_case_and_punctuation(self):
        text = "Hello, World! Classical 2026."
        key = "SECRET"
        enc = beaufort_encrypt(text, key)["result"]
        dec = beaufort_decrypt(enc, key)["result"]
        self.assertEqual(dec, text)

    def test_beaufort_invalid_keys(self):
        with self.assertRaises(ValueError):
            beaufort_encrypt("HELLO", "")
        with self.assertRaises(ValueError):
            beaufort_encrypt("HELLO", "12345!@#")
        with self.assertRaises(ValueError):
            beaufort_encrypt("", "KEY")


class TestAutokeyCipher(unittest.TestCase):
    """Test suite for Autokey Cipher extended keystream encryption, decryption, and reversibility."""

    def test_autokey_basic_encryption(self):
        result = autokey_encrypt("ATTACK AT DAWN", "QUEEN")
        self.assertEqual(result["result"], "QNXEPK TM DCGN")

    def test_autokey_basic_decryption(self):
        result = autokey_decrypt("QNXEPK TM DCGN", "QUEEN")
        self.assertEqual(result["result"], "ATTACK AT DAWN")

    def test_autokey_roundtrip(self):
        plain = "Meet at the Secret Headquarters at 2100 Hours! Don't be late."
        key = "VIGENERE"
        enc = autokey_encrypt(plain, key)["result"]
        dec = autokey_decrypt(enc, key)["result"]
        self.assertEqual(dec, plain)

    def test_autokey_preserves_case_and_punctuation(self):
        text = "Hello, World! Classical Cryptography 2026."
        key = "PRIMER"
        enc = autokey_encrypt(text, key)["result"]
        dec = autokey_decrypt(enc, key)["result"]
        self.assertEqual(dec, text)

    def test_autokey_invalid_keys(self):
        with self.assertRaises(ValueError):
            autokey_encrypt("HELLO", "")
        with self.assertRaises(ValueError):
            autokey_encrypt("HELLO", "12345!@#")
        with self.assertRaises(ValueError):
            autokey_encrypt("", "KEY")


class TestAlgorithmsEdgeCasesAndReversibility(unittest.TestCase):
    """Broad verification testing edge cases and roundtrip reversibility for all algorithms."""

    def test_single_character_reversibility(self):
        # Test 1-character input across ciphers
        self.assertEqual(caesar_decrypt(caesar_encrypt("Z", 13)["result"], 13)["result"], "Z")
        self.assertEqual(vigenere_decrypt(vigenere_encrypt("M", "SECRET")["result"], "SECRET")["result"], "M")
        self.assertEqual(rail_fence_decrypt(rail_fence_encrypt("A", 3)["result"], 3)["result"], "A")
        self.assertEqual(beaufort_decrypt(beaufort_encrypt("Q", "KEY")["result"], "KEY")["result"], "Q")
        self.assertEqual(autokey_decrypt(autokey_encrypt("X", "KEY")["result"], "KEY")["result"], "X")

    def test_long_message_roundtrip(self):
        # 2,000 character repeated paragraph with mixed case and symbols
        paragraph = (
            "Cyber Cipher is an educational cryptography laboratory designed to teach "
            "substitution and transposition mechanics. Caesar, Vigenere, Rail Fence, "
            "Playfair, Beaufort, and Autokey ciphers illustrate foundational principles! "
            "Timestamp: 2026-09-18. Special: #$%^&*()[]{}|<>~? "
        ) * 10

        # Caesar
        c_enc = caesar_encrypt(paragraph, 19)["result"]
        self.assertEqual(caesar_decrypt(c_enc, 19)["result"], paragraph)

        # Vigenere
        v_enc = vigenere_encrypt(paragraph, "CRYPTOGRAPHIC")["result"]
        self.assertEqual(vigenere_decrypt(v_enc, "CRYPTOGRAPHIC")["result"], paragraph)

        # Rail Fence
        rf_enc = rail_fence_encrypt(paragraph, 6)["result"]
        self.assertEqual(rail_fence_decrypt(rf_enc, 6)["result"], paragraph)

        # Beaufort
        b_enc = beaufort_encrypt(paragraph, "CYBERSECURITY")["result"]
        self.assertEqual(beaufort_decrypt(b_enc, "CYBERSECURITY")["result"], paragraph)

        # Autokey
        a_enc = autokey_encrypt(paragraph, "DEFENDER")["result"]
        self.assertEqual(autokey_decrypt(a_enc, "DEFENDER")["result"], paragraph)


if __name__ == "__main__":
    unittest.main()






