"""
Cyber Cipher - Cryptanalysis & Attack Lab Module
Provides educational attacks and cryptanalytic tools for classical ciphers.
"""

from typing import Dict, Any, List
from algorithms import caesar_decrypt

# Standard English letter frequencies (approximate percentages)
ENGLISH_LETTER_FREQUENCIES: Dict[str, float] = {
    'E': 12.02, 'T': 9.10, 'A': 8.12, 'O': 7.68, 'I': 7.31,
    'N': 6.95, 'S': 6.28, 'R': 6.02, 'H': 5.92, 'D': 4.32,
    'L': 3.98, 'U': 2.88, 'C': 2.71, 'M': 2.61, 'F': 2.30,
    'Y': 2.11, 'W': 2.09, 'G': 2.03, 'P': 1.82, 'B': 1.49,
    'V': 1.11, 'K': 0.69, 'X': 0.17, 'Q': 0.11, 'J': 0.10,
    'Z': 0.07
}


def caesar_brute_force(ciphertext: str) -> Dict[str, Any]:
    """
    Performs an educational brute-force keyspace exhaustion attack on Caesar ciphertext.
    Tests all 25 possible non-trivial shifts (1 to 25).
    
    Does NOT automatically decide which result is correct, allowing the student
    to inspect candidates and confirm readability.
    """
    if not ciphertext or not ciphertext.strip():
        raise ValueError("Please enter ciphertext to attack.")
        
    candidates: List[Dict[str, Any]] = []
    
    for shift in range(1, 26):
        decrypted = caesar_decrypt(ciphertext, shift, return_steps=False)
        candidates.append({
            'shift': shift,
            'plaintext': decrypted['result']
        })
        
    return {
        'total_shifts_tested': 25,
        'keyspace_size': 26,
        'candidates': candidates,
        'explanation': (
            "Brute force works well against Caesar Cipher because the keyspace contains "
            "only 26 possible shifts (25 non-trivial shifts). A human or automated dictionary "
            "can inspect every candidate in milliseconds."
        )
    }


def frequency_analysis(text: str) -> Dict[str, Any]:
    """
    Calculates letter frequency distribution for a given text.
    Compares the observed letter frequency against standard English language benchmarks.
    """
    if not text or not text.strip():
        raise ValueError("Please enter text for frequency analysis.")
        
    # Count uppercase letters only
    counts: Dict[str, int] = {chr(c): 0 for c in range(ord('A'), ord('Z') + 1)}
    total_letters = 0
    
    for char in text.upper():
        if 'A' <= char <= 'Z':
            counts[char] += 1
            total_letters += 1
            
    if total_letters == 0:
        raise ValueError("Input text must contain at least one alphabetic letter for frequency analysis.")
        
    frequencies: List[Dict[str, Any]] = []
    
    for char in sorted(counts.keys()):
        count = counts[char]
        percentage = round((count / total_letters * 100), 2) if total_letters > 0 else 0.0
        english_expected = ENGLISH_LETTER_FREQUENCIES.get(char, 0.0)
        frequencies.append({
            'letter': char,
            'count': count,
            'percentage': percentage,
            'expected_english': english_expected
        })
        
    # Sorted by frequency descending
    sorted_by_frequency = sorted(frequencies, key=lambda x: x['count'], reverse=True)
    
    return {
        'total_letters': total_letters,
        'frequencies': frequencies,
        'sorted_frequencies': sorted_by_frequency,
        'explanation': (
            "Frequency analysis exploits the non-uniform distribution of letters in human language. "
            "In English, letters like 'E', 'T', and 'A' occur much more frequently than 'Q', 'X', or 'Z'. "
            "In monoalphabetic substitution ciphers like Caesar, the frequencies are simply shifted, "
            "making the substitution alphabet readily identifiable. In polyalphabetic ciphers, the frequencies "
            "are flattened, making simple frequency analysis less direct."
        )
    }
