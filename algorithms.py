"""
Cyber Cipher - Classical Cryptography Algorithms Module
Manual implementations of classical encryption and decryption algorithms.
Educational tool designed for teaching cryptographic concepts.
"""

from typing import Dict, Any, Tuple, List, Optional


CIPHER_METADATA: Dict[str, Dict[str, Any]] = {
    'caesar': {
        'name': 'Caesar Cipher',
        'type': 'Monoalphabetic Substitution Cipher',
        'history': 'Named after Julius Caesar, who used it with a shift of 3 to protect military messages around 58 BC.',
        'how_it_works': 'Each letter in the plaintext is shifted forward or backward by a fixed number of positions in the alphabet (modulo 26). Spaces and punctuation remain unchanged.',
        'key_requirements': 'A single integer representing the shift amount (can be positive, negative, or greater than 26).',
        'strengths': 'Extremely simple to understand and implement; computationally lightweight.',
        'weaknesses': 'Extremely weak by modern standards. With only 25 non-trivial shifts, it is trivial to break via brute-force attack or frequency analysis.',
        'example': 'Plaintext: "HELLO WORLD", Key: 3 -> Ciphertext: "KHOOR ZRUOG"'
    },
    'vigenere': {
        'name': 'Vigenère Cipher',
        'type': 'Polyalphabetic Substitution Cipher',
        'history': "First described by Giovan Battista Bellaso in 1553 and later misattributed to Blaise de Vigenère. Famously called 'le chiffre indéchiffrable' for three centuries.",
        'how_it_works': 'Uses a repeated keyword to shift successive plaintext letters by different amounts, cycling through a series of Caesar shifts. Non-alphabetic characters are preserved without advancing the key.',
        'key_requirements': 'An alphabetic word or string of letters (e.g., "SECRET").',
        'strengths': 'Masks single-letter frequency spikes, making simple frequency analysis ineffective.',
        'weaknesses': 'Vulnerable to Kasiski examination and index of coincidence tests once the keyword length is determined.',
        'example': 'Plaintext: "ATTACK", Key: "LEMON" -> Ciphertext: "LXFOPV"'
    },
    'rail_fence': {
        'name': 'Rail Fence Cipher',
        'type': 'Transposition Cipher',
        'history': 'An ancient transposition technique related to the Greek scytale, used widely during the American Civil War for field communications.',
        'how_it_works': 'Plaintext characters are written downwards and upwards along imaginary parallel "rails" in a zigzag pattern, then read off horizontally row by row.',
        'key_requirements': 'An integer >= 2 representing the number of vertical rails (rows).',
        'strengths': 'Permutes character positions while preserving exact letter identities and frequencies.',
        'weaknesses': 'Easily broken with anagramming or known plaintext attacks; keyspace is restricted to reasonable rail counts.',
        'example': 'Plaintext: "WE ARE DISCOVERED", Rails: 3 -> Ciphertext: "WECRUERDSOEESAV"'
    },
    'playfair': {
        'name': 'Playfair Cipher',
        'type': 'Polygraphic Substitution Cipher',
        'history': 'Invented by Charles Wheatstone in 1854 but popularized by Lord Playfair. Used by British forces in the Boer War and WWI.',
        'how_it_works': 'Encrypts pairs of letters (digraphs) across a 5x5 key matrix (merging I and J). Digraphs in the same row shift right; same column shift down; opposite corners swap columns.',
        'key_requirements': 'An alphabetic keyword without symbols. Double letters in pairs are separated by filler "X".',
        'strengths': 'Flattens single-letter frequency distribution across 600 possible digraph pairs instead of 26 single letters.',
        'weaknesses': 'Vulnerable to digraph frequency analysis; matrix structure can be reconstructed with adequate ciphertext.',
        'example': 'Plaintext: "INSTRUMENTS", Key: "MONARCHY" -> Ciphertext: "GATLMZCLRQXA" (filler X)'
    },
    'beaufort': {
        'name': 'Beaufort Cipher',
        'type': 'Reciprocal Polyalphabetic Substitution Cipher',
        'history': 'Invented by Sir Francis Beaufort in 1857. An elegant variant of Vigenère with the unique mathematical property of self-reciprocity.',
        'how_it_works': 'Applies backward subtraction: Cipher = (Key - Plaintext) mod 26. Because (Key - (Key - Plaintext)) = Plaintext, encryption and decryption are executed with the exact same operation.',
        'key_requirements': 'An alphabetic keyword (letters only).',
        'strengths': 'Self-reciprocal cipher; identical machinery or algorithm performs both encryption and decryption.',
        'weaknesses': 'Shares Vigenère vulnerabilities: vulnerable to Kasiski examination and periodic index of coincidence tests once key length is found.',
        'example': 'Plaintext: "DEFEND", Key: "KEY" -> Ciphertext: "HATGRV"'
    },
    'autokey': {
        'name': 'Autokey Cipher',
        'type': 'Extended Keystream Polyalphabetic Cipher',
        'history': 'Invented by Blaise de Vigenère in 1586 to overcome the repeating key vulnerabilities of his earlier ciphers.',
        'how_it_works': 'Begins encryption with a short primer key, and subsequently extends the keystream by appending the message plaintext itself. Decryption cascades letter-by-letter as plaintext is revealed.',
        'key_requirements': 'An initial primer keyword (alphabetic characters only).',
        'strengths': 'Eliminates fixed periodic repetition of the key, preventing basic Kasiski examination.',
        'weaknesses': 'Since the keystream contains natural language plaintext letters, dictionary attacks and known-plaintext fragments can unravel the entire text.',
        'example': 'Plaintext: "ATTACK AT DAWN", Key: "QUEEN" -> Keystream: "QUEENATTACKAT"'
    }
}


def get_cipher_info(cipher_key: str) -> Optional[Dict[str, Any]]:
    """Retrieve metadata and educational information for a given cipher."""
    return CIPHER_METADATA.get(cipher_key.lower())


def validate_caesar_key(key: Any) -> int:
    """
    Validates that the Caesar cipher key is a valid integer.
    Raises ValueError if invalid.
    """
    if key is None or (isinstance(key, str) and not key.strip()):
        raise ValueError("Please enter a key.")
    try:
        shift_val = int(str(key).strip())
        return shift_val
    except ValueError:
        raise ValueError("Key must be a valid number.")


def caesar_encrypt(text: str, shift: Any, return_steps: bool = False) -> Dict[str, Any]:
    """
    Encrypts plaintext using the Caesar Cipher.
    
    Parameters:
        text (str): The message to encrypt.
        shift (int/str): The shift amount.
        return_steps (bool): Whether to return educational step-by-step transformations.
        
    Returns:
        dict: {'result': str, 'steps': list (optional), 'shift': int}
    """
    if not text:
        raise ValueError("Please enter some text.")
        
    shift_val = validate_caesar_key(shift)
    normalized_shift = shift_val % 26
    
    result_chars = []
    steps = []
    
    for char in text:
        if 'A' <= char <= 'Z':
            orig_pos = ord(char) - ord('A')
            new_pos = (orig_pos + normalized_shift) % 26
            new_char = chr(ord('A') + new_pos)
            result_chars.append(new_char)
            if return_steps:
                steps.append({
                    'original': char,
                    'transformed': new_char,
                    'orig_pos': orig_pos,
                    'new_pos': new_pos,
                    'type': 'uppercase',
                    'detail': f"'{char}' (pos {orig_pos}) + shift {shift_val} (mod 26 = {normalized_shift}) -> '{new_char}' (pos {new_pos})"
                })
        elif 'a' <= char <= 'z':
            orig_pos = ord(char) - ord('a')
            new_pos = (orig_pos + normalized_shift) % 26
            new_char = chr(ord('a') + new_pos)
            result_chars.append(new_char)
            if return_steps:
                steps.append({
                    'original': char,
                    'transformed': new_char,
                    'orig_pos': orig_pos,
                    'new_pos': new_pos,
                    'type': 'lowercase',
                    'detail': f"'{char}' (pos {orig_pos}) + shift {shift_val} (mod 26 = {normalized_shift}) -> '{new_char}' (pos {new_pos})"
                })
        else:
            result_chars.append(char)
            if return_steps:
                steps.append({
                    'original': char,
                    'transformed': char,
                    'type': 'preserved',
                    'detail': f"Character '{char}' is not alphabetic and is preserved unchanged."
                })
                
    ciphertext = ''.join(result_chars)
    response = {
        'result': ciphertext,
        'shift': shift_val,
        'normalized_shift': normalized_shift
    }
    if return_steps:
        response['steps'] = steps
        response['summary'] = f"Caesar encrypted {len(text)} characters using shift {shift_val} (normalized: {normalized_shift})."
        
    return response


def caesar_decrypt(text: str, shift: Any, return_steps: bool = False) -> Dict[str, Any]:
    """
    Decrypts ciphertext using the Caesar Cipher.
    Decryption is simply an encryption with shift = -shift.
    """
    if not text:
        raise ValueError("Please enter some text.")
        
    shift_val = validate_caesar_key(shift)
    normalized_shift = (-shift_val) % 26
    
    result_chars = []
    steps = []
    
    for char in text:
        if 'A' <= char <= 'Z':
            orig_pos = ord(char) - ord('A')
            new_pos = (orig_pos + normalized_shift) % 26
            new_char = chr(ord('A') + new_pos)
            result_chars.append(new_char)
            if return_steps:
                steps.append({
                    'original': char,
                    'transformed': new_char,
                    'orig_pos': orig_pos,
                    'new_pos': new_pos,
                    'type': 'uppercase',
                    'detail': f"'{char}' (pos {orig_pos}) - shift {shift_val} (mod 26 = {normalized_shift}) -> '{new_char}' (pos {new_pos})"
                })
        elif 'a' <= char <= 'z':
            orig_pos = ord(char) - ord('a')
            new_pos = (orig_pos + normalized_shift) % 26
            new_char = chr(ord('a') + new_pos)
            result_chars.append(new_char)
            if return_steps:
                steps.append({
                    'original': char,
                    'transformed': new_char,
                    'orig_pos': orig_pos,
                    'new_pos': new_pos,
                    'type': 'lowercase',
                    'detail': f"'{char}' (pos {orig_pos}) - shift {shift_val} (mod 26 = {normalized_shift}) -> '{new_char}' (pos {new_pos})"
                })
        else:
            result_chars.append(char)
            if return_steps:
                steps.append({
                    'original': char,
                    'transformed': char,
                    'type': 'preserved',
                    'detail': f"Character '{char}' is not alphabetic and is preserved unchanged."
                })
                
    plaintext = ''.join(result_chars)
    response = {
        'result': plaintext,
        'shift': shift_val,
        'normalized_shift': normalized_shift
    }
    if return_steps:
        response['steps'] = steps
        response['summary'] = f"Caesar decrypted {len(text)} characters reversing shift {shift_val} (backward shift: {normalized_shift})."
        
    return response


def validate_vigenere_key(key: Any) -> str:
    """
    Validates that the Vigenère key contains at least one alphabetic letter.
    Raises ValueError with a helpful message if empty or invalid.
    """
    if key is None or (isinstance(key, str) and not key.strip()):
        raise ValueError("Please enter a key.")
    clean_key = ''.join([c.upper() for c in str(key) if c.isalpha()])
    if not clean_key:
        raise ValueError("Key must contain at least one alphabetic letter.")
    return clean_key


def vigenere_encrypt(text: str, key: Any, return_steps: bool = False) -> Dict[str, Any]:
    """
    Encrypts plaintext using the Vigenère Cipher.
    
    Parameters:
        text (str): Plaintext message.
        key (str): Keyword.
        return_steps (bool): Whether to include educational breakdown.
        
    Returns:
        dict: {'result': str, 'key': str, 'steps': list (optional)}
    """
    if not text:
        raise ValueError("Please enter some text.")
        
    clean_key = validate_vigenere_key(key)
    key_len = len(clean_key)
    
    result_chars = []
    steps = []
    key_idx = 0
    
    for char in text:
        if 'A' <= char <= 'Z':
            k_char = clean_key[key_idx % key_len]
            shift = ord(k_char) - ord('A')
            orig_pos = ord(char) - ord('A')
            new_pos = (orig_pos + shift) % 26
            new_char = chr(ord('A') + new_pos)
            result_chars.append(new_char)
            if return_steps:
                steps.append({
                    'original': char,
                    'transformed': new_char,
                    'key_char': k_char,
                    'key_index': key_idx % key_len,
                    'shift': shift,
                    'detail': f"'{char}' (pos {orig_pos}) + key '{k_char}' (shift +{shift}) -> '{new_char}' (pos {new_pos})"
                })
            key_idx += 1
        elif 'a' <= char <= 'z':
            k_char = clean_key[key_idx % key_len]
            shift = ord(k_char) - ord('A')
            orig_pos = ord(char) - ord('a')
            new_pos = (orig_pos + shift) % 26
            new_char = chr(ord('a') + new_pos)
            result_chars.append(new_char)
            if return_steps:
                steps.append({
                    'original': char,
                    'transformed': new_char,
                    'key_char': k_char,
                    'key_index': key_idx % key_len,
                    'shift': shift,
                    'detail': f"'{char}' (pos {orig_pos}) + key '{k_char}' (shift +{shift}) -> '{new_char}' (pos {new_pos})"
                })
            key_idx += 1
        else:
            result_chars.append(char)
            if return_steps:
                steps.append({
                    'original': char,
                    'transformed': char,
                    'detail': f"Non-alphabetic '{char}' preserved; keystream does not advance."
                })
                
    ciphertext = ''.join(result_chars)
    response = {
        'result': ciphertext,
        'key': clean_key
    }
    if return_steps:
        response['steps'] = steps
        response['summary'] = f"Vigenère encrypted using repeating key '{clean_key}' ({key_len} letters) across {key_idx} alphabetic characters."
    return response


def vigenere_decrypt(text: str, key: Any, return_steps: bool = False) -> Dict[str, Any]:
    """
    Decrypts ciphertext using the Vigenère Cipher.
    """
    if not text:
        raise ValueError("Please enter some text.")
        
    clean_key = validate_vigenere_key(key)
    key_len = len(clean_key)
    
    result_chars = []
    steps = []
    key_idx = 0
    
    for char in text:
        if 'A' <= char <= 'Z':
            k_char = clean_key[key_idx % key_len]
            shift = ord(k_char) - ord('A')
            orig_pos = ord(char) - ord('A')
            new_pos = (orig_pos - shift) % 26
            new_char = chr(ord('A') + new_pos)
            result_chars.append(new_char)
            if return_steps:
                steps.append({
                    'original': char,
                    'transformed': new_char,
                    'key_char': k_char,
                    'key_index': key_idx % key_len,
                    'shift': shift,
                    'detail': f"'{char}' (pos {orig_pos}) - key '{k_char}' (shift -{shift}) -> '{new_char}' (pos {new_pos})"
                })
            key_idx += 1
        elif 'a' <= char <= 'z':
            k_char = clean_key[key_idx % key_len]
            shift = ord(k_char) - ord('A')
            orig_pos = ord(char) - ord('a')
            new_pos = (orig_pos - shift) % 26
            new_char = chr(ord('a') + new_pos)
            result_chars.append(new_char)
            if return_steps:
                steps.append({
                    'original': char,
                    'transformed': new_char,
                    'key_char': k_char,
                    'key_index': key_idx % key_len,
                    'shift': shift,
                    'detail': f"'{char}' (pos {orig_pos}) - key '{k_char}' (shift -{shift}) -> '{new_char}' (pos {new_pos})"
                })
            key_idx += 1
        else:
            result_chars.append(char)
            if return_steps:
                steps.append({
                    'original': char,
                    'transformed': char,
                    'detail': f"Non-alphabetic '{char}' preserved; keystream does not advance."
                })
                
    plaintext = ''.join(result_chars)
    response = {
        'result': plaintext,
        'key': clean_key
    }
    if return_steps:
        response['steps'] = steps
        response['summary'] = f"Vigenère decrypted using repeating key '{clean_key}' ({key_len} letters) across {key_idx} alphabetic characters."
    return response


def validate_rail_fence_key(key: Any) -> int:
    """
    Validates that the rail count is an integer >= 2.
    Raises ValueError with descriptive guidance otherwise.
    """
    if key is None or (isinstance(key, str) and not key.strip()):
        raise ValueError("Please enter a key.")
    try:
        rails = int(str(key).strip())
    except ValueError:
        raise ValueError("Key must be a valid number.")
        
    if rails < 2:
        raise ValueError("Number of rails must be an integer greater than or equal to 2.")
    return rails


def rail_fence_encrypt(text: str, rails: Any, return_steps: bool = False) -> Dict[str, Any]:
    """
    Encrypts text using the Rail Fence (Zigzag) Transposition Cipher.
    
    Parameters:
        text (str): Input message.
        rails (int/str): Number of rails (rows) >= 2.
        return_steps (bool): Whether to include step-by-step zigzag layout.
        
    Returns:
        dict: {'result': str, 'rails': int, 'steps': list (optional)}
    """
    if not text:
        raise ValueError("Please enter some text.")
        
    num_rails = validate_rail_fence_key(rails)
    n = len(text)
    
    if num_rails >= n or num_rails == 1:
        # Trivial case: all text fits on one rail or 1 char per rail
        response = {
            'result': text,
            'rails': num_rails
        }
        if return_steps:
            response['steps'] = [{'original': c, 'transformed': c, 'detail': f"Text length ({n}) <= rails ({num_rails}); text remains unchanged."} for c in text]
            response['summary'] = f"Rail Fence transposition: text length ({n}) <= rails ({num_rails}), no transposition needed."
        return response
        
    cycle = 2 * (num_rails - 1)
    fence = [[] for _ in range(num_rails)]
    steps = []
    
    for i, char in enumerate(text):
        pos_in_cycle = i % cycle
        row = pos_in_cycle if pos_in_cycle < num_rails else cycle - pos_in_cycle
        fence[row].append((i, char))
        
        if return_steps:
            steps.append({
                'original': char,
                'transformed': char,
                'index': i,
                'rail': row + 1,
                'detail': f"Character '{char}' (index {i}) placed on Rail {row + 1} of {num_rails}."
            })
            
    # Read rows sequentially
    ciphertext_chars = []
    for r in range(num_rails):
        for orig_idx, char in fence[r]:
            ciphertext_chars.append(char)
            
    ciphertext = ''.join(ciphertext_chars)
    response = {
        'result': ciphertext,
        'rails': num_rails
    }
    if return_steps:
        response['steps'] = steps
        response['summary'] = f"Rail Fence transposition encrypted {n} characters across {num_rails} rails in a zigzag pattern."
    return response


def rail_fence_decrypt(text: str, rails: Any, return_steps: bool = False) -> Dict[str, Any]:
    """
    Decrypts ciphertext using the Rail Fence Transposition Cipher.
    """
    if not text:
        raise ValueError("Please enter some text.")
        
    num_rails = validate_rail_fence_key(rails)
    n = len(text)
    
    if num_rails >= n or num_rails == 1:
        response = {
            'result': text,
            'rails': num_rails
        }
        if return_steps:
            response['steps'] = [{'original': c, 'transformed': c, 'detail': "No transposition needed."} for c in text]
            response['summary'] = f"Rail Fence decrypted {n} characters without transposition."
        return response
        
    cycle = 2 * (num_rails - 1)
    
    # Determine the row index for each character position in the original plaintext
    row_assignments = []
    row_counts = [0] * num_rails
    for i in range(n):
        pos_in_cycle = i % cycle
        row = pos_in_cycle if pos_in_cycle < num_rails else cycle - pos_in_cycle
        row_assignments.append(row)
        row_counts[row] += 1
        
    # Split the ciphertext into chunks for each row
    row_chars = []
    cursor = 0
    for r in range(num_rails):
        count = row_counts[r]
        row_chars.append(list(text[cursor:cursor + count]))
        cursor += count
        
    # Reconstruct original plaintext by traversing rows in zigzag order
    row_ptrs = [0] * num_rails
    plaintext_chars = []
    steps = []
    
    for i, row in enumerate(row_assignments):
        char = row_chars[row][row_ptrs[row]]
        row_ptrs[row] += 1
        plaintext_chars.append(char)
        if return_steps:
            steps.append({
                'original': char,
                'transformed': char,
                'index': i,
                'rail': row + 1,
                'detail': f"Character '{char}' recovered from Rail {row + 1} at original sequence position {i}."
            })
            
    plaintext = ''.join(plaintext_chars)
    response = {
        'result': plaintext,
        'rails': num_rails
    }
    if return_steps:
        response['steps'] = steps
        response['summary'] = f"Rail Fence transposition decrypted {n} characters by reconstructing the {num_rails}-rail zigzag sequence."
    return response


def validate_playfair_key(key: Any) -> str:
    """
    Validates that the Playfair key contains at least one alphabetic letter.
    """
    if key is None or (isinstance(key, str) and not key.strip()):
        raise ValueError("Please enter a key.")
    clean_key = ''.join([c.upper() for c in str(key) if c.isalpha()])
    if not clean_key:
        raise ValueError("Key must contain at least one alphabetic letter.")
    return clean_key


def generate_playfair_matrix(key: str) -> Tuple[List[List[str]], Dict[str, Tuple[int, int]]]:
    """
    Generates the 5x5 Playfair matrix using the key.
    Merges 'I' and 'J' (all 'J's are converted to 'I's).
    """
    clean_key = validate_playfair_key(key).replace('J', 'I')
    
    seen = set()
    key_chars = []
    for c in clean_key:
        if c not in seen:
            seen.add(c)
            key_chars.append(c)
            
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # 25 letters, J omitted
    for c in alphabet:
        if c not in seen:
            seen.add(c)
            key_chars.append(c)
            
    matrix = [key_chars[i * 5:(i + 1) * 5] for i in range(5)]
    pos_map = {}
    for r in range(5):
        for c in range(5):
            pos_map[matrix[r][c]] = (r, c)
            
    return matrix, pos_map


def prepare_playfair_text(text: str) -> List[Tuple[str, str]]:
    """
    Prepares plaintext into digraph pairs for Playfair encryption:
    - Uppercase, removes non-alphabetic characters.
    - Replaces 'J' with 'I'.
    - Inserts filler 'X' (or 'Q' if character is 'X') between identical letters in a pair.
    - Appends trailing filler if the sequence length is odd.
    """
    clean = [c.upper().replace('J', 'I') for c in text if c.isalpha()]
    if not clean:
        raise ValueError("Please enter text containing at least one alphabetic character.")
        
    digraphs = []
    i = 0
    while i < len(clean):
        c1 = clean[i]
        if i + 1 < len(clean):
            c2 = clean[i + 1]
            if c1 == c2:
                filler = 'Q' if c1 == 'X' else 'X'
                digraphs.append((c1, filler))
                i += 1
            else:
                digraphs.append((c1, c2))
                i += 2
        else:
            filler = 'Q' if c1 == 'X' else 'X'
            digraphs.append((c1, filler))
            i += 1
            
    return digraphs


def playfair_encrypt(text: str, key: Any, return_steps: bool = False) -> Dict[str, Any]:
    """
    Encrypts plaintext using the Playfair Cipher.
    
    Parameters:
        text (str): Message to encrypt.
        key (str): Keyword.
        return_steps (bool): Whether to include educational digraph steps.
        
    Returns:
        dict: {'result': str, 'matrix': list, 'steps': list (optional)}
    """
    if not text:
        raise ValueError("Please enter some text.")
        
    matrix, pos_map = generate_playfair_matrix(str(key))
    digraphs = prepare_playfair_text(text)
    
    result_chars = []
    steps = []
    
    for idx, (c1, c2) in enumerate(digraphs):
        r1, c1_col = pos_map[c1]
        r2, c2_col = pos_map[c2]
        
        if r1 == r2:
            # Same row: shift right with wrap
            enc1 = matrix[r1][(c1_col + 1) % 5]
            enc2 = matrix[r2][(c2_col + 1) % 5]
            rule = "Same Row (shift right)"
        elif c1_col == c2_col:
            # Same column: shift down with wrap
            enc1 = matrix[(r1 + 1) % 5][c1_col]
            enc2 = matrix[(r2 + 1) % 5][c2_col]
            rule = "Same Column (shift down)"
        else:
            # Rectangle: swap columns
            enc1 = matrix[r1][c2_col]
            enc2 = matrix[r2][c1_col]
            rule = "Rectangle (swap columns)"
            
        result_chars.extend([enc1, enc2])
        
        if return_steps:
            steps.append({
                'original': f"{c1}{c2}",
                'transformed': f"{enc1}{enc2}",
                'rule': rule,
                'pair_index': idx + 1,
                'detail': f"Digraph '{c1}{c2}' [({r1},{c1_col}) and ({r2},{c2_col})] -> '{enc1}{enc2}' using rule: {rule}."
            })
            
    ciphertext = ''.join(result_chars)
    response = {
        'result': ciphertext,
        'matrix': matrix
    }
    if return_steps:
        response['steps'] = steps
        matrix_str = " | ".join(["".join(row) for row in matrix])
        response['summary'] = f"Playfair encrypted {len(digraphs)} digraphs using 5x5 matrix [{matrix_str}]."
    return response


def playfair_decrypt(text: str, key: Any, return_steps: bool = False) -> Dict[str, Any]:
    """
    Decrypts ciphertext using the Playfair Cipher.
    """
    if not text:
        raise ValueError("Please enter some text.")
        
    matrix, pos_map = generate_playfair_matrix(str(key))
    clean = [c.upper().replace('J', 'I') for c in text if c.isalpha()]
    
    if not clean:
        raise ValueError("Please enter text containing at least one alphabetic character.")
        
    if len(clean) % 2 != 0:
        raise ValueError("Playfair ciphertext must contain an even number of alphabetic characters.")
        
    result_chars = []
    steps = []
    
    for i in range(0, len(clean), 2):
        c1 = clean[i]
        c2 = clean[i + 1]
        r1, c1_col = pos_map[c1]
        r2, c2_col = pos_map[c2]
        
        if r1 == r2:
            # Same row: shift left with wrap
            dec1 = matrix[r1][(c1_col - 1) % 5]
            dec2 = matrix[r2][(c2_col - 1) % 5]
            rule = "Same Row (shift left)"
        elif c1_col == c2_col:
            # Same column: shift up with wrap
            dec1 = matrix[(r1 - 1) % 5][c1_col]
            dec2 = matrix[(r2 - 1) % 5][c2_col]
            rule = "Same Column (shift up)"
        else:
            # Rectangle: swap columns
            dec1 = matrix[r1][c2_col]
            dec2 = matrix[r2][c1_col]
            rule = "Rectangle (swap columns)"
            
        result_chars.extend([dec1, dec2])
        
        if return_steps:
            steps.append({
                'original': f"{c1}{c2}",
                'transformed': f"{dec1}{dec2}",
                'rule': rule,
                'pair_index': (i // 2) + 1,
                'detail': f"Digraph '{c1}{c2}' reversed to '{dec1}{dec2}' using rule: {rule}."
            })
            
    plaintext = ''.join(result_chars)
    response = {
        'result': plaintext,
        'matrix': matrix
    }
    if return_steps:
        response['steps'] = steps
        matrix_str = " | ".join(["".join(row) for row in matrix])
        response['summary'] = f"Playfair decrypted {len(clean) // 2} digraphs using 5x5 matrix [{matrix_str}]."
    return response


def validate_beaufort_key(key: Any) -> str:
    """
    Validates that the Beaufort key contains at least one alphabetic letter.
    """
    if key is None or (isinstance(key, str) and not key.strip()):
        raise ValueError("Please enter a key.")
    clean_key = ''.join([c.upper() for c in str(key) if c.isalpha()])
    if not clean_key:
        raise ValueError("Key must contain at least one alphabetic letter.")
    return clean_key


def _beaufort_transform(text: str, key: Any, is_decrypt: bool = False, return_steps: bool = False) -> Dict[str, Any]:
    """
    Internal reciprocal transformation for Beaufort cipher: C = (K - P) mod 26.
    Identical for both encryption and decryption.
    """
    if not text:
        raise ValueError("Please enter some text.")
        
    clean_key = validate_beaufort_key(key)
    key_len = len(clean_key)
    
    result_chars = []
    steps = []
    key_idx = 0
    op_label = "Decryption" if is_decrypt else "Encryption"
    
    for char in text:
        if 'A' <= char <= 'Z':
            k_char = clean_key[key_idx % key_len]
            k_val = ord(k_char) - ord('A')
            p_val = ord(char) - ord('A')
            c_val = (k_val - p_val) % 26
            new_char = chr(ord('A') + c_val)
            result_chars.append(new_char)
            if return_steps:
                steps.append({
                    'original': char,
                    'transformed': new_char,
                    'key_char': k_char,
                    'key_index': key_idx % key_len,
                    'detail': f"({k_char}={k_val} - {char}={p_val}) mod 26 = {c_val} -> '{new_char}'"
                })
            key_idx += 1
        elif 'a' <= char <= 'z':
            k_char = clean_key[key_idx % key_len]
            k_val = ord(k_char) - ord('A')
            p_val = ord(char) - ord('a')
            c_val = (k_val - p_val) % 26
            new_char = chr(ord('a') + c_val)
            result_chars.append(new_char)
            if return_steps:
                steps.append({
                    'original': char,
                    'transformed': new_char,
                    'key_char': k_char,
                    'key_index': key_idx % key_len,
                    'detail': f"({k_char}={k_val} - {char}={p_val}) mod 26 = {c_val} -> '{new_char}'"
                })
            key_idx += 1
        else:
            result_chars.append(char)
            if return_steps:
                steps.append({
                    'original': char,
                    'transformed': char,
                    'detail': f"Non-alphabetic '{char}' preserved; key does not advance."
                })
                
    result_text = ''.join(result_chars)
    response = {
        'result': result_text,
        'key': clean_key
    }
    if return_steps:
        response['steps'] = steps
        response['summary'] = f"Beaufort {op_label.lower()} applied reciprocal formula C = (K - P) mod 26 using key '{clean_key}' ({key_len} letters)."
    return response


def beaufort_encrypt(text: str, key: Any, return_steps: bool = False) -> Dict[str, Any]:
    """Encrypts plaintext using the Beaufort Cipher."""
    return _beaufort_transform(text, key, is_decrypt=False, return_steps=return_steps)


def beaufort_decrypt(text: str, key: Any, return_steps: bool = False) -> Dict[str, Any]:
    """Decrypts ciphertext using the Beaufort Cipher."""
    return _beaufort_transform(text, key, is_decrypt=True, return_steps=return_steps)


def validate_autokey_key(key: Any) -> str:
    """
    Validates that the Autokey primer key contains at least one alphabetic letter.
    """
    if key is None or (isinstance(key, str) and not key.strip()):
        raise ValueError("Please enter a key.")
    clean_key = ''.join([c.upper() for c in str(key) if c.isalpha()])
    if not clean_key:
        raise ValueError("Key must contain at least one alphabetic letter.")
    return clean_key


def autokey_encrypt(text: str, key: Any, return_steps: bool = False) -> Dict[str, Any]:
    """
    Encrypts plaintext using the Autokey Cipher.
    Keystream is formed by primer key + plaintext characters.
    """
    if not text:
        raise ValueError("Please enter some text.")
        
    primer = validate_autokey_key(key)
    plain_letters = [c.upper() for c in text if c.isalpha()]
    
    if not plain_letters:
        response = {'result': text, 'key': primer}
        if return_steps:
            response['steps'] = []
            response['summary'] = "No alphabetic letters found in text."
        return response
        
    keystream = list(primer) + plain_letters[:max(0, len(plain_letters) - len(primer))]
    
    result_chars = []
    steps = []
    k_idx = 0
    
    for char in text:
        if 'A' <= char <= 'Z':
            k_char = keystream[k_idx]
            shift = ord(k_char) - ord('A')
            orig_pos = ord(char) - ord('A')
            new_pos = (orig_pos + shift) % 26
            new_char = chr(ord('A') + new_pos)
            result_chars.append(new_char)
            if return_steps:
                source = "primer key" if k_idx < len(primer) else f"plaintext letter '{k_char}'"
                steps.append({
                    'original': char,
                    'transformed': new_char,
                    'key_char': k_char,
                    'key_index': k_idx,
                    'shift': shift,
                    'detail': f"'{char}' (pos {orig_pos}) + key '{k_char}' from {source} (shift +{shift}) -> '{new_char}' (pos {new_pos})"
                })
            k_idx += 1
        elif 'a' <= char <= 'z':
            k_char = keystream[k_idx]
            shift = ord(k_char) - ord('A')
            orig_pos = ord(char) - ord('a')
            new_pos = (orig_pos + shift) % 26
            new_char = chr(ord('a') + new_pos)
            result_chars.append(new_char)
            if return_steps:
                source = "primer key" if k_idx < len(primer) else f"plaintext letter '{k_char}'"
                steps.append({
                    'original': char,
                    'transformed': new_char,
                    'key_char': k_char,
                    'key_index': k_idx,
                    'shift': shift,
                    'detail': f"'{char}' (pos {orig_pos}) + key '{k_char}' from {source} (shift +{shift}) -> '{new_char}' (pos {new_pos})"
                })
            k_idx += 1
        else:
            result_chars.append(char)
            if return_steps:
                steps.append({
                    'original': char,
                    'transformed': char,
                    'detail': f"Non-alphabetic '{char}' preserved; keystream does not advance."
                })
                
    ciphertext = ''.join(result_chars)
    response = {
        'result': ciphertext,
        'key': primer
    }
    if return_steps:
        response['steps'] = steps
        response['keystream'] = ''.join(keystream)
        response['summary'] = f"Autokey encrypted {len(plain_letters)} letters with primer '{primer}' and extended keystream '{''.join(keystream[:25])}{'...' if len(keystream) > 25 else ''}'."
    return response


def autokey_decrypt(text: str, key: Any, return_steps: bool = False) -> Dict[str, Any]:
    """
    Decrypts ciphertext using the Autokey Cipher.
    Decryption sequentially reveals plaintext letters, which are appended to the keystream.
    """
    if not text:
        raise ValueError("Please enter some text.")
        
    primer = validate_autokey_key(key)
    keystream = list(primer)
    
    result_chars = []
    steps = []
    k_idx = 0
    
    for char in text:
        if 'A' <= char <= 'Z':
            k_char = keystream[k_idx]
            shift = ord(k_char) - ord('A')
            orig_pos = ord(char) - ord('A')
            new_pos = (orig_pos - shift) % 26
            new_char = chr(ord('A') + new_pos)
            result_chars.append(new_char)
            keystream.append(new_char)
            if return_steps:
                source = "primer key" if k_idx < len(primer) else f"recovered plaintext '{k_char}'"
                steps.append({
                    'original': char,
                    'transformed': new_char,
                    'key_char': k_char,
                    'key_index': k_idx,
                    'shift': shift,
                    'detail': f"'{char}' (pos {orig_pos}) - key '{k_char}' from {source} (shift -{shift}) -> recovered '{new_char}' (pos {new_pos})"
                })
            k_idx += 1
        elif 'a' <= char <= 'z':
            k_char = keystream[k_idx]
            shift = ord(k_char) - ord('A')
            orig_pos = ord(char) - ord('a')
            new_pos = (orig_pos - shift) % 26
            new_char = chr(ord('a') + new_pos)
            result_chars.append(new_char)
            keystream.append(new_char.upper())
            if return_steps:
                source = "primer key" if k_idx < len(primer) else f"recovered plaintext '{k_char}'"
                steps.append({
                    'original': char,
                    'transformed': new_char,
                    'key_char': k_char,
                    'key_index': k_idx,
                    'shift': shift,
                    'detail': f"'{char}' (pos {orig_pos}) - key '{k_char}' from {source} (shift -{shift}) -> recovered '{new_char}' (pos {new_pos})"
                })
            k_idx += 1
        else:
            result_chars.append(char)
            if return_steps:
                steps.append({
                    'original': char,
                    'transformed': char,
                    'detail': f"Non-alphabetic '{char}' preserved; keystream does not advance."
                })
                
    plaintext = ''.join(result_chars)
    response = {
        'result': plaintext,
        'key': primer
    }
    if return_steps:
        response['steps'] = steps
        response['keystream'] = ''.join(keystream)
        response['summary'] = f"Autokey decrypted message by dynamically regenerating keystream from primer '{primer}' and recovered characters."
    return response





