# Cyber Cipher 🛡️
### Educational Text Encryption, Decryption & Cryptanalysis Lab

A modern, portfolio-quality cybersecurity laboratory built with Python 3, Flask, HTML5, CSS3, and Vanilla JavaScript. **Cyber Cipher** allows students and security enthusiasts to interactively encrypt, decrypt, inspect transformation mechanics step-by-step, and perform cryptanalysis on foundational classical ciphers.

---

## 📋 Table of Contents
- [Overview](#overview)
- [Key Features](#key-features)
- [Technologies](#technologies)
- [Algorithms Implemented](#algorithms-implemented)
- [Cryptanalysis & Attack Lab](#cryptanalysis--attack-lab)
- [Project Architecture](#project-architecture)
- [Installation & Setup](#installation--setup)
- [Running Automated Tests](#running-automated-tests)
- [Screenshots & UI Showcase](#screenshots--ui-showcase)
- [Educational Security Disclaimer](#educational-security-disclaimer)
- [Learning Outcomes](#learning-outcomes)
- [Future Improvements](#future-improvements)

---

## Overview

Classical cryptography laid the groundwork for modern information security. Understanding historical techniques like substitution, transposition, key scheduling, and frequency analysis gives developers intuition into Kerckhoffs's principle and why modern block/stream ciphers (such as AES) were engineered.

**Cyber Cipher** demonstrates these transformations manually in pure Python without external crypto libraries, exposing character-level and digraph-level steps so learners can see exactly how ciphertext is generated and unraveled.

---

## Key Features

- **Interactive Multi-Cipher Workspace**:
  - Encrypt and decrypt using 6 classical algorithms.
  - Dynamic key inputs tailored to each cipher's mathematical constraints.
  - Live character and word counters.
  - Input/Output text swapping for quick roundtrip testing.
  - One-click copy to clipboard with toast notifications.
  - Educational sample loader for every cipher.
- **Educational Step Visualizer ("Show Steps")**:
  - Breaks down the complete transformation pipeline: `INPUT → KEY → ALGORITHM → TRANSFORMATION → OUTPUT`.
  - Step-by-step audit logs showing modular arithmetic, zigzag rail positions, and Playfair digraph matrix rules.
- **⚔ Attack Lab (Cryptanalysis)**:
  - **Caesar Brute Force Cracker**: Exhausts the entire 25-shift keyspace, displaying all candidate plaintexts with one-click workspace loading.
  - **Frequency Analysis Visualizer**: Computes letter counts and observed percentages, comparing distribution profiles against standard English language benchmarks (`ETAOIN SHRDLU`).
- **Cryptographic Knowledge Base**:
  - 11 educational cards covering foundational concepts (Plaintext, Ciphertext, Encryption, Decryption, Keys, Substitution, Transposition, Brute Force, Cryptanalysis, Classical vs. Modern).
- **Classical vs. Modern Cryptography Comparison**:
  - Detailed side-by-side contrast between historical paper-and-pencil ciphers and production standards (AES, RSA, ECC).
- **Cybersecurity Dark Theme**:
  - High-contrast, responsive interface optimized for desktop, tablet, and mobile.

---

## Technologies

- **Frontend**:
  - **HTML5**: Semantic layout with accessibility features.
  - **CSS3**: Custom cybersecurity dark theme, CSS Grid & Flexbox, neon accent glows.
  - **Vanilla JavaScript**: Pure ECMAScript client managing dynamic DOM updates, asynchronous fetch requests, and chart visualizations without heavy frameworks.
- **Backend**:
  - **Python 3.10+**: Modular, pure-Python algorithm engine with thorough docstrings and type annotations.
  - **Flask**: Lightweight WSGI microframework providing REST API endpoints.
- **Testing**:
  - **Python standard `unittest` library**: 38 automated test cases covering encryption, decryption, roundtrip reversibility, edge cases, and cryptanalysis.

---

## Algorithms Implemented

All algorithms are implemented manually from mathematical first principles in [`algorithms.py`](file:///algorithms.py):

| Algorithm | Type | Key Type | Description |
| :--- | :--- | :--- | :--- |
| **Caesar Cipher** | Monoalphabetic Substitution | Integer Shift ($\mathbb{Z}$) | Shifts letters by a fixed offset modulo 26; preserves casing and punctuation. |
| **Vigenère Cipher** | Polyalphabetic Substitution | Keyword ($A\text{--}Z$) | Cycles through a keyword to apply shifting Caesar alphabets across plaintext. |
| **Rail Fence Cipher** | Transposition | Integer Rails ($\ge 2$) | Writes characters along a zigzag rail path and reads off row by row. |
| **Playfair Cipher** | Polygraphic Substitution | Keyword ($A\text{--}Z$) | Encrypts letter pairs (digraphs) across a $5\times 5$ key matrix (merging I/J and inserting filler X). |
| **Beaufort Cipher** | Reciprocal Substitution | Keyword ($A\text{--}Z$) | Employs reverse subtraction $C = (K - P) \pmod{26}$; encryption and decryption are identical operations. |
| **Autokey Cipher** | Extended Keystream | Primer Keyword | Eliminates key periodicity by extending the initial key with the plaintext message itself. |

---

## Cryptanalysis & Attack Lab

Located in [`cryptanalysis.py`](file:///cryptanalysis.py):

1. **Caesar Brute Force Cracker (`POST /attack/caesar`)**:
   - Because the keyspace $|K| = 26$ has only 25 non-trivial shifts, an attacker can exhaust all possible keys instantly.
   - The lab generates all 25 candidate plaintexts without bias, empowering the user to identify the correct message.
2. **Frequency Analysis Tool (`POST /analysis/frequency`)**:
   - Measures single-letter frequencies against standard English letter frequencies (where `E` $\approx 12.0\%$, `T` $\approx 9.1\%$, `A` $\approx 8.1\%$).
   - Demonstrates why monoalphabetic substitution fails against statistical cryptanalysis.

---

## Project Architecture

```
CyberCipher/
│
├── app.py                      # Flask application and REST API routing
├── algorithms.py               # Manual cipher implementations & step generators
├── cryptanalysis.py            # Caesar brute force and letter frequency analyzer
├── requirements.txt            # Application dependencies (Flask)
├── README.md                   # Project documentation
│
├── templates/
│   └── index.html              # Responsive single-page application UI
│
├── static/
│   ├── css/
│   │   └── style.css           # Cybersecurity dark theme & layout
│   └── js/
│       └── script.js           # Vanilla JS controller & API client
│
└── tests/
    ├── __init__.py
    └── test_algorithms.py      # Automated test suite (38 unit tests)
```

---

## Installation & Setup

### Prerequisites
- Python 3.10 or higher installed.

### 1. Clone or Open the Repository
```powershell
cd "c:\Users\Vedant Desai\Documents\Text Encryption Web Application"
```

### 2. Create and Activate Virtual Environment (Recommended)
**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 4. Run the Application
```powershell
python app.py
```

### 5. Access the Web Application
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## Running Automated Tests

Run the full automated test suite using Python's built-in `unittest` discovery runner:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

### Test Coverage Highlights:
- ✅ **Caesar Cipher**: Basic encryption/decryption, shift normalization, negative shifts, case & symbol preservation, invalid key rejection.
- ✅ **Vigenère Cipher**: Standard vectors, case preservation, non-alpha skipping in keystream, key validation, roundtrip reversibility.
- ✅ **Rail Fence Cipher**: Transposition zigzag routing, row reconstruction, rail counts $2\dots 7$, validation for $<2$ rails.
- ✅ **Playfair Cipher**: 5x5 matrix construction, I/J consolidation, duplicate letter splitting with filler 'X', digraph rules (same row, same column, rectangle), roundtrip decoding.
- ✅ **Beaufort Cipher**: Basic encryption/decryption, reciprocal self-inversion verification ($E(E(P, K), K) == P$).
- ✅ **Autokey Cipher**: Dynamic keystream extension, sequential cascading decryption, roundtrip reversibility.
- ✅ **Cryptanalysis**: Exhaustive 25-shift candidate generation, letter frequency counting and validation.
- ✅ **Reversibility & Edge Cases**: Single-character messages, 2,000+ character stress tests with mixed symbols.

---

## Screenshots & UI Showcase

*(Screenshots can be placed in `docs/screenshots/`)*

| Main Encryption Workspace | Educational Steps Visualizer |
| :---: | :---: |
| *[Screenshot Placeholder: Interactive Workspace with Caesar Cipher]* | *[Screenshot Placeholder: Step-by-Step Modular Transformation]* |

| Caesar Brute Force Cracker | Letter Frequency Distribution |
| :---: | :---: |
| *[Screenshot Placeholder: 25-Shift Keyspace Exhaustion]* | *[Screenshot Placeholder: Observed vs. Expected English Chart]* |

---

## Educational Security Disclaimer

> [!CAUTION]
> **⚠ Educational Project Notice**
>
> The classical ciphers implemented in this project (Caesar, Vigenère, Rail Fence, Playfair, Beaufort, Autokey) are historical artifacts designed centuries before electronic computation. They are **fundamentally insecure** against modern cryptanalysis and **must never be used** for protecting real passwords, financial transactions, session cookies, or confidential user data.
>
> Production systems must exclusively employ modern, peer-reviewed standards such as:
> - **Symmetric Encryption**: AES-256-GCM, ChaCha20-Poly1305.
> - **Asymmetric Encryption & Key Exchange**: RSA (3072+ bits), ECDH (Curve25519, NIST P-256).
> - **Cryptographic Hashing & Password Derivation**: Argon2id, bcrypt, PBKDF2, SHA-256 / SHA-3.
> - **Transport Security**: TLS 1.3 / HTTPS.

---

## Learning Outcomes

After working with this project, students understand:
1. **The Difference Between Substitution and Transposition**:
   - Substitution alters character identities; transposition scrambles character positions.
2. **Keyspace Exhaustion & Brute Force**:
   - Why small keyspaces ($|K| \le 26$) can be cracked in microseconds.
3. **Statistical Cryptanalysis**:
   - How human language entropy and non-uniform letter distributions reveal monoalphabetic keys.
4. **Polyalphabetic vs. Polygraphic Advancements**:
   - How Vigenère, Beaufort, Autokey, and Playfair attempt to flatten single-letter frequency spikes.
5. **Kerckhoffs's Principle**:
   - Why cipher security must reside solely in the secrecy of the key, not in hiding the algorithm.

---

## Future Improvements

Potential future modules for advanced cybersecurity coursework:
- [ ] **Modern Symmetric Demonstrations**: Educational visualizer for AES S-Box substitution and MixColumns.
- [ ] **Modern Asymmetric Demonstrations**: Step-by-step RSA key generation ($p, q, n, e, d$) with small primes.
- [ ] **Cryptographic Hash Lab**: Visualizing SHA-256 avalanche effect and collision resistance.
- [ ] **Password Security & Salting**: Interactive comparison between raw MD5/SHA-1 and salted Argon2id/bcrypt.
- [ ] **File Encryption**: Secure AES-GCM file upload and client-side encryption.
- [ ] **Docker Containerization**: Containerized Dockerfile and docker-compose deployment.

---

## License

Created for educational purposes. Feel free to adapt for academic instruction, workshops, and cybersecurity coursework.
