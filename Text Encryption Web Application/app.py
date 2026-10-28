"""
Cyber Cipher - Flask Web Application
Main entry point for the Text Encryption, Decryption & Cryptanalysis Lab.
"""

from flask import Flask, render_template, request, jsonify
import algorithms
import cryptanalysis

app = Flask(__name__)

# Maximum allowed text length to avoid denial of service
MAX_TEXT_LENGTH = 100000


@app.route("/")
def index():
    """Renders the main educational application dashboard."""
    return render_template("index.html")


@app.route("/api/ciphers", methods=["GET"])
def get_ciphers():
    """Returns available ciphers and their educational metadata."""
    return jsonify({
        "success": True,
        "ciphers": algorithms.CIPHER_METADATA
    })


@app.route("/encrypt", methods=["POST"])
def handle_encrypt():
    """
    Encrypts input text using the specified algorithm and key.
    Payload: { "cipher": str, "text": str, "key": any, "show_steps": bool }
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Request body must be valid JSON."}), 400

    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Empty request payload."}), 400

    cipher = str(data.get("cipher", "")).strip().lower()
    text = data.get("text", "")
    key = data.get("key", "")
    show_steps = bool(data.get("show_steps", False))

    if not cipher:
        return jsonify({"success": False, "error": "Please select an algorithm."}), 400

    if not text:
        return jsonify({"success": False, "error": "Please enter some text."}), 400

    if len(text) > MAX_TEXT_LENGTH:
        return jsonify({"success": False, "error": f"Input text exceeds the maximum allowed length of {MAX_TEXT_LENGTH} characters."}), 400

    try:
        if cipher == "caesar":
            res = algorithms.caesar_encrypt(text, key, return_steps=show_steps)
        elif cipher == "vigenere":
            if not hasattr(algorithms, "vigenere_encrypt"):
                return jsonify({"success": False, "error": "Vigenere Cipher is not yet loaded."}), 400
            res = algorithms.vigenere_encrypt(text, key, return_steps=show_steps)
        elif cipher == "rail_fence" or cipher == "railfence":
            if not hasattr(algorithms, "rail_fence_encrypt"):
                return jsonify({"success": False, "error": "Rail Fence Cipher is not yet loaded."}), 400
            res = algorithms.rail_fence_encrypt(text, key, return_steps=show_steps)
        elif cipher == "playfair":
            if not hasattr(algorithms, "playfair_encrypt"):
                return jsonify({"success": False, "error": "Playfair Cipher is not yet loaded."}), 400
            res = algorithms.playfair_encrypt(text, key, return_steps=show_steps)
        elif cipher == "beaufort":
            if not hasattr(algorithms, "beaufort_encrypt"):
                return jsonify({"success": False, "error": "Beaufort Cipher is not yet loaded."}), 400
            res = algorithms.beaufort_encrypt(text, key, return_steps=show_steps)
        elif cipher == "autokey":
            if not hasattr(algorithms, "autokey_encrypt"):
                return jsonify({"success": False, "error": "Autokey Cipher is not yet loaded."}), 400
            res = algorithms.autokey_encrypt(text, key, return_steps=show_steps)
        else:
            return jsonify({"success": False, "error": f"Unknown cipher '{cipher}'."}), 400

        return jsonify({
            "success": True,
            "result": res["result"],
            "steps": res.get("steps"),
            "summary": res.get("summary")
        })
    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"An unexpected error occurred: {str(e)}"}), 500


@app.route("/decrypt", methods=["POST"])
def handle_decrypt():
    """
    Decrypts input text using the specified algorithm and key.
    Payload: { "cipher": str, "text": str, "key": any, "show_steps": bool }
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Request body must be valid JSON."}), 400

    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Empty request payload."}), 400

    cipher = str(data.get("cipher", "")).strip().lower()
    text = data.get("text", "")
    key = data.get("key", "")
    show_steps = bool(data.get("show_steps", False))

    if not cipher:
        return jsonify({"success": False, "error": "Please select an algorithm."}), 400

    if not text:
        return jsonify({"success": False, "error": "Please enter some text."}), 400

    if len(text) > MAX_TEXT_LENGTH:
        return jsonify({"success": False, "error": f"Input text exceeds the maximum allowed length of {MAX_TEXT_LENGTH} characters."}), 400

    try:
        if cipher == "caesar":
            res = algorithms.caesar_decrypt(text, key, return_steps=show_steps)
        elif cipher == "vigenere":
            if not hasattr(algorithms, "vigenere_decrypt"):
                return jsonify({"success": False, "error": "Vigenere Cipher is not yet loaded."}), 400
            res = algorithms.vigenere_decrypt(text, key, return_steps=show_steps)
        elif cipher == "rail_fence" or cipher == "railfence":
            if not hasattr(algorithms, "rail_fence_decrypt"):
                return jsonify({"success": False, "error": "Rail Fence Cipher is not yet loaded."}), 400
            res = algorithms.rail_fence_decrypt(text, key, return_steps=show_steps)
        elif cipher == "playfair":
            if not hasattr(algorithms, "playfair_decrypt"):
                return jsonify({"success": False, "error": "Playfair Cipher is not yet loaded."}), 400
            res = algorithms.playfair_decrypt(text, key, return_steps=show_steps)
        elif cipher == "beaufort":
            if not hasattr(algorithms, "beaufort_decrypt"):
                return jsonify({"success": False, "error": "Beaufort Cipher is not yet loaded."}), 400
            res = algorithms.beaufort_decrypt(text, key, return_steps=show_steps)
        elif cipher == "autokey":
            if not hasattr(algorithms, "autokey_decrypt"):
                return jsonify({"success": False, "error": "Autokey Cipher is not yet loaded."}), 400
            res = algorithms.autokey_decrypt(text, key, return_steps=show_steps)
        else:
            return jsonify({"success": False, "error": f"Unknown cipher '{cipher}'."}), 400

        return jsonify({
            "success": True,
            "result": res["result"],
            "steps": res.get("steps"),
            "summary": res.get("summary")
        })
    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"An unexpected error occurred: {str(e)}"}), 500


@app.route("/attack/caesar", methods=["POST"])
def handle_caesar_attack():
    """
    Executes a brute-force attack testing all 25 non-trivial Caesar shifts.
    Payload: { "ciphertext": str }
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Request body must be valid JSON."}), 400

    data = request.get_json()
    ciphertext = data.get("ciphertext", "") if data else ""

    try:
        results = cryptanalysis.caesar_brute_force(ciphertext)
        return jsonify({
            "success": True,
            **results
        })
    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"An unexpected error occurred: {str(e)}"}), 500


@app.route("/analysis/frequency", methods=["POST"])
def handle_frequency_analysis():
    """
    Computes letter frequency counts, percentages, and comparison against English benchmarks.
    Payload: { "text": str }
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Request body must be valid JSON."}), 400

    data = request.get_json()
    text = data.get("text", "") if data else ""

    try:
        results = cryptanalysis.frequency_analysis(text)
        return jsonify({
            "success": True,
            **results
        })
    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"An unexpected error occurred: {str(e)}"}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
