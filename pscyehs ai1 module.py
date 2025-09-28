import os
import base64
import hashlib
import hmac
from flask import Flask, request, jsonify, render_template_string
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# Load API keys from environment variable (comma-separated)
API_KEYS = set(os.environ.get("API_KEYS", "demo-key-123").split(","))

app = Flask(__name__)

def derive_key(password: str, salt: bytes) -> bytes:
    # Scrypt is a strong KDF, no need for extra password hashing
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
    return kdf.derive(password.encode())

def encrypt(message: str, password: str) -> dict:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    hmac_digest = hmac.new(key, ciphertext, hashlib.sha256).digest()
    return {
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "hmac": base64.b64encode(hmac_digest).decode()
    }

def decrypt(enc: dict, password: str) -> str:
    salt = base64.b64decode(enc["salt"])
    iv = base64.b64decode(enc["iv"])
    ciphertext = base64.b64decode(enc["ciphertext"])
    expected_hmac = base64.b64decode(enc["hmac"])
    key = derive_key(password, salt)
    hmac_digest = hmac.new(key, ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(hmac_digest, expected_hmac):
        raise ValueError("HMAC verification failed. Wrong password or tampered data.")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode()

def check_api_key():
    key = request.headers.get("X-API-Key")
    return key in API_KEYS

@app.route("/encrypt", methods=["POST"])
def api_encrypt():
    if not check_api_key():
        return jsonify({"error": "Invalid API key"}), 401
    req = request.get_json()
    message = req.get("message")
    password = req.get("password")
    if not message or not password:
        return jsonify({"error": "Missing message or password"}), 400
    result = encrypt(message, password)
    return jsonify(result)

@app.route("/decrypt", methods=["POST"])
def api_decrypt():
    if not check_api_key():
        return jsonify({"error": "Invalid API key"}), 401
    req = request.get_json()
    password = req.get("password")
    for field in ["salt", "iv", "ciphertext", "hmac"]:
        if field not in req:
            return jsonify({"error": f"Missing field: {field}"}), 400
    try:
        decrypted = decrypt(req, password)
        return jsonify({"message": decrypted})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/", methods=["GET", "POST"])
def home():
    HTML = """
    <!DOCTYPE html>
    <html>
    <head>
      <title>Psyches Encryption Console</title>
      <style>
        body { background: #181818; color: #fff; font-family: 'Segoe UI', Arial, sans-serif; margin: 0; }
        .container { max-width: 500px; margin: 60px auto; background: #232323; border-radius: 12px; box-shadow: 0 0 20px #00e6e6; padding: 32px; }
        h1 { color: #00e6e6; margin-bottom: 10px; text-align: center; }
        label { color: #00e6e6; font-weight: bold; }
        input, textarea, button { margin: 8px 0; padding: 8px; border-radius: 6px; border: none; width: 100%; }
        textarea { resize: vertical; }
        button { background: #00e6e6; color: #222; font-weight: bold; cursor: pointer; }
        .result { background: #222; color: #00e6e6; padding: 10px; border-radius: 6px; margin-top: 16px; }
        .footer { color: #888; font-size: 0.9em; margin-top: 30px; text-align: center; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>🦾 Psyches Encryption Console</h1>
        <form method="post">
          <label for="action">Action:</label>
          <select name="action" id="action">
            <option value="encrypt">Encrypt</option>
            <option value="decrypt">Decrypt</option>
          </select>
          <label for="message">Message:</label>
          <textarea name="message" id="message" rows="3" placeholder="Type your message or paste encrypted JSON here"></textarea>
          <label for="password">Password:</label>
          <input type="password" name="password" id="password" placeholder="Password" required>
          <button type="submit">Go</button>
        </form>
        {% if result %}
          <div class="result">{{ result }}</div>
        {% endif %}
        {% if error %}
          <div class="result" style="color:#ff6666;">{{ error }}</div>
        {% endif %}
        <div class="footer">
          &copy; 2025 Psyches Security. All rights reserved.<br>
          <span style="color:#00e6e6;">Contact: support@psyches.com</span>
        </div>
      </div>
    </body>
    </html>
    """
    result = None
    error = None
    if request.method == "POST":
        action = request.form.get("action")
        message = request.form.get("message")
        password = request.form.get("password")
        try:
            if action == "encrypt":
                if not message or not password:
                    error = "Message and password required."
                else:
                    enc = encrypt(message, password)
                    import json
                    result = json.dumps(enc, indent=2)
            elif action == "decrypt":
                if not message or not password:
                    error = "Encrypted JSON and password required."
                else:
                    import json
                    try:
                        enc = json.loads(message)
                        dec = decrypt(enc, password)
                        result = dec
                    except Exception as e:
                        error = f"Decryption error: {e}"
            else:
                error = "Unknown action."
        except Exception as e:
            error = f"Error: {e}"
    return render_template_string(HTML, result=result, error=error)

if __name__ == "__main__":
    app.run(debug=True)