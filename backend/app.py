"""
app.py
------
Flask REST API for the AES Cryptography Analysis Platform.

Endpoints:
    GET  /api/health
    POST /api/keygen
    POST /api/encrypt          — ECB, CBC, CTR
    POST /api/decrypt          — ECB, CBC, CTR
    POST /api/gcm/encrypt      — AES-GCM (AEAD)
    POST /api/gcm/decrypt      — AES-GCM with tag verification
    POST /api/pattern          — ECB pattern leakage analysis (with conclusions)
    POST /api/benchmark        — Performance benchmark (with conclusions)

Run:
    python app.py

Requires:
    pip install flask flask-cors pycryptodome
"""

import base64
from flask import Flask, request, jsonify
from flask_cors import CORS

from aes_core import (
    encrypt as aes_encrypt,
    decrypt as aes_decrypt,
    generate_key,
    generate_iv,
    GCMCipher,
)
from aes_analysis import (
    analyze_pattern_leakage,
    run_full_benchmark,
    gcm_integrity_demo,
)

app = Flask(__name__)
CORS(app)


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _parse_hex(value: str, field: str) -> bytes:
    """Convert hex string to bytes, raising ValueError on failure."""
    try:
        return bytes.fromhex(value.strip())
    except (ValueError, AttributeError):
        raise ValueError(f"'{field}' must be a valid hex string.")


def _err(msg: str, status: int = 400):
    return jsonify({"error": msg}), status


def _strip_raw_bytes(obj: dict) -> dict:
    """Remove non-serializable bytes fields before JSON response."""
    return {k: v for k, v in obj.items() if not isinstance(v, (bytes, bytearray))}


# ──────────────────────────────────────────────
# Health
# ──────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    """Health check."""
    return jsonify({"status": "ok", "service": "AES Cryptography Analysis API"})


# ──────────────────────────────────────────────
# Key generation
# ──────────────────────────────────────────────

@app.route("/api/keygen", methods=["POST"])
def keygen():
    """
    Generate a random AES key.

    Request JSON:
        key_size (int, optional): 16, 24, or 32. Default: 32.

    Response JSON:
        key_hex, key_b64, key_size_bytes, key_size_bits
    """
    body = request.get_json(silent=True) or {}
    key_size = int(body.get("key_size", 32))
    if key_size not in (16, 24, 32):
        return _err("key_size must be 16, 24, or 32.")
    key = generate_key(key_size)
    return jsonify({
        "key_hex": key.hex(),
        "key_b64": base64.b64encode(key).decode(),
        "key_size_bytes": key_size,
        "key_size_bits": key_size * 8,
    })


# ──────────────────────────────────────────────
# Encrypt / Decrypt (ECB, CBC, CTR)
# ──────────────────────────────────────────────

@app.route("/api/encrypt", methods=["POST"])
def encrypt_endpoint():
    """
    Encrypt plaintext with AES-ECB, AES-CBC, or AES-CTR.

    Request JSON:
        plaintext (str): UTF-8 text to encrypt.
        key_hex (str): AES key as hex.
        mode (str): 'ECB', 'CBC', or 'CTR'.
        iv_hex (str, optional): IV/nonce hex. Auto-generated if omitted.

    Response JSON:
        mode, ciphertext_hex, ciphertext_b64, iv_hex, iv_b64,
        blocks, block_count, plaintext_length, ciphertext_length,
        secure, security_note, repeated_block_types, leaked_repetitions
    """
    body = request.get_json(silent=True)
    if not body:
        return _err("Request body must be JSON.")

    try:
        plaintext = body.get("plaintext", "")
        if not isinstance(plaintext, str):
            return _err("'plaintext' must be a string.")

        key = _parse_hex(body.get("key_hex", ""), "key_hex")
        mode = str(body.get("mode", "CBC")).upper()
        if mode not in ("ECB", "CBC", "CTR"):
            return _err("mode must be 'ECB', 'CBC', or 'CTR'. Use /api/gcm/encrypt for GCM.")

        iv = None
        if "iv_hex" in body and body["iv_hex"]:
            iv = _parse_hex(body["iv_hex"], "iv_hex")

        result = aes_encrypt(plaintext, key, mode, iv)
        return jsonify(_strip_raw_bytes(result))

    except (ValueError, KeyError) as e:
        return _err(str(e))
    except Exception as e:
        return _err(f"Encryption failed: {e}", 500)


@app.route("/api/decrypt", methods=["POST"])
def decrypt_endpoint():
    """
    Decrypt AES-ECB, AES-CBC, or AES-CTR ciphertext.

    Request JSON:
        ciphertext_hex (str): Ciphertext as hex.
        key_hex (str): AES key as hex.
        mode (str): 'ECB', 'CBC', or 'CTR'.
        iv_hex (str): IV/nonce hex (required for CBC and CTR).

    Response JSON:
        plaintext, plaintext_hex, mode
    """
    body = request.get_json(silent=True)
    if not body:
        return _err("Request body must be JSON.")

    try:
        ciphertext = _parse_hex(body.get("ciphertext_hex", ""), "ciphertext_hex")
        key = _parse_hex(body.get("key_hex", ""), "key_hex")
        mode = str(body.get("mode", "CBC")).upper()
        if mode not in ("ECB", "CBC", "CTR"):
            return _err("mode must be 'ECB', 'CBC', or 'CTR'. Use /api/gcm/decrypt for GCM.")

        iv = None
        if "iv_hex" in body and body["iv_hex"]:
            iv = _parse_hex(body["iv_hex"], "iv_hex")

        plaintext_bytes = aes_decrypt(ciphertext, key, mode, iv)
        plaintext = plaintext_bytes.decode("utf-8")

        return jsonify({
            "plaintext": plaintext,
            "plaintext_hex": plaintext_bytes.hex(),
            "mode": mode,
        })

    except UnicodeDecodeError:
        return _err("Decrypted bytes are not valid UTF-8.")
    except (ValueError, KeyError) as e:
        return _err(str(e))
    except Exception as e:
        return _err(f"Decryption failed: {e}", 500)


# ──────────────────────────────────────────────
# AES-GCM (AEAD)
# ──────────────────────────────────────────────

@app.route("/api/gcm/encrypt", methods=["POST"])
def gcm_encrypt_endpoint():
    """
    Encrypt and authenticate plaintext with AES-256-GCM.

    Provides both confidentiality (CTR-mode encryption) and integrity
    (128-bit Galois authentication tag). The auth tag covers both the
    ciphertext and the AAD.

    Request JSON:
        plaintext (str): UTF-8 text to encrypt.
        aad (str, optional): Additional Authenticated Data — authenticated
                             but NOT encrypted. E.g. transaction IDs, headers.
        key_hex (str, optional): AES-256 key as hex. New key generated if omitted.
        iv_hex (str, optional): 12-byte (24 hex char) nonce. Auto-generated if omitted.

    Response JSON:
        mode, ciphertext_hex, ciphertext_b64,
        auth_tag_hex, auth_tag_b64, auth_tag_bits,
        iv_hex, iv_b64,
        key_hex (only if auto-generated),
        aad, plaintext_length, ciphertext_length,
        authenticated, security_note
    """
    body = request.get_json(silent=True)
    if not body:
        return _err("Request body must be JSON.")

    try:
        plaintext = body.get("plaintext", "")
        if not isinstance(plaintext, str):
            return _err("'plaintext' must be a string.")

        aad = body.get("aad", "")
        if not isinstance(aad, str):
            return _err("'aad' must be a string.")
        aad_bytes = aad.encode("utf-8")

        # Key — auto-generate if not provided
        key_provided = bool(body.get("key_hex"))
        if key_provided:
            key = _parse_hex(body["key_hex"], "key_hex")
        else:
            key = generate_key(32)

        # Nonce — auto-generate if not provided
        iv = None
        if "iv_hex" in body and body["iv_hex"]:
            iv = _parse_hex(body["iv_hex"], "iv_hex")
            if len(iv) != 12:
                return _err("GCM iv_hex must be 24 hex chars (12 bytes / 96-bit).")

        cipher = GCMCipher(key)
        result = cipher.encrypt(plaintext.encode("utf-8"), aad=aad_bytes, nonce=iv)

        response = _strip_raw_bytes(result)
        response["aad"] = aad
        if not key_provided:
            response["key_hex"] = key.hex()

        return jsonify(response)

    except (ValueError, KeyError) as e:
        return _err(str(e))
    except Exception as e:
        return _err(f"GCM encryption failed: {e}", 500)


@app.route("/api/gcm/decrypt", methods=["POST"])
def gcm_decrypt_endpoint():
    """
    Decrypt and verify AES-256-GCM ciphertext.

    If the ciphertext or AAD has been tampered with, returns HTTP 400
    with an authentication failure message — decryption is aborted.

    Request JSON:
        ciphertext_hex (str): Ciphertext as hex.
        key_hex (str): AES key as hex.
        iv_hex (str): 12-byte nonce hex (24 chars).
        auth_tag_hex (str): 16-byte authentication tag hex (32 chars).
        aad (str, optional): Same AAD used during encryption.

    Response JSON (success):
        plaintext, plaintext_hex, mode, authentic: true

    Response JSON (failure):
        error: "Authentication failed — …", authentic: false  [HTTP 400]
    """
    body = request.get_json(silent=True)
    if not body:
        return _err("Request body must be JSON.")

    try:
        ciphertext = _parse_hex(body.get("ciphertext_hex", ""), "ciphertext_hex")
        key = _parse_hex(body.get("key_hex", ""), "key_hex")
        iv = _parse_hex(body.get("iv_hex", ""), "iv_hex")
        tag = _parse_hex(body.get("auth_tag_hex", ""), "auth_tag_hex")
        aad_bytes = body.get("aad", "").encode("utf-8")

        if len(iv) != 12:
            return _err("GCM iv_hex must be 24 hex chars (12 bytes / 96-bit).")
        if len(tag) != 16:
            return _err("auth_tag_hex must be 32 hex chars (16 bytes / 128-bit).")

        cipher = GCMCipher(key)
        plaintext_bytes = cipher.decrypt(ciphertext, tag, iv, aad_bytes)
        plaintext = plaintext_bytes.decode("utf-8")

        return jsonify({
            "plaintext": plaintext,
            "plaintext_hex": plaintext_bytes.hex(),
            "mode": "GCM",
            "authentic": True,
            "message": "Decryption and authentication successful — data integrity verified.",
        })

    except UnicodeDecodeError:
        return _err("Decrypted bytes are not valid UTF-8.")
    except ValueError as e:
        # GCM authentication failure — must return 400 with clear message
        return jsonify({
            "error": str(e),
            "authentic": False,
            "message": (
                "Authentication tag mismatch — the ciphertext or AAD has been "
                "modified. Decryption was aborted to prevent processing of tampered data. "
                "This is AES-GCM's integrity guarantee in action."
            ),
        }), 400
    except Exception as e:
        return _err(f"GCM decryption failed: {e}", 500)


# ──────────────────────────────────────────────
# Pattern Analysis
# ──────────────────────────────────────────────

@app.route("/api/pattern", methods=["POST"])
def pattern_endpoint():
    """
    Analyse ECB pattern leakage across ECB, CBC, and CTR modes.

    Demonstrates ECB's IND-CPA failure: identical plaintext blocks produce
    identical ciphertext blocks, revealing structural patterns to observers.

    Request JSON:
        plaintext (str): Text to analyse — ideally with repeating 16-byte blocks.
        key_hex (str, optional): Shared AES key hex. Random key if omitted.

    Response JSON:
        plaintext_hex, plaintext_blocks, plaintext_repeated_block_types,
        plaintext_leaked_repetitions, key_hex,
        modes: {
            ECB: { total_blocks, unique_blocks, duplicate_block_types,
                   leaked_repetitions, leakage_ratio, blocks, block_frequencies,
                   secure, security_verdict, security_reason, ciphertext_hex },
            CBC: { … },
            CTR: { … }
        },
        conclusions: { observation, inference, conclusion, attack_description }
    """
    body = request.get_json(silent=True)
    if not body:
        return _err("Request body must be JSON.")

    try:
        plaintext = body.get("plaintext", "")
        if not isinstance(plaintext, str):
            return _err("'plaintext' must be a string.")

        key = None
        if "key_hex" in body and body["key_hex"]:
            key = _parse_hex(body["key_hex"], "key_hex")

        result = analyze_pattern_leakage(plaintext, key)

        # Remove raw bytes from nested mode results
        for mode_data in result["modes"].values():
            mode_data.pop("ciphertext", None)

        return jsonify(result)

    except (ValueError, KeyError) as e:
        return _err(str(e))
    except Exception as e:
        return _err(f"Pattern analysis failed: {e}", 500)


# ──────────────────────────────────────────────
# Performance Benchmark
# ──────────────────────────────────────────────

@app.route("/api/benchmark", methods=["POST"])
def benchmark_endpoint():
    """
    Run a performance benchmark across ECB, CBC, and CTR modes.

    Request JSON:
        data_sizes (list[int], optional): Sizes in bytes. Default: [64, 256, 1024, 4096].
        iterations (int, optional): Iterations per test. Default: 50. Max: 500.
        key_size (int, optional): Key size in bytes — 16, 24, or 32. Default: 32.

    Response JSON:
        key_size_bits, iterations,
        modes: { ECB: […], CBC: […], CTR: […] },
        summary: [{ data_size, fastest_mode, times_ms }],
        conclusions: {
            fastest_mode, slowest_mode, average_latency_ms,
            throughput_at_largest_size_mb_s, speedup_ratio,
            observation, inference, conclusion, security_note
        }
    """
    body = request.get_json(silent=True) or {}

    try:
        data_sizes = body.get("data_sizes", [64, 256, 1024, 4096])
        iterations = int(body.get("iterations", 50))
        key_size = int(body.get("key_size", 32))

        if iterations > 500:
            return _err("Max 500 iterations per request to prevent timeout.")
        if key_size not in (16, 24, 32):
            return _err("key_size must be 16, 24, or 32.")
        if not isinstance(data_sizes, list) or len(data_sizes) > 8:
            return _err("data_sizes must be a list of up to 8 integers.")

        results = run_full_benchmark(data_sizes, iterations, key_size)
        return jsonify(results)

    except (ValueError, TypeError) as e:
        return _err(str(e))
    except Exception as e:
        return _err(f"Benchmark failed: {e}", 500)


# ──────────────────────────────────────────────
# GCM Demo (pre-run integrity demonstration)
# ──────────────────────────────────────────────

@app.route("/api/gcm/demo", methods=["GET"])
def gcm_demo_endpoint():
    """
    Pre-run GCM integrity demonstration.

    Encrypts a sample message, tampers with the ciphertext, and returns
    the results showing that the tamper is detected — with academic conclusions.

    Response JSON:
        original_plaintext, aad, ciphertext_hex, auth_tag_hex, iv_hex,
        legitimate_decryption_succeeded, tamper_detected,
        conclusions: { observation, inference, conclusion }
    """
    try:
        result = gcm_integrity_demo()
        return jsonify(result)
    except Exception as e:
        return _err(f"GCM demo failed: {e}", 500)


# ──────────────────────────────────────────────
# Error handlers
# ──────────────────────────────────────────────

@app.errorhandler(404)
def not_found(_):
    return _err("Endpoint not found.", 404)


@app.errorhandler(405)
def method_not_allowed(_):
    return _err("Method not allowed.", 405)


if __name__ == "__main__":
    print("AES Cryptography Analysis API")
    print("Endpoints:")
    print("  GET  /api/health")
    print("  POST /api/keygen")
    print("  POST /api/encrypt        (ECB | CBC | CTR)")
    print("  POST /api/decrypt        (ECB | CBC | CTR)")
    print("  POST /api/gcm/encrypt    (AES-GCM AEAD)")
    print("  POST /api/gcm/decrypt    (AES-GCM with tag verification)")
    print("  GET  /api/gcm/demo       (pre-run tamper detection demo)")
    print("  POST /api/pattern        (ECB leakage analysis + conclusions)")
    print("  POST /api/benchmark      (performance + conclusions)")
    print("\nStarting on http://localhost:5000")
    app.run(debug=True, port=5000)
