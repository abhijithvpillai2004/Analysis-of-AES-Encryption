"""
aes_core.py
-----------
Core AES encryption/decryption logic using PyCryptodome.
Supports ECB, CBC, CTR, and GCM modes.

ECB  — Electronic Codebook      (PKCS7 padding, NO IV — insecure for structured data)
CBC  — Cipher Block Chaining     (PKCS7 padding, random 16-byte IV)
CTR  — Counter Mode              (stream cipher, random 8-byte nonce, no padding)
GCM  — Galois/Counter Mode       (AEAD, random 12-byte nonce, 128-bit auth tag)
"""

import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def generate_key(key_size: int = 32) -> bytes:
    """
    Generate a cryptographically secure random AES key.

    Args:
        key_size: 16 (AES-128), 24 (AES-192), or 32 (AES-256).

    Returns:
        Random bytes of the requested length.
    """
    if key_size not in (16, 24, 32):
        raise ValueError("Key size must be 16, 24, or 32 bytes.")
    return get_random_bytes(key_size)


def generate_iv(size: int = 16) -> bytes:
    """Generate a cryptographically secure random IV or nonce."""
    return get_random_bytes(size)


def validate_key(key: bytes) -> None:
    """Raise ValueError if key length is not AES-compatible."""
    if len(key) not in (16, 24, 32):
        raise ValueError(
            f"Invalid key length {len(key)}. Must be 16, 24, or 32 bytes."
        )


# ──────────────────────────────────────────────
# ECB Mode
# ──────────────────────────────────────────────

class ECBCipher:
    """
    AES-ECB: Electronic Codebook Mode

    ⚠ INSECURE for any structured or repeating data.
    Identical 16-byte plaintext blocks always produce identical ciphertext
    blocks, leaking structural patterns without requiring the key.
    Fails IND-CPA semantic security.

    No IV is used. PKCS7 padding applied automatically.
    """

    def __init__(self, key: bytes):
        validate_key(key)
        self.key = key

    def encrypt(self, plaintext: bytes) -> dict:
        cipher = AES.new(self.key, AES.MODE_ECB)
        padded = pad(plaintext, AES.block_size)
        ciphertext = cipher.encrypt(padded)

        blocks = [
            ciphertext[i: i + AES.block_size].hex()
            for i in range(0, len(ciphertext), AES.block_size)
        ]

        # Detect pattern leakage inline
        freq = {}
        for b in blocks:
            freq[b] = freq.get(b, 0) + 1
        repeated_types = sum(1 for c in freq.values() if c > 1)
        leaked_reps = sum(c - 1 for c in freq.values() if c > 1)

        return {
            "mode": "ECB",
            "ciphertext": ciphertext,
            "ciphertext_hex": ciphertext.hex(),
            "ciphertext_b64": base64.b64encode(ciphertext).decode(),
            "iv": None,
            "iv_hex": None,
            "blocks": blocks,
            "block_count": len(blocks),
            "plaintext_length": len(plaintext),
            "ciphertext_length": len(ciphertext),
            # Security metadata
            "secure": leaked_reps == 0,
            "repeated_block_types": repeated_types,
            "leaked_repetitions": leaked_reps,
            "security_note": (
                "ECB mode: no IV used. Identical plaintext blocks produce identical "
                "ciphertext blocks — pattern leakage is inherent to this mode."
            ),
        }

    def decrypt(self, ciphertext: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_ECB)
        padded = cipher.decrypt(ciphertext)
        return unpad(padded, AES.block_size)


# ──────────────────────────────────────────────
# CBC Mode
# ──────────────────────────────────────────────

class CBCCipher:
    """
    AES-CBC: Cipher Block Chaining Mode

    Each plaintext block is XORed with the previous ciphertext block
    before encryption. A random IV seeds the chain for the first block.

    Security properties:
      - Semantically secure (IND-CPA) when IV is random and unpredictable
      - Identical plaintexts with different IVs → entirely different ciphertexts
      - Encryption is sequential; decryption is parallelizable
      - Vulnerable to padding oracle attacks if error handling leaks timing info
    """

    def __init__(self, key: bytes):
        validate_key(key)
        self.key = key

    def encrypt(self, plaintext: bytes, iv: bytes = None) -> dict:
        if iv is None:
            iv = generate_iv()
        if len(iv) != AES.block_size:
            raise ValueError(f"IV must be {AES.block_size} bytes.")

        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded = pad(plaintext, AES.block_size)
        ciphertext = cipher.encrypt(padded)

        blocks = [
            ciphertext[i: i + AES.block_size].hex()
            for i in range(0, len(ciphertext), AES.block_size)
        ]

        return {
            "mode": "CBC",
            "ciphertext": ciphertext,
            "ciphertext_hex": ciphertext.hex(),
            "ciphertext_b64": base64.b64encode(ciphertext).decode(),
            "iv": iv,
            "iv_hex": iv.hex(),
            "iv_b64": base64.b64encode(iv).decode(),
            "blocks": blocks,
            "block_count": len(blocks),
            "plaintext_length": len(plaintext),
            "ciphertext_length": len(ciphertext),
            # Security metadata
            "secure": True,
            "repeated_block_types": 0,
            "leaked_repetitions": 0,
            "security_note": (
                "CBC mode: random IV used. Chaining ensures identical plaintext blocks "
                "produce distinct ciphertext blocks. Semantically secure (IND-CPA)."
            ),
        }

    def decrypt(self, ciphertext: bytes, iv: bytes) -> bytes:
        if len(iv) != AES.block_size:
            raise ValueError(f"IV must be {AES.block_size} bytes.")
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded = cipher.decrypt(ciphertext)
        return unpad(padded, AES.block_size)


# ──────────────────────────────────────────────
# CTR Mode
# ──────────────────────────────────────────────

class CTRCipher:
    """
    AES-CTR: Counter Mode

    Turns AES into a stream cipher. Encrypts incrementing counter values
    (nonce ∥ counter) to produce a keystream, then XORs with plaintext.
    No padding required.

    Security properties:
      - Semantically secure (IND-CPA) when nonce is unique per (key, message)
      - Fully parallelizable for both encryption and decryption
      - Supports random-access decryption of any block
      - CRITICAL: Never reuse (key, nonce) — catastrophic plaintext XOR exposure
    """

    def __init__(self, key: bytes):
        validate_key(key)
        self.key = key

    def encrypt(self, plaintext: bytes, nonce: bytes = None) -> dict:
        if nonce is None:
            nonce = generate_iv(8)
        if len(nonce) != 8:
            raise ValueError("CTR nonce must be 8 bytes.")

        cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext)

        blocks = [
            ciphertext[i: i + AES.block_size].hex()
            for i in range(0, len(ciphertext), AES.block_size)
        ]

        return {
            "mode": "CTR",
            "ciphertext": ciphertext,
            "ciphertext_hex": ciphertext.hex(),
            "ciphertext_b64": base64.b64encode(ciphertext).decode(),
            "iv": nonce,
            "iv_hex": nonce.hex(),
            "iv_b64": base64.b64encode(nonce).decode(),
            "blocks": blocks,
            "block_count": len(blocks),
            "plaintext_length": len(plaintext),
            "ciphertext_length": len(ciphertext),
            # Security metadata
            "secure": True,
            "repeated_block_types": 0,
            "leaked_repetitions": 0,
            "security_note": (
                "CTR mode: unique nonce used. Stream cipher output — ciphertext equals "
                "plaintext length. Fully parallelizable. Never reuse (key, nonce)."
            ),
        }

    def decrypt(self, ciphertext: bytes, nonce: bytes) -> bytes:
        if len(nonce) != 8:
            raise ValueError("CTR nonce must be 8 bytes.")
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
        return cipher.decrypt(ciphertext)


# ──────────────────────────────────────────────
# GCM Mode (AEAD)
# ──────────────────────────────────────────────

class GCMCipher:
    """
    AES-GCM: Galois/Counter Mode — Authenticated Encryption with Associated Data (AEAD)

    Combines CTR-mode encryption with GHASH authentication to provide:
      - Confidentiality  (CTR-based stream cipher)
      - Integrity        (128-bit authentication tag via Galois field multiplication)
      - Authenticity     (tag covers both ciphertext and AAD)

    This is the recommended mode for modern secure systems:
      TLS 1.3 (RFC 8446), SSH, IPSec, HTTPS all mandate AES-GCM.

    Security properties:
      - AEAD: single-pass confidentiality + integrity
      - No padding required (stream cipher output)
      - AAD is authenticated but NOT encrypted (e.g., headers, transaction IDs)
      - Fully parallelizable (inherits from CTR)
      - CRITICAL: Never reuse (key, nonce) — tag forgery and plaintext exposure
      - Standard nonce: 96-bit (12 bytes) for optimal GCM performance
    """

    def __init__(self, key: bytes):
        validate_key(key)
        self.key = key

    def encrypt(self, plaintext: bytes, aad: bytes = b"", nonce: bytes = None) -> dict:
        """
        Encrypt and authenticate plaintext with AES-GCM.

        Args:
            plaintext: Bytes to encrypt.
            aad: Additional Authenticated Data — authenticated but not encrypted.
                 Use for metadata (transaction IDs, headers) that must be integrity-protected.
            nonce: Optional 12-byte nonce. If None, a random nonce is generated.
                   NEVER reuse with the same key.

        Returns:
            dict with ciphertext, auth_tag, nonce, and security metadata.
        """
        if nonce is None:
            nonce = generate_iv(12)  # 96-bit recommended for GCM
        if len(nonce) != 12:
            raise ValueError("GCM nonce must be 12 bytes (96-bit).")

        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        return {
            "mode": "GCM",
            "ciphertext": ciphertext,
            "ciphertext_hex": ciphertext.hex(),
            "ciphertext_b64": base64.b64encode(ciphertext).decode(),
            "auth_tag": tag,
            "auth_tag_hex": tag.hex(),
            "auth_tag_b64": base64.b64encode(tag).decode(),
            "auth_tag_bits": len(tag) * 8,
            "iv": nonce,
            "iv_hex": nonce.hex(),
            "iv_b64": base64.b64encode(nonce).decode(),
            "aad": aad,
            "aad_hex": aad.hex() if aad else None,
            "plaintext_length": len(plaintext),
            "ciphertext_length": len(ciphertext),
            # Security metadata
            "secure": True,
            "authenticated": True,
            "security_note": (
                "GCM mode: AEAD — confidentiality + integrity in one pass. "
                "The 128-bit authentication tag detects any modification to the "
                "ciphertext or AAD before decryption. Recommended for all new systems."
            ),
        }

    def decrypt(self, ciphertext: bytes, tag: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
        """
        Decrypt and verify AES-GCM ciphertext.

        Args:
            ciphertext: Encrypted bytes.
            tag: 16-byte authentication tag from encryption.
            nonce: The same 12-byte nonce used during encryption.
            aad: The same AAD bytes used during encryption.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            ValueError: If authentication tag verification fails — data integrity violated.
        """
        if len(nonce) != 12:
            raise ValueError("GCM nonce must be 12 bytes (96-bit).")
        if len(tag) != 16:
            raise ValueError("GCM authentication tag must be 16 bytes (128-bit).")

        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(aad)

        try:
            return cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError as e:
            raise ValueError(
                "GCM authentication failed — ciphertext or AAD has been tampered with. "
                "Decryption aborted to prevent processing of corrupted data."
            ) from e


# ──────────────────────────────────────────────
# Unified Interface
# ──────────────────────────────────────────────

def get_cipher(mode: str, key: bytes):
    """
    Factory — return the appropriate cipher object for the given mode.

    Args:
        mode: 'ECB', 'CBC', 'CTR', or 'GCM' (case-insensitive).
        key: AES key bytes (16, 24, or 32).
    """
    mode = mode.upper()
    ciphers = {
        "ECB": ECBCipher,
        "CBC": CBCCipher,
        "CTR": CTRCipher,
        "GCM": GCMCipher,
    }
    if mode not in ciphers:
        raise ValueError(f"Unsupported mode '{mode}'. Choose ECB, CBC, CTR, or GCM.")
    return ciphers[mode](key)


def encrypt(
    plaintext,
    key: bytes,
    mode: str,
    iv: bytes = None,
    aad: bytes = b"",
) -> dict:
    """
    High-level encrypt function supporting all four AES modes.

    Args:
        plaintext: String or bytes to encrypt.
        key: AES key bytes (16, 24, or 32).
        mode: 'ECB', 'CBC', 'CTR', or 'GCM'.
        iv: Optional IV/nonce (auto-generated if None).
        aad: Additional Authenticated Data for GCM (ignored for other modes).

    Returns:
        Full result dict from the underlying cipher.
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    cipher = get_cipher(mode, key)
    mode_upper = mode.upper()

    if mode_upper == "ECB":
        return cipher.encrypt(plaintext)
    elif mode_upper == "GCM":
        return cipher.encrypt(plaintext, aad=aad, nonce=iv)
    else:
        return cipher.encrypt(plaintext, iv)


def decrypt(
    ciphertext: bytes,
    key: bytes,
    mode: str,
    iv: bytes = None,
    tag: bytes = None,
    aad: bytes = b"",
) -> bytes:
    """
    High-level decrypt function supporting all four AES modes.

    Args:
        ciphertext: Bytes to decrypt.
        key: AES key bytes (16, 24, or 32).
        mode: 'ECB', 'CBC', 'CTR', or 'GCM'.
        iv: IV/nonce (required for CBC, CTR, GCM).
        tag: Authentication tag (required for GCM).
        aad: Additional Authenticated Data (required for GCM if used during encryption).

    Returns:
        Decrypted plaintext bytes.
    """
    cipher = get_cipher(mode, key)
    mode_upper = mode.upper()

    if mode_upper == "ECB":
        return cipher.decrypt(ciphertext)
    elif mode_upper == "GCM":
        if iv is None:
            raise ValueError("GCM mode requires a nonce (iv).")
        if tag is None:
            raise ValueError("GCM mode requires an authentication tag.")
        return cipher.decrypt(ciphertext, tag, iv, aad)
    else:
        if iv is None:
            raise ValueError(f"IV/nonce is required for {mode} mode.")
        return cipher.decrypt(ciphertext, iv)
