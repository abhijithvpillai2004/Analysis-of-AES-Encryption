"""
test_aes.py
-----------
Unit tests for the AES Cryptography Analysis Platform.

Coverage:
  - Key & IV generation
  - ECB, CBC, CTR encrypt/decrypt round-trips
  - GCM encrypt/decrypt/tamper detection
  - Unified interface (encrypt / decrypt)
  - Pattern leakage analysis (including conclusions dict)
  - Benchmarking (structure validation)

Run:
    python -m pytest test_aes.py -v
"""

import pytest
import base64
from aes_core import (
    ECBCipher, CBCCipher, CTRCipher, GCMCipher,
    encrypt, decrypt,
    generate_key, generate_iv,
    get_cipher,
)
from aes_analysis import (
    analyze_pattern_leakage,
    benchmark_mode,
    identical_block_demo,
    gcm_integrity_demo,
)


# ──────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────

@pytest.fixture
def key_128():
    return bytes.fromhex("0123456789abcdef0123456789abcdef")

@pytest.fixture
def key_256():
    return generate_key(32)

PLAINTEXTS = [
    b"Hello, World!",
    b"A" * 16,
    b"A" * 32,
    b"A" * 33,
    b"\x00" * 64,
    "Unicode: \u00e9\u00e0\u00fc".encode("utf-8"),
]


# ──────────────────────────────────────────────
# Key generation
# ──────────────────────────────────────────────

class TestKeyGeneration:
    def test_key_128(self):
        assert len(generate_key(16)) == 16

    def test_key_192(self):
        assert len(generate_key(24)) == 24

    def test_key_256(self):
        assert len(generate_key(32)) == 32

    def test_invalid_key_size(self):
        with pytest.raises(ValueError):
            generate_key(10)

    def test_keys_are_random(self):
        assert generate_key(32) != generate_key(32)

    def test_iv_default_length(self):
        assert len(generate_iv()) == 16

    def test_iv_custom_length(self):
        assert len(generate_iv(12)) == 12


# ──────────────────────────────────────────────
# ECB mode
# ──────────────────────────────────────────────

class TestECB:
    def test_encrypt_decrypt_roundtrip(self, key_128):
        c = ECBCipher(key_128)
        for pt in PLAINTEXTS:
            result = c.encrypt(pt)
            assert c.decrypt(result["ciphertext"]) == pt

    def test_no_iv(self, key_128):
        result = ECBCipher(key_128).encrypt(b"Test block data.")
        assert result["iv"] is None
        assert result["iv_hex"] is None

    def test_identical_blocks_produce_identical_ciphertext(self, key_128):
        """Core ECB weakness: same plaintext block → same ciphertext block."""
        result = ECBCipher(key_128).encrypt(b"A" * 64)
        # All four 16-byte blocks must be identical
        assert len(set(result["blocks"])) == 1

    def test_leakage_metadata_present(self, key_128):
        result = ECBCipher(key_128).encrypt(b"A" * 48)
        assert "leaked_repetitions" in result
        assert "repeated_block_types" in result
        assert result["leaked_repetitions"] > 0

    def test_result_structure(self, key_128):
        r = ECBCipher(key_128).encrypt(b"Test input data!")
        assert r["mode"] == "ECB"
        for field in ("ciphertext_hex", "ciphertext_b64", "block_count", "secure"):
            assert field in r

    def test_invalid_key(self):
        with pytest.raises(ValueError):
            ECBCipher(b"short")

    def test_ciphertext_length_is_multiple_of_16(self, key_128):
        c = ECBCipher(key_128)
        for pt in [b"a", b"a" * 15, b"a" * 16, b"a" * 17]:
            assert len(c.encrypt(pt)["ciphertext"]) % 16 == 0


# ──────────────────────────────────────────────
# CBC mode
# ──────────────────────────────────────────────

class TestCBC:
    def test_encrypt_decrypt_roundtrip(self, key_256):
        c = CBCCipher(key_256)
        for pt in PLAINTEXTS:
            result = c.encrypt(pt)
            assert c.decrypt(result["ciphertext"], result["iv"]) == pt

    def test_random_iv_generated(self, key_256):
        c = CBCCipher(key_256)
        r1 = c.encrypt(b"Same plaintext!!")
        r2 = c.encrypt(b"Same plaintext!!")
        assert r1["iv"] != r2["iv"]
        assert r1["ciphertext"] != r2["ciphertext"]

    def test_custom_iv(self, key_256):
        iv = generate_iv(16)
        result = CBCCipher(key_256).encrypt(b"Test block here!", iv)
        assert result["iv"] == iv

    def test_identical_blocks_produce_different_ciphertext(self, key_256):
        """CBC must not leak block repetitions."""
        result = CBCCipher(key_256).encrypt(b"A" * 64)
        assert len(set(result["blocks"])) > 1

    def test_invalid_iv_length(self, key_256):
        with pytest.raises(ValueError):
            CBCCipher(key_256).encrypt(b"data", iv=b"short")

    def test_secure_flag_set(self, key_256):
        result = CBCCipher(key_256).encrypt(b"A" * 64)
        assert result["secure"] is True

    def test_result_has_iv_fields(self, key_256):
        r = CBCCipher(key_256).encrypt(b"Check IV fields!!")
        assert "iv_hex" in r
        assert "iv_b64" in r
        assert len(r["iv"]) == 16


# ──────────────────────────────────────────────
# CTR mode
# ──────────────────────────────────────────────

class TestCTR:
    def test_encrypt_decrypt_roundtrip(self, key_256):
        c = CTRCipher(key_256)
        for pt in PLAINTEXTS:
            result = c.encrypt(pt)
            assert c.decrypt(result["ciphertext"], result["iv"]) == pt

    def test_no_padding_needed(self, key_256):
        """CTR is a stream cipher — ciphertext length equals plaintext length."""
        c = CTRCipher(key_256)
        for length in range(1, 35):
            pt = bytes(range(length))
            assert len(c.encrypt(pt)["ciphertext"]) == length

    def test_different_nonces_give_different_ciphertexts(self, key_256):
        c = CTRCipher(key_256)
        r1 = c.encrypt(b"Test data here!!")
        r2 = c.encrypt(b"Test data here!!")
        assert r1["ciphertext"] != r2["ciphertext"]

    def test_invalid_nonce_length(self, key_256):
        with pytest.raises(ValueError):
            CTRCipher(key_256).encrypt(b"data", nonce=b"short")

    def test_identical_blocks_produce_different_ciphertext(self, key_256):
        result = CTRCipher(key_256).encrypt(b"A" * 64)
        assert len(set(result["blocks"])) > 1

    def test_secure_flag_set(self, key_256):
        result = CTRCipher(key_256).encrypt(b"A" * 64)
        assert result["secure"] is True


# ──────────────────────────────────────────────
# GCM mode (AEAD)
# ──────────────────────────────────────────────

class TestGCM:
    def test_encrypt_decrypt_roundtrip(self, key_256):
        c = GCMCipher(key_256)
        for pt in PLAINTEXTS:
            enc = c.encrypt(pt)
            dec = c.decrypt(enc["ciphertext"], enc["auth_tag"], enc["iv"])
            assert dec == pt

    def test_roundtrip_with_aad(self, key_256):
        c = GCMCipher(key_256)
        pt = b"Secret message"
        aad = b"transaction-id:TXN-001"
        enc = c.encrypt(pt, aad=aad)
        dec = c.decrypt(enc["ciphertext"], enc["auth_tag"], enc["iv"], aad)
        assert dec == pt

    def test_no_padding_needed(self, key_256):
        """GCM is a stream cipher — no padding."""
        c = GCMCipher(key_256)
        for length in range(1, 35):
            pt = bytes(range(length))
            assert len(c.encrypt(pt)["ciphertext"]) == length

    def test_auth_tag_present_and_correct_length(self, key_256):
        enc = GCMCipher(key_256).encrypt(b"test")
        assert "auth_tag" in enc
        assert len(enc["auth_tag"]) == 16
        assert enc["auth_tag_bits"] == 128

    def test_tamper_ciphertext_raises(self, key_256):
        """Tampering with ciphertext must cause authentication failure."""
        c = GCMCipher(key_256)
        enc = c.encrypt(b"Critical data")
        tampered = bytearray(enc["ciphertext"])
        tampered[0] ^= 0xFF
        with pytest.raises(ValueError, match="[Aa]uthenticat"):
            c.decrypt(bytes(tampered), enc["auth_tag"], enc["iv"])

    def test_tamper_aad_raises(self, key_256):
        """Tampering with AAD must cause authentication failure."""
        c = GCMCipher(key_256)
        aad = b"original-aad"
        enc = c.encrypt(b"Message", aad=aad)
        with pytest.raises(ValueError):
            c.decrypt(enc["ciphertext"], enc["auth_tag"], enc["iv"], b"modified-aad")

    def test_wrong_tag_raises(self, key_256):
        """Wrong authentication tag must be rejected."""
        c = GCMCipher(key_256)
        enc = c.encrypt(b"test")
        bad_tag = bytes(16)  # all-zero tag
        with pytest.raises(ValueError):
            c.decrypt(enc["ciphertext"], bad_tag, enc["iv"])

    def test_invalid_nonce_length(self, key_256):
        with pytest.raises(ValueError):
            GCMCipher(key_256).encrypt(b"data", nonce=b"short")

    def test_invalid_tag_length_on_decrypt(self, key_256):
        c = GCMCipher(key_256)
        enc = c.encrypt(b"test")
        with pytest.raises(ValueError):
            c.decrypt(enc["ciphertext"], b"shorttag", enc["iv"])

    def test_authenticated_flag(self, key_256):
        enc = GCMCipher(key_256).encrypt(b"test")
        assert enc["authenticated"] is True

    def test_different_nonces_give_different_ciphertexts(self, key_256):
        c = GCMCipher(key_256)
        r1 = c.encrypt(b"Same plaintext!!")
        r2 = c.encrypt(b"Same plaintext!!")
        assert r1["ciphertext"] != r2["ciphertext"]
        assert r1["auth_tag"] != r2["auth_tag"]


# ──────────────────────────────────────────────
# Unified interface
# ──────────────────────────────────────────────

class TestUnifiedInterface:
    @pytest.mark.parametrize("mode", ["ECB", "CBC", "CTR"])
    def test_string_plaintext_accepted(self, mode, key_256):
        result = encrypt("hello world", key_256, mode)
        assert "ciphertext_hex" in result

    @pytest.mark.parametrize("mode", ["ECB", "CBC", "CTR"])
    def test_roundtrip(self, mode, key_256):
        plaintext = "Round-trip test message!"
        enc = encrypt(plaintext, key_256, mode)
        dec = decrypt(enc["ciphertext"], key_256, mode, enc.get("iv"))
        assert dec.decode("utf-8") == plaintext

    def test_gcm_roundtrip_via_unified(self, key_256):
        plaintext = "GCM round-trip test"
        enc = encrypt(plaintext, key_256, "GCM", aad=b"header")
        dec = decrypt(
            enc["ciphertext"], key_256, "GCM",
            iv=enc["iv"], tag=enc["auth_tag"], aad=b"header"
        )
        assert dec.decode("utf-8") == plaintext

    def test_invalid_mode_raises(self, key_256):
        with pytest.raises(ValueError):
            get_cipher("XTS", key_256)

    def test_cbc_requires_iv_on_decrypt(self, key_256):
        enc = encrypt("test data", key_256, "CBC")
        with pytest.raises(ValueError):
            decrypt(enc["ciphertext"], key_256, "CBC", iv=None)

    def test_gcm_requires_iv_on_decrypt(self, key_256):
        enc = encrypt("test data", key_256, "GCM")
        with pytest.raises(ValueError):
            decrypt(enc["ciphertext"], key_256, "GCM", iv=None, tag=enc["auth_tag"])

    def test_gcm_requires_tag_on_decrypt(self, key_256):
        enc = encrypt("test data", key_256, "GCM")
        with pytest.raises(ValueError):
            decrypt(enc["ciphertext"], key_256, "GCM", iv=enc["iv"], tag=None)


# ──────────────────────────────────────────────
# Pattern leakage analysis
# ──────────────────────────────────────────────

class TestPatternAnalysis:
    def test_ecb_leaks_patterns(self, key_256):
        result = analyze_pattern_leakage("A" * 64, key_256)
        ecb = result["modes"]["ECB"]
        assert not ecb["secure"]
        assert ecb["duplicate_block_types"] > 0
        assert ecb["leaked_repetitions"] > 0
        assert ecb["security_verdict"] == "INSECURE"

    def test_cbc_no_leakage(self, key_256):
        result = analyze_pattern_leakage("A" * 64, key_256)
        cbc = result["modes"]["CBC"]
        assert cbc["secure"]
        assert cbc["duplicate_block_types"] == 0
        assert cbc["security_verdict"] == "SECURE"

    def test_ctr_no_leakage(self, key_256):
        result = analyze_pattern_leakage("A" * 64, key_256)
        ctr = result["modes"]["CTR"]
        assert ctr["secure"]
        assert ctr["duplicate_block_types"] == 0
        assert ctr["security_verdict"] == "SECURE"

    def test_result_has_all_modes(self, key_256):
        result = analyze_pattern_leakage("test " * 20, key_256)
        for mode in ("ECB", "CBC", "CTR"):
            assert mode in result["modes"]

    def test_conclusions_dict_present(self, key_256):
        result = analyze_pattern_leakage("A" * 64, key_256)
        c = result["conclusions"]
        for field in ("observation", "inference", "conclusion", "attack_description"):
            assert field in c
            assert isinstance(c[field], str)
            assert len(c[field]) > 20

    def test_plaintext_metadata_present(self, key_256):
        result = analyze_pattern_leakage("A" * 64, key_256)
        assert "plaintext_repeated_block_types" in result
        assert "plaintext_leaked_repetitions" in result
        assert result["plaintext_length"] == 64

    def test_auto_key_generation(self):
        result = analyze_pattern_leakage("AAAAAAAAAAAAAAAA" * 3)
        assert "key_hex" in result
        assert len(bytes.fromhex(result["key_hex"])) == 32

    def test_identical_block_demo(self):
        demo = identical_block_demo()
        assert not demo["modes"]["ECB"]["secure"]
        assert demo["modes"]["CBC"]["secure"]
        assert demo["modes"]["CTR"]["secure"]

    def test_security_reason_present(self, key_256):
        result = analyze_pattern_leakage("A" * 64, key_256)
        for mode_data in result["modes"].values():
            assert "security_reason" in mode_data
            assert len(mode_data["security_reason"]) > 10

    def test_leakage_ratio(self, key_256):
        result = analyze_pattern_leakage("A" * 64, key_256)
        ecb = result["modes"]["ECB"]
        assert 0 < ecb["leakage_ratio"] <= 1.0


# ──────────────────────────────────────────────
# GCM integrity demo
# ──────────────────────────────────────────────

class TestGCMIntegrityDemo:
    def test_legitimate_decryption_succeeds(self):
        result = gcm_integrity_demo()
        assert result["legitimate_decryption_succeeded"] is True

    def test_tamper_is_detected(self):
        result = gcm_integrity_demo()
        assert result["tamper_detected"] is True

    def test_conclusions_present(self):
        result = gcm_integrity_demo()
        c = result["conclusions"]
        for field in ("observation", "inference", "conclusion"):
            assert field in c
            assert len(c[field]) > 20


# ──────────────────────────────────────────────
# Benchmarking
# ──────────────────────────────────────────────

class TestBenchmark:
    @pytest.mark.parametrize("mode", ["ECB", "CBC", "CTR"])
    def test_benchmark_mode_structure(self, mode, key_256):
        result = benchmark_mode(mode, key_256, data_size=64, iterations=5)
        assert result["mode"] == mode
        assert result["mean_ms"] > 0
        assert result["throughput_mb_s"] > 0
        for field in ("min_ms", "max_ms", "stdev_ms"):
            assert field in result

    def test_full_benchmark_conclusions(self, key_256):
        from aes_analysis import run_full_benchmark
        results = run_full_benchmark(data_sizes=[64, 256], iterations=5, key_size=32)
        c = results["conclusions"]
        for field in ("fastest_mode", "slowest_mode", "observation", "inference",
                      "conclusion", "security_note", "speedup_ratio"):
            assert field in c
        assert c["fastest_mode"] in ("ECB", "CBC", "CTR")
        assert c["speedup_ratio"] > 0
