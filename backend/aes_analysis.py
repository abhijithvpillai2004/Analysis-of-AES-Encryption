"""
aes_analysis.py
---------------
Performance benchmarking and security analysis for AES modes.

Each public function returns structured results that include:
  - Raw data  (timings, block frequencies, leakage counts)
  - observation  — what was directly measured
  - inference    — the cryptographic reason behind the result
  - conclusion   — the definitive security/performance finding

These fields are surfaced directly by the Flask API and the frontend.
"""

import os
import time
import statistics
from aes_core import encrypt, decrypt, generate_key, generate_iv


# ──────────────────────────────────────────────
# Performance Benchmarking
# ──────────────────────────────────────────────

def benchmark_mode(
    mode: str,
    key: bytes,
    data_size: int,
    iterations: int = 100,
) -> dict:
    """
    Benchmark AES encryption for a single mode and data size.

    Args:
        mode: 'ECB', 'CBC', or 'CTR'.
        key: AES key bytes.
        data_size: Plaintext size in bytes.
        iterations: Number of encryption operations.

    Returns:
        Timing statistics: mean, min, max, stdev, throughput (MB/s).
    """
    plaintext = os.urandom(data_size)
    times = []

    for _ in range(iterations):
        t_start = time.perf_counter()
        encrypt(plaintext, key, mode)
        t_end = time.perf_counter()
        times.append((t_end - t_start) * 1000)  # ms

    mean_ms = statistics.mean(times)
    throughput_mb_s = (data_size / (mean_ms / 1000)) / (1024 * 1024)

    return {
        "mode": mode,
        "data_size_bytes": data_size,
        "iterations": iterations,
        "mean_ms": round(mean_ms, 4),
        "min_ms": round(min(times), 4),
        "max_ms": round(max(times), 4),
        "stdev_ms": round(statistics.stdev(times), 4) if len(times) > 1 else 0.0,
        "throughput_mb_s": round(throughput_mb_s, 2),
    }


def run_full_benchmark(
    data_sizes: list = None,
    iterations: int = 100,
    key_size: int = 32,
) -> dict:
    """
    Benchmark ECB, CBC, and CTR across multiple data sizes.

    Returns per-mode timing stats, a fastest-mode summary, and
    structured academic conclusions (observation / inference / conclusion).

    Args:
        data_sizes: List of plaintext sizes in bytes.
                    Default: [64, 256, 1024, 4096, 65536].
        iterations: Iterations per (mode, size) combination.
        key_size: AES key size in bytes — 16, 24, or 32.
    """
    if data_sizes is None:
        data_sizes = [64, 256, 1024, 4096, 65536]

    key = generate_key(key_size)
    modes = ["ECB", "CBC", "CTR"]

    results = {
        "key_size_bits": key_size * 8,
        "iterations": iterations,
        "modes": {},
    }

    for mode in modes:
        mode_results = []
        for size in data_sizes:
            stats = benchmark_mode(mode, key, size, iterations)
            mode_results.append(stats)
            print(
                f"  {mode} | {size:>6} bytes | {stats['mean_ms']:.4f} ms/op | "
                f"{stats['throughput_mb_s']:.2f} MB/s"
            )
        results["modes"][mode] = mode_results

    # Fastest mode per data size
    summary = []
    for i, size in enumerate(data_sizes):
        times = {m: results["modes"][m][i]["mean_ms"] for m in modes}
        fastest = min(times, key=times.get)
        summary.append({"data_size": size, "fastest_mode": fastest, "times_ms": times})
    results["summary"] = summary

    # ── Academic conclusions ──────────────────
    avg_times = {
        m: round(statistics.mean(r["mean_ms"] for r in results["modes"][m]), 4)
        for m in modes
    }
    fastest_mode = min(avg_times, key=avg_times.get)
    slowest_mode = max(avg_times, key=avg_times.get)
    speedup = round(avg_times[slowest_mode] / avg_times[fastest_mode], 2)

    largest_idx = len(data_sizes) - 1
    tp_largest = {
        m: results["modes"][m][largest_idx]["throughput_mb_s"] for m in modes
    }

    results["conclusions"] = {
        "fastest_mode": fastest_mode,
        "slowest_mode": slowest_mode,
        "average_latency_ms": avg_times,
        "throughput_at_largest_size_mb_s": tp_largest,
        "speedup_ratio": speedup,
        "observation": (
            f"{fastest_mode} achieved the lowest average latency "
            f"({avg_times[fastest_mode]:.4f} ms/op across all sizes). "
            f"{slowest_mode} was slowest at {avg_times[slowest_mode]:.4f} ms/op. "
            f"At {data_sizes[largest_idx]} bytes, throughput: "
            + ", ".join(f"{m} = {tp_largest[m]:.2f} MB/s" for m in modes) + "."
        ),
        "inference": (
            "CTR mode is parallelizable in both directions — the keystream for block N "
            "(computed as AES_K(nonce || N)) is independent of block N-1, enabling "
            "hardware and software pipelines to compute all blocks simultaneously. "
            "CBC encryption is inherently sequential: C_i = AES_K(P_i XOR C_{i-1}) "
            "requires C_{i-1} before C_i can begin, creating a data-dependency chain. "
            "ECB is parallelizable but incurs overhead from block-level cipher creation."
        ),
        "conclusion": (
            f"{fastest_mode} mode provides the best encryption throughput, "
            f"{speedup}x faster than {slowest_mode} on average. "
            "For high-bandwidth applications — TLS, disk encryption, streaming — "
            "CTR or GCM should be chosen over CBC. "
            "Note: performance must never override security — ECB is fast but insecure."
        ),
        "security_note": (
            "ECB's performance advantage is irrelevant given its IND-CPA failure. "
            "GCM adds authenticated encryption at negligible cost versus CTR and is "
            "the recommended default for all new systems."
        ),
    }

    return results


# ──────────────────────────────────────────────
# Pattern Leakage Analysis
# ──────────────────────────────────────────────

def analyze_pattern_leakage(plaintext, key: bytes = None) -> dict:
    """
    Encrypt plaintext with ECB, CBC, and CTR. Analyze ciphertext block
    repetitions to demonstrate ECB's structural leakage weakness.

    Returns raw block-frequency data, per-mode security verdicts, and
    structured academic conclusions.

    Demonstrates ECB's failure under IND-CPA: an adversary can distinguish
    encryptions of structurally different messages purely by observing
    ciphertext block frequencies — without knowing the key.

    Args:
        plaintext: String or bytes — should contain repeating 16-byte blocks
                   to make the ECB weakness clearly visible.
        key: Optional shared AES key. Random 256-bit key if None.
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    if key is None:
        key = generate_key(32)

    mode_results = {}

    for mode in ("ECB", "CBC", "CTR"):
        enc = encrypt(plaintext, key, mode)
        cipher_bytes = enc["ciphertext"]

        blocks = [
            cipher_bytes[i: i + 16].hex()
            for i in range(0, len(cipher_bytes), 16)
        ]

        block_freq: dict = {}
        for b in blocks:
            block_freq[b] = block_freq.get(b, 0) + 1

        duplicate_block_types = {h: c for h, c in block_freq.items() if c > 1}
        leaked_count = sum(c - 1 for c in duplicate_block_types.values())
        leakage_ratio = round(leaked_count / max(len(blocks), 1), 4)

        # Per-mode security verdict and explanation
        if mode == "ECB" and leaked_count > 0:
            security_verdict = "INSECURE"
            security_reason = (
                f"ECB produced {len(duplicate_block_types)} repeated ciphertext block "
                f"type(s) ({leaked_count} total repetitions). "
                "An observer of the ciphertext can identify identical plaintext blocks "
                "without the key — direct IND-CPA violation."
            )
        elif mode == "ECB":
            security_verdict = "CONDITIONALLY SECURE"
            security_reason = (
                "No repeated blocks in this input, but ECB is structurally insecure — "
                "any data with repeating 16-byte aligned patterns will leak."
            )
        else:
            security_verdict = "SECURE"
            security_reason = (
                f"{mode} uses a random IV/nonce so that each block's encryption depends "
                "on unique context. Identical plaintext blocks produce distinct ciphertext "
                "blocks. IND-CPA semantic security is satisfied."
            )

        mode_results[mode] = {
            "mode": mode,
            "total_blocks": len(blocks),
            "unique_blocks": len(block_freq),
            "duplicate_block_types": len(duplicate_block_types),
            "leaked_repetitions": leaked_count,
            "leakage_ratio": leakage_ratio,
            "blocks": blocks,
            "block_frequencies": block_freq,
            "secure": leaked_count == 0,
            "security_verdict": security_verdict,
            "security_reason": security_reason,
            "iv_hex": enc.get("iv_hex"),
            "ciphertext_hex": enc["ciphertext_hex"],
        }

    # Plaintext block structure (reference)
    plain_blocks = [plaintext[i: i + 16].hex() for i in range(0, len(plaintext), 16)]
    plain_freq: dict = {}
    for b in plain_blocks:
        plain_freq[b] = plain_freq.get(b, 0) + 1
    plain_repeated_types = sum(1 for c in plain_freq.values() if c > 1)
    plain_leaked = sum(c - 1 for c in plain_freq.values() if c > 1)

    # ── Academic conclusions ──────────────────
    ecb = mode_results["ECB"]
    cbc = mode_results["CBC"]
    ctr = mode_results["CTR"]

    conclusions = {
        "observation": (
            f"Plaintext had {plain_repeated_types} repeated 16-byte block type(s) "
            f"({plain_leaked} repetitions). "
            f"ECB ciphertext revealed {ecb['duplicate_block_types']} repeated block "
            f"type(s) ({ecb['leaked_repetitions']} repetitions, "
            f"leakage ratio = {ecb['leakage_ratio']:.1%}). "
            f"CBC and CTR revealed {cbc['duplicate_block_types']} and "
            f"{ctr['duplicate_block_types']} repeated blocks respectively."
        ),
        "inference": (
            "ECB applies the same block transformation E_K without any state: "
            "E_K(P) = C is purely deterministic. This makes ECB a block-level "
            "substitution cipher — an attacker observing ciphertext frequencies "
            "learns the plaintext block frequency distribution without any key. "
            "CBC's chaining (C_i = E_K(P_i XOR C_{i-1})) and CTR's counter-based "
            "keystream (C_i = KS_i XOR P_i, where KS_i is unique per position) both "
            "destroy this determinism, hiding structural patterns."
        ),
        "conclusion": (
            "ECB mode is semantically insecure (IND-CPA fails) for any structured data. "
            "The attack demonstrated here requires no key knowledge — only passive "
            "ciphertext observation. CBC and CTR achieve semantic security through "
            "IV/nonce-based randomization. "
            "NIST SP 800-38A restricts ECB to single-block use (e.g., key wrapping). "
            "ECB must never be used for message encryption."
        ),
        "attack_description": (
            "ECB Penguin Attack: when a bitmap image is encrypted with ECB, uniform "
            "color regions produce repeating ciphertext blocks — the image outline "
            "remains visible in the 'encrypted' output. This experiment is equivalent: "
            "repeating protocol fields, form data, or structured records expose the "
            "same structural leak regardless of key secrecy."
        ),
    }

    return {
        "plaintext_hex": plaintext.hex(),
        "plaintext_length": len(plaintext),
        "plaintext_blocks": plain_blocks,
        "plaintext_repeated_block_types": plain_repeated_types,
        "plaintext_leaked_repetitions": plain_leaked,
        "key_hex": key.hex(),
        "modes": mode_results,
        "conclusions": conclusions,
    }


# ──────────────────────────────────────────────
# Classic ECB Demo
# ──────────────────────────────────────────────

def identical_block_demo(key: bytes = None) -> dict:
    """
    Classic ECB pattern leakage demo.
    Plaintext: 4 × block_A + 2 × block_B + 1 × block_C.

    Shows ECB leaking the repetition of the first 4 blocks while
    CBC and CTR produce entirely unique ciphertext block sequences.
    """
    block_A = b"AAAAAAAAAAAAAAAA"
    block_B = b"BBBBBBBBBBBBBBBB"
    block_C = b"CCCCCCCCCCCCCCCC"
    plaintext = block_A * 4 + block_B * 2 + block_C
    return analyze_pattern_leakage(plaintext, key)


# ──────────────────────────────────────────────
# GCM Integrity Demo
# ──────────────────────────────────────────────

def gcm_integrity_demo() -> dict:
    """
    Demonstrate AES-GCM authentication:
      1. Encrypt a message with GCM and record the auth tag.
      2. Flip one byte of the ciphertext.
      3. Attempt decryption — the tag mismatch should be detected.

    Returns structured result with observation / inference / conclusion.
    """
    from aes_core import GCMCipher

    key = generate_key(32)
    plaintext = b"Authenticated record: account balance = $9999"
    aad = b"transaction-id:TXN-20240417"

    cipher = GCMCipher(key)
    enc = cipher.encrypt(plaintext, aad=aad)

    # Legitimate decryption
    legit_ok = False
    try:
        recovered = cipher.decrypt(enc["ciphertext"], enc["auth_tag"], enc["iv"], aad)
        legit_ok = (recovered == plaintext)
    except ValueError:
        pass

    # Tampered ciphertext: flip byte at index 5
    tampered = bytearray(enc["ciphertext"])
    tampered[5] ^= 0xFF
    tamper_detected = False
    try:
        cipher.decrypt(bytes(tampered), enc["auth_tag"], enc["iv"], aad)
    except ValueError:
        tamper_detected = True

    return {
        "original_plaintext": plaintext.decode(),
        "aad": aad.decode(),
        "ciphertext_hex": enc["ciphertext_hex"],
        "auth_tag_hex": enc["auth_tag_hex"],
        "iv_hex": enc["iv_hex"],
        "legitimate_decryption_succeeded": legit_ok,
        "tamper_detected": tamper_detected,
        "conclusions": {
            "observation": (
                f"Legitimate decryption {'succeeded' if legit_ok else 'failed unexpectedly'}. "
                f"After modifying 1 byte of the ciphertext, decryption was "
                f"{'rejected — authentication tag mismatch' if tamper_detected else 'incorrectly accepted'}."
            ),
            "inference": (
                "GCM's authentication tag is GHASH(H, AAD, ciphertext) XOR E_K(J0), "
                "where H = E_K(0) and J0 is derived from the nonce. "
                "Any modification to the ciphertext or AAD changes the GHASH value, "
                "making the computed tag differ from the stored tag. "
                "Decryption is aborted before any plaintext is produced."
            ),
            "conclusion": (
                "AES-GCM provides AEAD — confidentiality and integrity in a single pass. "
                "A single flipped bit is detected with probability 1 - 2^-128 (effectively certain). "
                "This eliminates padding oracle and bit-flip attacks inherent in CBC, "
                "and is why GCM is mandated in TLS 1.3 (RFC 8446)."
            ),
        },
    }


if __name__ == "__main__":
    print("=" * 60)
    print("AES MODE BENCHMARKS")
    print("=" * 60)
    bench = run_full_benchmark(iterations=50)
    c = bench["conclusions"]
    print(f"\nObservation : {c['observation']}")
    print(f"Conclusion  : {c['conclusion']}")

    print("\n" + "=" * 60)
    print("PATTERN LEAKAGE DEMO")
    print("=" * 60)
    demo = identical_block_demo()
    for mode, data in demo["modes"].items():
        print(f"  {mode}: {data['security_verdict']} — "
              f"{data['duplicate_block_types']} duplicate types, "
              f"{data['leaked_repetitions']} leaked repetitions")
    print(f"\nConclusion: {demo['conclusions']['conclusion']}")

    print("\n" + "=" * 60)
    print("GCM INTEGRITY DEMO")
    print("=" * 60)
    gcm = gcm_integrity_demo()
    print(f"  Legitimate decryption : {'OK' if gcm['legitimate_decryption_succeeded'] else 'FAILED'}")
    print(f"  Tamper detection      : {'DETECTED' if gcm['tamper_detected'] else 'MISSED'}")
    print(f"\nConclusion: {gcm['conclusions']['conclusion']}")
