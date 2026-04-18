# AES Cipher Lab
**Team:** 23BAI1346 Kishen P Vijayan · 23BAI1318 Abhijith V Pillai

Implementation and performance analysis of AES encryption with ECB, CBC, and CTR modes of operation.

---

## Project Structure

```
aes_project/
├── backend/
│   ├── aes_core.py        ← Core AES encrypt/decrypt (ECB, CBC, CTR)
│   ├── aes_analysis.py    ← Performance benchmarking + pattern analysis
│   ├── app.py             ← Flask REST API
│   ├── test_aes.py        ← Pytest unit tests (45+ test cases)
│   └── requirements.txt
└── frontend/
    └── index.html         ← Standalone interactive web app
```

---

## Backend Setup

### 1. Install dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Run the Flask API

```bash
python app.py
```

The API starts at `http://localhost:5000`.

### 3. Run unit tests

```bash
pytest test_aes.py -v
```

---

## Frontend Usage

Open `frontend/index.html` in any modern browser — no build step required.

Switch between **Browser** (Web Crypto API) and **API** (Flask backend) modes using the toggle in the top-right corner. The API mode requires the Flask server to be running.

---

## API Reference

### `GET /api/health`
Health check. Returns `{ "status": "ok" }`.

---

### `POST /api/keygen`
Generate a random AES key.

**Request:**
```json
{ "key_size": 32 }
```

**Response:**
```json
{
  "key_hex": "3f2a1b...",
  "key_b64": "Pyo...",
  "key_size_bytes": 32,
  "key_size_bits": 256
}
```

---

### `POST /api/encrypt`
Encrypt plaintext with AES.

**Request:**
```json
{
  "plaintext": "Hello, World!",
  "key_hex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "mode": "CBC",
  "iv_hex": ""
}
```

**Response:**
```json
{
  "mode": "CBC",
  "ciphertext_hex": "a3f1...",
  "ciphertext_b64": "o/E...",
  "iv_hex": "c2d4...",
  "iv_b64": "wtQ...",
  "blocks": ["a3f1...", "b2e0...", "..."],
  "block_count": 1,
  "plaintext_length": 13,
  "ciphertext_length": 16
}
```

---

### `POST /api/decrypt`
Decrypt AES ciphertext.

**Request:**
```json
{
  "ciphertext_hex": "a3f1...",
  "key_hex": "0123...",
  "mode": "CBC",
  "iv_hex": "c2d4..."
}
```

**Response:**
```json
{
  "plaintext": "Hello, World!",
  "plaintext_hex": "48656c6c6f...",
  "mode": "CBC"
}
```

---

### `POST /api/pattern`
Analyse ECB pattern leakage across all three modes.

**Request:**
```json
{
  "plaintext": "AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA BBBBBBBBBBBBBBBB"
}
```

**Response** includes per-mode `blocks`, `duplicate_block_types`, `leaked_repetitions`, `secure` flag.

---

### `POST /api/benchmark`
Run a performance benchmark.

**Request:**
```json
{
  "data_sizes": [64, 256, 1024, 4096],
  "iterations": 50,
  "key_size": 32
}
```

**Response** includes per-mode timing stats (`mean_ms`, `min_ms`, `max_ms`, `throughput_mb_s`) and a `summary` of the fastest mode per data size.

---

## Module Overview

### `aes_core.py`

| Class / Function | Description |
|---|---|
| `ECBCipher` | AES-ECB encrypt/decrypt with PKCS7 padding |
| `CBCCipher` | AES-CBC with random IV generation |
| `CTRCipher` | AES-CTR stream cipher mode |
| `encrypt()` | Unified high-level encrypt (str or bytes) |
| `decrypt()` | Unified high-level decrypt |
| `generate_key()` | Secure random key (128/192/256-bit) |

### `aes_analysis.py`

| Function | Description |
|---|---|
| `benchmark_mode()` | Benchmark single mode at a given data size |
| `run_full_benchmark()` | Full benchmark across all modes and sizes |
| `analyze_pattern_leakage()` | Detect pattern leakage across ECB/CBC/CTR |
| `identical_block_demo()` | Classic ECB weakeness demonstration |

---

## Security Notes

| Mode | Secure? | Key takeaway |
|---|---|---|
| ECB | No | Never use for data with repeating structure |
| CBC | Yes | Use a fresh random IV per message |
| CTR | Yes | Never reuse (key, nonce) pair |

---

## References

1. William Stallings, *Cryptography and Network Security*, Pearson Education
2. NIST FIPS 197 — Advanced Encryption Standard
3. PyCryptodome Documentation — AES Modes of Operation
4. NIST SP 800-38A — Recommendation for Block Cipher Modes of Operation
