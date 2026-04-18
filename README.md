AES Encryption with Different Modes of Operation
Overview
This project implements and compares three AES modes of operation — ECB, CBC, and CTR — analyzing their security properties and performance across different data sizes.
Security Demonstration

Encrypts identical plaintext blocks across all three modes
Demonstrates pattern leakage in ECB mode (identical blocks → identical ciphertext)
Confirms CBC and CTR prevent pattern leakage through chaining and counter mechanisms

Modes Implemented

ECB (Electronic Codebook) — independent block encryption, insecure for multi-block data
CBC (Cipher Block Chaining) — IV-based chaining, eliminates pattern leakage
CTR (Counter Mode) — stream cipher variant, no padding required, fully parallelisable

Performance Analysis

Benchmarked encryption and decryption times across small, medium, and large datasets
Results presented using comparison tables and Matplotlib graphs
CTR and CBC show comparable throughput with significantly better security than ECB

Tech Stack
Python, PyCryptodome, NumPy, Matplotlib

Authors
Abhijith V Pillai
Kishen P Vijayan
