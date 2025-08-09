# AES-128 Inverse Key Expansion & Forensic Analysis Tool

![Project Logo](https://github.com/tmfontan/AESRoundKeyInverter/blob/main/AES-128.svg)

A Java-based cryptographic utility that **reverses the AES-128 round key generation process** to reconstruct the **original 128-bit encryption key** and all previously generated round keys. This project is designed for **cryptographic research, forensic analysis, debugging, and educational purposes**.

---

## Features

- **Inverse Key Expansion** – Retrieves the original AES-128 key and every round key from an existing key schedule.
- **Custom Round Key Data Structure** – Implements a dedicated `RoundKey` object to store the round number and corresponding byte array for clean organization and easy retrieval.
- **Forensic & Educational Applications** – Supports learning, validating encryption processes, and investigating cryptographic key handling in systems.

---

## Installation

1. **Clone the Repository**
   
   ```bash
   git clone https://github.com/your-username/aes-inverse-key-expansion.git
   
   cd aes-inverse-key-expansion

2. **Compile the Source Code**
   
   ```bash
   javac RoundKey.java InverseKeyGeneration.java

3. **Run The Application**
   
   ```bash
   java InverseKeyGeneration

---

## Usage
The tool prompts for input key data or round keys (depending on your implementation), then reconstructs:

- The original AES-128 encryption key.
- All 10 round keys used in the AES-128 encryption process.

**Example Output (simplified):**

```bash
   Original Key:  2b7e151628aed2a6abf7158809cf4f3c
   Round Key 1:   a0fafe1788542cb123a339392a6c7605
   Round Key 2:   f2c295f27a96b9435935807a7359f67f
   ...
   Round Key 10:  d014f9a8c9ee2589e13f0cc8b6630ca6
```

---

## How It Works

AES-128 uses a key schedule to generate a series of round keys from the original 128-bit key.
This tool reverses that process to recover the original key.

**Key Expansion (Forward):**

```bash
   Original Key --> Round Key 1 --> Round Key 2 --> ... --> Round Key 10
```

**Inverse Key Expansion (This Tool):**

```bash
   Round Key 10 --> Round Key 9 --> ... --> Original Key
```

**Diagram:**

![Tutorial Diagram](https://github.com/tmfontan/AESRoundKeyInverter/blob/main/Inverse%20Round%20Key%20Diagram.png)

---

## Project Structure

- **RoundKey.java** – Defines a data structure for holding round numbers and their byte array values.
- **InverseKeyGeneration.java** – Contains the logic to reverse AES-128 key scheduling and retrieve the original key.

---

## Prerequisites

- Java 8+
- Basic understanding of AES encryption and key scheduling (recommended but not required).
  
---

## Disclaimer

*This project is intended solely for educational and authorized security testing purposes.*
*Do not use it for unauthorized access, decryption, or any illegal activities.*
