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

Example Output (simplified):

Project Structure

- RoundKey.java – Defines a data structure for holding round numbers and their byte array values.

- InverseKeyGeneration.java – Contains the logic to reverse AES-128 key scheduling and retrieve the original key.

Prerequisites

- Java 8+

- Basic understanding of AES encryption and key scheduling (recommended but not required).
