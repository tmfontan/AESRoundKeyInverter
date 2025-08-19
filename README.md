<h1 align="center">AES-128 Inverse Key Expansion & Forensic Analysis Tool</h1>

<p align="center">
  <img src="Images/Logos/AES-128_logo.png" alt="AES-128 Tool Logo" width="1200"/>
</p>

[![Java](https://img.shields.io/badge/Java-8%2B-blue.svg)](https://www.oracle.com/java/technologies/javase-downloads.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Last Commit](https://img.shields.io/github/last-commit/tmfontan/AESRoundKeyInverter)](https://github.com/tmfontan/AESRoundKeyInverter/commits/main)
[![Repo Size](https://img.shields.io/github/repo-size/tmfontan/AESRoundKeyInverter)](https://github.com/tmfontan/AESRoundKeyInverter)
[![Open Issues](https://img.shields.io/github/issues/tmfontan/AESRoundKeyInverter)](https://github.com/tmfontan/AESRoundKeyInverter/issues)

A **Java-based cryptographic utility** that reverses the **AES-128 round key generation process** to reconstruct the **original 128-bit encryption key** and all previously generated round keys. Designed for **cryptographic research, forensic analysis, debugging, and educational purposes**.

---

## 📑 Table of Contents

* [📖 Overview](#-overview)
* [✨ Features](#-features)
* [🚀 Getting Started](#-getting-started)
* [⚡ Usage](#-usage)
* [📘 How It Works](#-how-it-works)
* [🛠️ Project Structure](#-project-structure)
* [🗺️ Roadmap](#-roadmap)
* [🤝 Contributing](#-contributing)
* [📜 License](#-license)

---

## 📖 Overview

AES-128 uses a key schedule to generate a series of round keys from the original 128-bit key. This tool performs the **inverse key expansion** process, allowing users to:

* Reconstruct the **original AES-128 key** from the final round key.
* Retrieve **all 10 round keys** used in AES-128 encryption.
* Analyze AES key scheduling for research and educational purposes.

---

## ✨ Features

* **Inverse Key Expansion** – Reverses the AES-128 key schedule.
* **Custom RoundKey Object** – Stores round number and corresponding byte array for clean organization.
* **Forensic & Educational Applications** – Supports learning, validating, and investigating cryptographic systems.

---

## 🚀 Getting Started

### Prerequisites

* **Java JDK 8+**
* Basic knowledge of AES key scheduling (recommended)

### Installation

```bash
git clone https://github.com/tmfontan/AESRoundKeyInverter.git
cd AESRoundKeyInverter
```

### Compilation

```bash
javac RoundKey.java InverseKeyGeneration.java
```

### Execution

```bash
java InverseKeyGeneration
```

---

## ⚡ Usage

The tool prompts for input key data or round keys, then reconstructs:

* The **original AES-128 encryption key**
* All **10 round keys** used in the AES-128 encryption process

**Example Output:**

```bash
Original Key:  2b7e151628aed2a6abf7158809cf4f3c
Round Key 1:   a0fafe1788542cb123a339392a6c7605
Round Key 2:   f2c295f27a96b9435935807a7359f67f
...
Round Key 10:  d014f9a8c9ee2589e13f0cc8b6630ca6
```

---

## 📘 How It Works

AES-128 performs key expansion to derive round keys:

**Key Expansion (Forward):**

```
Original Key --> Round Key 1 --> Round Key 2 --> ... --> Round Key 10
```

**Inverse Expansion (This Tool):**

```
Round Key 10 --> Round Key 9 --> ... --> Original Key
```

**Diagram:**

![Tutorial Diagram](https://github.com/tmfontan/AESRoundKeyInverter/blob/main/Inverse%20Round%20Key%20Diagram.png)

---

## 🛠️ Project Structure

* **[RoundKey.java](https://github.com/tmfontan/AESRoundKeyInverter/blob/main/src/RoundKey.java)** – Defines the data structure for holding round numbers and their byte arrays.
* **[InverseKeyGeneration.java](https://github.com/tmfontan/AESRoundKeyInverter/blob/main/src/InverseKeyGeneration.java)** – Contains the logic for reversing AES-128 key scheduling and retrieving the original key.

---

## 🗺️ Roadmap

Planned enhancements and future improvements:

* [ ] Add **support for AES-192 and AES-256** key inversion.
* [ ] Implement a **GUI version** for easier visualization.
* [ ] Provide **unit tests** for improved reliability.
* [ ] Add **export functionality** to save reconstructed keys.
* [ ] Include **performance benchmarks**.

---

## 🤝 Contributing

Contributions are welcome! To get started:

1. Fork the repository.
2. Create a new branch: `git checkout -b feature-name`.
3. Make your changes and commit: `git commit -m "Add feature"`.
4. Push to your branch: `git push origin feature-name`.
5. Submit a pull request.

Please ensure your contributions align with the project’s coding standards and include updates to documentation if necessary.

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

---

## ⚠️ Disclaimer

This project is intended solely for **educational and authorized security testing purposes**.
Do **not** use it for unauthorized access, decryption, or illegal activities.
