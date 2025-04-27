# Remote Document Access

> Secure cloud storage & sharing with end‑to‑end encryption and user‑centric key management.

## Contributors
João Meira (meiraxx)
José Brás (sneakyjbras)

## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Security Details](#security-details)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Introduction
Remote Document Access (RDA) is a self‑hosted service that lets you store, access, and share files with strong privacy guarantees. All cryptographic operations happen on the client, so your data is never exposed in plaintext—even to the server operator.

## Features
- **End‑to‑End Encryption** – Files are encrypted client‑side and decrypted only on the recipient’s device.  
- **User‑Owned Keys** – Each user keeps their private key locally; the server stores only public keys.  
- **Digital Signatures** – Every file is signed so recipients can verify its integrity and origin.  
- **Mutual TLS** – SSL/TLS with client certificates blocks man‑in‑the‑middle attacks.  
- **Granular Sharing** – Share read‑only or read/write links with specific users or groups.  
- **Revocation** – Instantly revoke shared access without re‑uploading data.

## Architecture
```
client ─┬─► (encrypt + sign) ─┬─► server (store ciphertext)
        │                     └─► other clients (share)
        └── (decrypt + verify) ◄─┘
```

## Quick Start
### Prerequisites
- **Server:** Python 3.11+, PostgreSQL 15+, OpenSSL 1.1+  
- **Client:** Python 3.11+ (or packaged desktop app), OpenSSL, `pipx` (optional)

> Detailed setup guides live in `/server/README.md` and `/client/README.md`.

### 1. Clone the repo
```bash
git clone https://github.com/your-org/remote-document-access.git
cd remote-document-access
```

### 2. Launch the server (development)
```bash
cd server
cp .env.example .env
docker compose up -d
```

### 3. Initialise a client
```bash
cd ../client
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python rda.py init
```

### 4. Upload a file
```bash
python rda.py upload /path/to/file.pdf
```

## Project Structure
```
remote-document-access/
├─ client/         # Client‑side app (CLI + optional GUI)
├─ server/         # REST/GraphQL backend & key‑management
├─ docs/           # Additional documentation
└─ scripts/        # DevOps helpers
```

## Security Details
- **Encryption:** AES‑256‑GCM for file content; RSA‑4096 (or Ed25519) for key wrapping and signatures.
- **Transport:** TLS 1.3 with mutual authentication.
- **Key Backup:** Encrypted recovery bundle can be exported by the user (optional, off by default).

## Roadmap
- [ ] Mobile client (iOS / Android)  
- [ ] Web‑based file viewer  
- [ ] Hardware token support (FIDO2)

## Contributing
1. Fork the project and create your feature branch (`git checkout -b feat/awesome`).
2. Commit your changes (`git commit -m 'Add awesome feature'`).
3. Push to the branch (`git push origin feat/awesome`) and open a pull request.

## License
This project is licensed under the MIT License – see the `LICENSE` file for details.

