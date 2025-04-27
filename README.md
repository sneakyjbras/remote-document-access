# Remote Document Access

**Project IDs:** [João Meira](github.com/meiraxx) · [José Brás](github.com/sneakyjbras)

## Objective
Provide clients with a secure way to store, retrieve, and share documents through a remote server.

## Private Keys
Each user keeps their private key locally and securely. Possession of this key is required to decrypt any stored file, guaranteeing that users retain complete control over their data.

## Security Model
- **Client‑side encryption** – Files are encrypted before they leave the device and decrypted only after download.
- **Digital signatures** – Every file is signed, enabling recipients to verify authenticity and integrity.
- **Mutual TLS** – SSL/TLS with client certificates protects against man‑in‑the‑middle attacks.

## Setup
See the server‑side and client‑side `README.md` files for installation and configuration instructions.
