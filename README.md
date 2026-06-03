# Overview

- Each secret is encrypted symmetrically for all authorized recipients simultaneously meaning any holder of a listed private key can decrypt, while everyone else cannot.
- When a user's access is revoked, the tool removes their key from the repository's isolated keyring and immediately re-encrypts every stored secret for the remaining recipients, then performs a cryptographic check to confirm the revoked key is no longer present.

  <img width="1063" height="678" alt="gitsec_frontend" src="https://github.com/user-attachments/assets/3ba49825-aefe-4f9d-bff1-7e983eb53b9f" />


# Requirements

- Python 3.9 or later
- GnuPG binary (gpg or gpg2) 
- Linux/macOS: typically pre-installed or available via your package manager
- Windows (Gpg4win): the tool searches standard Gpg4win install paths, the Windows Registry (HKLM\SOFTWARE\GnuPG), Git-for-Windows, and Scoop shims automatically if the binary is not on PATH.
- python gnupg Python package:

          pip install python-gnupg

# Usage

          # Inside an existing Git repository
          python gitsec.py init

          # Authorize someone using a public key file
          python gitsec.py add-person alice@example.com --key-file alice.pub
          
          # Or load directly from your system keyring
          python gitsec.py add-person bob@example.com
          
          # Encrypt a file
          python gitsec.py add-secret .env
          
          # Decrypt it (requires your private key to be in the system keyring)
          python gitsec.py reveal .env --output-dir /tmp
          
          # Revoke access — re-encrypts all secrets automatically
          python gitsec.py remove-person alice@example.com

# Notice

- Secrets larger than 100 MB are rejected.
- Files with spaces or non-ASCII names need to be renamed before being added.
- If no private key is present in the system keyring, ***_re_encrypt_all_secrets*** will log an error for each file it cannot decrypt and skip it the revocation itself still completes.
- The tool does not manage Git commits. After encrypting or re-encrypting secrets, committing the ***updated .gitsecret/ contents to the repository is a manual step.***
