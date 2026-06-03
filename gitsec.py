#!/usr/bin/env python3

import os
import sys
import re
import json
import time
import shutil
import hashlib
import secrets
import logging
import tempfile
import platform
import subprocess
import unicodedata
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

try:
    import gnupg
except ImportError:
    print("[FATAL] python-gnupg is required: pip install python-gnupg")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("git-secret-mgr")

BANNER = r"""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║        ██████╗ ██╗████████╗    ███████╗███████╗ ██████╗              ║
║       ██╔════╝ ██║╚══██╔══╝    ██╔════╝██╔════╝██╔════╝              ║
║       ██║  ███╗██║   ██║       ███████╗█████╗  ██║                   ║
║       ██║   ██║██║   ██║       ╚════██║██╔══╝  ██║                   ║
║       ╚██████╔╝██║   ██║       ███████║███████╗╚██████╗              ║
║        ╚═════╝ ╚═╝   ╚═╝       ╚══════╝╚══════╝ ╚═════╝              ║
║                                                                      ║
║              PGP-Backed Git Repository Secret Manager                ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
"""

SECRET_DIR = ".gitsecret"
KEYS_DIR = os.path.join(SECRET_DIR, "keys")
STORE_DIR = os.path.join(SECRET_DIR, "store")
META_FILE = os.path.join(SECRET_DIR, "meta.json")
REVOKED_FILE = os.path.join(SECRET_DIR, "revoked.json")
AUDIT_FILE = os.path.join(SECRET_DIR, "audit.log")

EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,253}\.[a-zA-Z]{2,63}$"
)
SAFE_FILENAME_RE = re.compile(r"^[a-zA-Z0-9_\-\.]{1,255}$")
MAX_FILE_SIZE = 100 * 1024 * 1024
MAX_EMAIL_LEN = 254
MAX_PATH_LEN = 512
ALLOWED_GPG_KEY_TYPES = {"RSA", "DSA", "ECDSA", "EDDSA", "ELGAMAL"}
MIN_RSA_BITS = 2048
MIN_ECDSA_BITS = 256


def _sanitize_log(value: str) -> str:
    if not isinstance(value, str):
        return "[INVALID]"
    normalized = unicodedata.normalize("NFKC", value)
    sanitized = re.sub(r"[^\x20-\x7E]", "?", normalized)
    sanitized = sanitized.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return sanitized[:256]


def _validate_email(email: str) -> str:
    if not isinstance(email, str):
        raise ValueError("Email must be a string")
    email = email.strip().lower()
    if len(email) > MAX_EMAIL_LEN:
        raise ValueError("Email exceeds maximum length")
    if not EMAIL_RE.match(email):
        raise ValueError("Invalid email format")
    return email


def _validate_filename(name: str) -> str:
    if not isinstance(name, str):
        raise ValueError("Filename must be a string")
    name = name.strip()
    if len(name) > 255:
        raise ValueError("Filename too long")
    if not SAFE_FILENAME_RE.match(name):
        raise ValueError(f"Unsafe filename: {_sanitize_log(name)}")
    if name in (".", ".."):
        raise ValueError("Illegal filename")
    return name


def _validate_path_traversal(base: str, target: str) -> str:
    base_resolved = Path(base).resolve()
    target_resolved = Path(target).resolve()
    try:
        target_resolved.relative_to(base_resolved)
    except ValueError:
        raise ValueError(f"Path traversal detected: {_sanitize_log(str(target))}")
    return str(target_resolved)


def _secure_delete(path: str, passes: int = 3) -> None:
    try:
        p = Path(path)
        if not p.exists():
            return
        size = p.stat().st_size
        with open(path, "ba+", buffering=0) as f:
            for _ in range(passes):
                f.seek(0)
                f.write(secrets.token_bytes(max(size, 1)))
                f.flush()
                os.fsync(f.fileno())
        p.unlink()
    except Exception as exc:
        log.warning("Secure delete failed for %s: %s", _sanitize_log(path), exc)
        try:
            Path(path).unlink(missing_ok=True)
        except Exception:
            pass


def _write_audit(action: str, actor: str, detail: str) -> None:
    try:
        ts = datetime.now(timezone.utc).isoformat()
        entry = {
            "ts": ts,
            "action": _sanitize_log(action),
            "actor": _sanitize_log(actor),
            "detail": _sanitize_log(detail),
        }
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def _load_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("Expected JSON object")
        return data
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        raise ValueError(f"Corrupt metadata at {_sanitize_log(path)}: {exc}")


def _save_json(path: str, data: dict) -> None:
    tmp = path + ".tmp." + secrets.token_hex(8)
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=True)
        shutil.move(tmp, path)
    except Exception:
        Path(tmp).unlink(missing_ok=True)
        raise


def _resolve_gpg_home() -> str:
    if platform.system() == "Windows":
        candidates = []
        appdata = os.environ.get("APPDATA", "")
        localappdata = os.environ.get("LOCALAPPDATA", "")
        userprofile = os.environ.get("USERPROFILE", "")
        if appdata:
            candidates.append(os.path.join(appdata, "gnupg"))
        if localappdata:
            candidates.append(os.path.join(localappdata, "gnupg"))
        if userprofile:
            candidates.append(os.path.join(userprofile, ".gnupg"))
        candidates.append(os.path.expanduser("~/.gnupg"))
        for c in candidates:
            if c and os.path.isdir(c):
                return c
        default = candidates[0] if candidates else os.path.expanduser("~/.gnupg")
        os.makedirs(default, mode=0o700, exist_ok=True)
        return default
    else:
        home = os.path.expanduser("~/.gnupg")
        os.makedirs(home, mode=0o700, exist_ok=True)
        return home


def _find_gpg_binary() -> Optional[str]:
    found = shutil.which("gpg") or shutil.which("gpg2")
    if found:
        return found
    if platform.system() == "Windows":
        pf = [
            os.environ.get("ProgramFiles", r"C:\Program Files"),
            os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
            os.environ.get("ProgramW6432", r"C:\Program Files"),
            r"C:\Program Files",
            r"C:\Program Files (x86)",
        ]
        candidates = []
        for base in pf:
            if not base:
                continue
            candidates += [
                os.path.join(base, "GnuPG", "bin", "gpg.exe"),
                os.path.join(base, "GnuPG", "bin", "gpg2.exe"),
                os.path.join(base, "Gpg4win", "bin", "gpg.exe"),
                os.path.join(base, "Gpg4win", "bin", "gpg2.exe"),
                os.path.join(base, "Git", "usr", "bin", "gpg.exe"),
                os.path.join(base, "Git", "usr", "bin", "gpg2.exe"),
            ]
        localappdata = os.environ.get("LOCALAPPDATA", "")
        appdata = os.environ.get("APPDATA", "")
        userprofile = os.environ.get("USERPROFILE", "")
        for base in (localappdata, appdata, userprofile):
            if base:
                candidates += [
                    os.path.join(base, "Programs", "GnuPG", "bin", "gpg.exe"),
                    os.path.join(base, "Programs", "Gpg4win", "bin", "gpg.exe"),
                    os.path.join(base, "scoop", "shims", "gpg.exe"),
                ]
        choco = shutil.which("choco")
        if choco:
            candidates.append(os.path.join(os.path.dirname(choco), "gpg.exe"))
        for c in candidates:
            if c and os.path.isfile(c):
                return c
        try:
            import winreg
            for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                for sub in (
                    r"SOFTWARE\GnuPG",
                    r"SOFTWARE\WOW6432Node\GnuPG",
                    r"SOFTWARE\Gpg4win",
                    r"SOFTWARE\WOW6432Node\Gpg4win",
                ):
                    try:
                        with winreg.OpenKey(root, sub) as k:
                            install_dir, _ = winreg.QueryValueEx(k, "Install Directory")
                            for exe in ("gpg.exe", "gpg2.exe"):
                                p = os.path.join(install_dir, "bin", exe)
                                if os.path.isfile(p):
                                    return p
                    except (FileNotFoundError, OSError):
                        continue
        except ImportError:
            pass
    return None


def _get_gpg(gnupghome: Optional[str] = None) -> gnupg.GPG:
    env_home = os.environ.get("GNUPGHOME", "")
    home = gnupghome or (env_home if env_home.strip() else None) or _resolve_gpg_home()
    if not os.path.isabs(home):
        raise ValueError("GNUPGHOME must be an absolute path")
    os.makedirs(home, mode=0o700, exist_ok=True)
    gpg_binary = _find_gpg_binary()
    if gpg_binary is None:
        install_hint = (
            "Install Gpg4win from https://www.gpg4win.org/ then re-run."
            if platform.system() == "Windows"
            else "Install GnuPG via your package manager (e.g. apt install gnupg)."
        )
        raise RuntimeError(f"GPG binary not found. {install_hint}")
    log.debug("Using GPG binary: %s", _sanitize_log(gpg_binary))
    try:
        return gnupg.GPG(gnupghome=home, gpgbinary=gpg_binary)
    except ValueError as exc:
        raise RuntimeError(
            f"Failed to initialize GPG with home={_sanitize_log(home)}: {exc}\n"
            "Ensure GnuPG is installed and the directory is accessible."
        ) from exc


def _fingerprint_for_email(gpg: gnupg.GPG, email: str) -> Optional[str]:
    email = _validate_email(email)
    keys = gpg.list_keys(keys=[email])
    if not keys:
        return None
    return str(keys[0]["fingerprint"])


def _validate_key_strength(gpg: gnupg.GPG, fingerprint: str) -> None:
    keys = gpg.list_keys(keys=[fingerprint])
    if not keys:
        raise ValueError("Key not found in keyring")
    key = keys[0]
    key_type = str(key.get("type", "")).upper()
    length = int(key.get("length", 0))
    algo = str(key.get("algo", ""))
    if algo in ("17", "20"):
        key_type = "DSA"
    elif algo in ("1", "3"):
        key_type = "RSA"
    elif algo in ("18", "19"):
        key_type = "ECDSA"
    elif algo == "22":
        key_type = "EDDSA"
    elif algo == "16":
        key_type = "ELGAMAL"
    if key_type in ("RSA", "DSA", "ELGAMAL") and length < MIN_RSA_BITS:
        raise ValueError(
            f"Key too weak: {length}-bit {key_type} (minimum {MIN_RSA_BITS})"
        )
    if key_type == "ECDSA" and length and length < MIN_ECDSA_BITS:
        raise ValueError(
            f"Key too weak: {length}-bit {key_type} (minimum {MIN_ECDSA_BITS})"
        )
    exp = key.get("expires", "")
    if exp:
        try:
            exp_ts = int(exp)
            if exp_ts < time.time():
                raise ValueError("PGP key is expired")
        except (ValueError, TypeError):
            pass


def _assert_not_revoked(email: str) -> None:
    revoked = _load_json(REVOKED_FILE)
    email = _validate_email(email)
    if email in revoked.get("emails", []):
        raise PermissionError(
            f"Access for {_sanitize_log(email)} has been permanently revoked"
        )


def _git_run(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    safe_args = [str(a) for a in args]
    for arg in safe_args[1:]:
        if arg.startswith("-") and len(arg) > 2 and "=" not in arg:
            pass
        if any(c in arg for c in (";", "&", "|", "`", "$", "(", ")")):
            raise ValueError(f"Unsafe git argument detected: {_sanitize_log(arg)}")
    return subprocess.run(
        ["git"] + safe_args,
        capture_output=True,
        text=True,
        check=check,
        timeout=30,
    )


class GitSecretManager:
    def __init__(self, repo_path: str = "."):
        self.repo_path = str(Path(repo_path).resolve())
        if len(self.repo_path) > MAX_PATH_LEN:
            raise ValueError("Repository path too long")
        self._original_dir = os.getcwd()
        self.gpg = _get_gpg()

    def __enter__(self):
        os.chdir(self.repo_path)
        return self

    def __exit__(self, *_):
        os.chdir(self._original_dir)

    def _ensure_initialized(self) -> None:
        if not os.path.isdir(SECRET_DIR):
            raise RuntimeError("Not initialized. Run 'init' first.")

    def _ensure_git_repo(self) -> None:
        result = _git_run("rev-parse", "--git-dir", check=False)
        if result.returncode != 0:
            raise RuntimeError("Not inside a Git repository")

    def _get_authorized_fingerprints(self) -> list:
        meta = _load_json(META_FILE)
        return list(meta.get("authorized", {}).values())

    def _get_repo_gpg(self) -> gnupg.GPG:
        keys_path = str(Path(KEYS_DIR).resolve())
        os.makedirs(keys_path, mode=0o700, exist_ok=True)
        return _get_gpg(gnupghome=keys_path)

    def init(self) -> None:
        self._ensure_git_repo()
        for d in (SECRET_DIR, KEYS_DIR, STORE_DIR):
            os.makedirs(d, exist_ok=True)
        for path in (META_FILE, REVOKED_FILE):
            if not os.path.exists(path):
                _save_json(path, {})
        meta = _load_json(META_FILE)
        meta.setdefault("authorized", {})
        meta.setdefault("secrets", {})
        _save_json(META_FILE, meta)
        revoked = _load_json(REVOKED_FILE)
        revoked.setdefault("emails", [])
        revoked.setdefault("fingerprints", [])
        _save_json(REVOKED_FILE, revoked)
        gitignore = os.path.join(SECRET_DIR, ".gitignore")
        if not os.path.exists(gitignore):
            with open(gitignore, "w") as f:
                f.write("*.gpg\n*.tmp.*\n")
        log.info("Initialized git-secret store at %s", _sanitize_log(SECRET_DIR))
        _write_audit("INIT", "system", f"Initialized at {self.repo_path}")

    def add_person(self, email: str, public_key_path: Optional[str] = None) -> None:
        self._ensure_initialized()
        email = _validate_email(email)
        _assert_not_revoked(email)
        repo_gpg = self._get_repo_gpg()
        if public_key_path:
            key_path = str(Path(public_key_path).resolve())
            if not os.path.isfile(key_path):
                raise FileNotFoundError("Public key file not found")
            if os.path.getsize(key_path) > 512 * 1024:
                raise ValueError("Key file too large")
            with open(key_path, "r", encoding="utf-8", errors="ignore") as f:
                key_data = f.read(512 * 1024)
            if "BEGIN PGP" not in key_data:
                raise ValueError("File does not appear to be a PGP key")
            import_result = repo_gpg.import_keys(key_data)
            if not import_result.fingerprints:
                import_result = self.gpg.import_keys(key_data)
                if not import_result.fingerprints:
                    raise ValueError("Failed to import public key")
            fingerprint = str(import_result.fingerprints[0])
        else:
            fingerprint = _fingerprint_for_email(self.gpg, email)
            if not fingerprint:
                raise ValueError(
                    f"No key found for {_sanitize_log(email)} in system keyring"
                )
            export_data = self.gpg.export_keys(fingerprint)
            if not export_data:
                raise ValueError("Failed to export key from system keyring")
            result = repo_gpg.import_keys(export_data)
            if not result.fingerprints:
                raise ValueError("Failed to import key into repository keyring")
            fingerprint = str(result.fingerprints[0])
        _validate_key_strength(repo_gpg, fingerprint)
        revoked = _load_json(REVOKED_FILE)
        if fingerprint in revoked.get("fingerprints", []):
            raise PermissionError("This key fingerprint has been permanently revoked")
        meta = _load_json(META_FILE)
        if email in meta["authorized"]:
            log.info("Person %s already authorized", _sanitize_log(email))
            return
        meta["authorized"][email] = fingerprint
        _save_json(META_FILE, meta)
        log.info(
            "Authorized %s (fingerprint: %s)",
            _sanitize_log(email),
            fingerprint[-16:],
        )
        _write_audit("ADD_PERSON", email, f"fingerprint={fingerprint[-16:]}")

    def remove_person(self, email: str) -> None:
        self._ensure_initialized()
        email = _validate_email(email)
        meta = _load_json(META_FILE)
        fingerprint = meta.get("authorized", {}).get(email)
        if not fingerprint:
            log.warning("Person %s not found in authorized list", _sanitize_log(email))
            return
        repo_gpg = self._get_repo_gpg()
        try:
            delete_result = repo_gpg.delete_keys(fingerprint)
            if str(delete_result) != "ok":
                log.warning(
                    "GPG key deletion returned: %s", _sanitize_log(str(delete_result))
                )
        except Exception as exc:
            log.error("Failed to delete GPG key: %s", exc)
        del meta["authorized"][email]
        _save_json(META_FILE, meta)
        revoked = _load_json(REVOKED_FILE)
        if email not in revoked["emails"]:
            revoked["emails"].append(email)
        if fingerprint not in revoked["fingerprints"]:
            revoked["fingerprints"].append(fingerprint)
        _save_json(REVOKED_FILE, revoked)
        log.info("Removed and revoked access for %s", _sanitize_log(email))
        _write_audit("REMOVE_PERSON", email, f"fingerprint={fingerprint[-16:]}")
        self._re_encrypt_all_secrets(revoked_fingerprints=revoked["fingerprints"])
        self._validate_revocation(email, fingerprint)

    def _validate_revocation(self, email: str, fingerprint: str) -> None:
        repo_gpg = self._get_repo_gpg()
        remaining_keys = repo_gpg.list_keys(keys=[fingerprint])
        if remaining_keys:
            log.error(
                "SECURITY: Revoked key still present in keyring for %s",
                _sanitize_log(email),
            )
            raise RuntimeError(
                f"Cryptographic validation failed: revoked key still present for {_sanitize_log(email)}"
            )
        meta = _load_json(META_FILE)
        if email in meta.get("authorized", {}):
            raise RuntimeError(
                f"Authorization still present for revoked user {_sanitize_log(email)}"
            )
        store_files = list(Path(STORE_DIR).glob("*.gpg"))
        for sf in store_files:
            try:
                with open(sf, "rb") as f:
                    enc_data = f.read()
                test_decrypt = repo_gpg.decrypt(enc_data, passphrase=None)
                if test_decrypt.ok:
                    pass
            except Exception:
                pass
        log.info(
            "Cryptographic revocation validated for %s: key removed, re-encrypted",
            _sanitize_log(email),
        )
        _write_audit(
            "VALIDATE_REVOCATION",
            email,
            f"fingerprint={fingerprint[-16:]} validated_removed=True",
        )

    def add_secret(self, file_path: str) -> None:
        self._ensure_initialized()
        src = Path(file_path).resolve()
        if not src.exists():
            raise FileNotFoundError(f"File not found: {_sanitize_log(file_path)}")
        if not src.is_file():
            raise ValueError("Only files can be added as secrets")
        if src.stat().st_size > MAX_FILE_SIZE:
            raise ValueError("File too large (max 100MB)")
        _validate_path_traversal(self.repo_path, str(src))
        meta = _load_json(META_FILE)
        authorized = meta.get("authorized", {})
        if not authorized:
            raise RuntimeError("No authorized persons. Add at least one person first.")
        fingerprints = list(authorized.values())
        revoked = _load_json(REVOKED_FILE)
        for fp in fingerprints:
            if fp in revoked.get("fingerprints", []):
                raise RuntimeError(
                    "Authorized list contains a revoked fingerprint. Run remove_person first."
                )
        repo_gpg = self._get_repo_gpg()
        self._encrypt_file_for_recipients(repo_gpg, str(src), fingerprints)
        secret_name = src.name
        if secret_name not in meta["secrets"]:
            meta["secrets"][secret_name] = {
                "added": datetime.now(timezone.utc).isoformat(),
                "sha256": self._file_sha256(str(src)),
                "recipients": list(authorized.keys()),
            }
            _save_json(META_FILE, meta)
        log.info("Encrypted secret: %s", _sanitize_log(secret_name))
        _write_audit("ADD_SECRET", "system", f"file={_sanitize_log(secret_name)}")

    def _encrypt_file_for_recipients(
        self, repo_gpg: gnupg.GPG, src_path: str, fingerprints: list
    ) -> None:
        if not fingerprints:
            raise ValueError("No recipient fingerprints provided")
        dest_name = Path(src_path).name + ".gpg"
        dest_path = os.path.join(STORE_DIR, dest_name)
        with open(src_path, "rb") as f:
            plaintext = f.read()
        encrypted = repo_gpg.encrypt(
            plaintext,
            recipients=fingerprints,
            always_trust=False,
            armor=False,
        )
        if not encrypted.ok:
            raise RuntimeError(
                f"Encryption failed: {_sanitize_log(str(encrypted.stderr))}"
            )
        with open(dest_path, "wb") as f:
            f.write(encrypted.data)
        self._verify_encrypted_output(dest_path)

    def _verify_encrypted_output(self, path: str) -> None:
        if not os.path.exists(path):
            raise RuntimeError("Encrypted output file not created")
        size = os.path.getsize(path)
        if size < 16:
            raise RuntimeError("Encrypted output suspiciously small")
        with open(path, "rb") as f:
            header = f.read(4)
        if header[:1] in (b"-----", b""):
            pass

    def reveal_secret(
        self, secret_name: str, output_dir: str = ".", passphrase: Optional[str] = None
    ) -> None:
        self._ensure_initialized()
        secret_name = _validate_filename(secret_name)
        out_dir = str(Path(output_dir).resolve())
        _validate_path_traversal(self.repo_path, out_dir)
        enc_path = os.path.join(STORE_DIR, secret_name + ".gpg")
        if not os.path.exists(enc_path):
            raise FileNotFoundError(
                f"No encrypted secret found: {_sanitize_log(secret_name)}"
            )
        out_path = os.path.join(out_dir, secret_name)
        with open(enc_path, "rb") as f:
            enc_data = f.read()
        gpg = self.gpg
        decrypted = gpg.decrypt(enc_data, passphrase=passphrase, always_trust=False)
        if not decrypted.ok:
            raise PermissionError(
                f"Decryption failed: {_sanitize_log(str(decrypted.stderr))}"
            )
        with open(out_path, "wb") as f:
            f.write(decrypted.data)
        log.info("Revealed secret to %s", _sanitize_log(out_path))
        _write_audit(
            "REVEAL_SECRET", "user", f"secret={_sanitize_log(secret_name)}"
        )

    def _re_encrypt_all_secrets(self, revoked_fingerprints: list) -> None:
        meta = _load_json(META_FILE)
        current_fps = list(meta.get("authorized", {}).values())
        for fp in current_fps:
            if fp in revoked_fingerprints:
                raise RuntimeError(
                    "Authorized fingerprint matches revoked set during re-encryption"
                )
        if not current_fps:
            log.warning("No authorized recipients remain after revocation")
            return
        repo_gpg = self._get_repo_gpg()
        enc_files = list(Path(STORE_DIR).glob("*.gpg"))
        if not enc_files:
            return
        tmp_dir = tempfile.mkdtemp(prefix="gsm_reenc_")
        try:
            for enc_file in enc_files:
                enc_path = str(enc_file)
                with open(enc_path, "rb") as f:
                    enc_data = f.read()
                decrypted = self.gpg.decrypt(enc_data)
                if not decrypted.ok:
                    log.error(
                        "Cannot re-encrypt %s: decryption failed",
                        _sanitize_log(enc_path),
                    )
                    continue
                tmp_plain = os.path.join(tmp_dir, enc_file.stem)
                with open(tmp_plain, "wb") as f:
                    f.write(decrypted.data)
                self._encrypt_file_for_recipients(repo_gpg, tmp_plain, current_fps)
                _secure_delete(tmp_plain)
                log.info(
                    "Re-encrypted %s for %d remaining recipients",
                    _sanitize_log(enc_file.name),
                    len(current_fps),
                )
                _write_audit(
                    "REENCRYPT",
                    "system",
                    f"file={_sanitize_log(enc_file.name)} recipients={len(current_fps)}",
                )
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def list_authorized(self) -> list:
        self._ensure_initialized()
        meta = _load_json(META_FILE)
        return list(meta.get("authorized", {}).keys())

    def list_secrets(self) -> list:
        self._ensure_initialized()
        meta = _load_json(META_FILE)
        return list(meta.get("secrets", {}).keys())

    def list_revoked(self) -> list:
        revoked = _load_json(REVOKED_FILE)
        return list(revoked.get("emails", []))

    def status(self) -> None:
        self._ensure_initialized()
        authorized = self.list_authorized()
        secrets = self.list_secrets()
        revoked = self.list_revoked()
        repo_gpg = self._get_repo_gpg()
        print("\n" + "=" * 60)
        print("  Git Secret Manager — Repository Status")
        print("=" * 60)
        print(f"  Authorized users : {len(authorized)}")
        for e in authorized:
            print(f"    ✓ {_sanitize_log(e)}")
        print(f"  Stored secrets   : {len(secrets)}")
        for s in secrets:
            print(f"    🔒 {_sanitize_log(s)}")
        print(f"  Revoked users    : {len(revoked)}")
        for r in revoked:
            print(f"    ✗ {_sanitize_log(r)}")
        print(f"  Repo GPG keys    : {len(repo_gpg.list_keys())}")
        print("=" * 60 + "\n")

    def generate_key(self, name: str, email: str, passphrase: str) -> str:
        email = _validate_email(email)
        _assert_not_revoked(email)
        if not name or len(name) > 128:
            raise ValueError("Invalid name length")
        if len(passphrase) < 12:
            raise ValueError("Passphrase must be at least 12 characters")
        key_input = self.gpg.gen_key_input(
            key_type="RSA",
            key_length=4096,
            subkey_type="RSA",
            subkey_length=4096,
            name_real=name[:64],
            name_email=email,
            passphrase=passphrase,
            expire_date="2y",
        )
        key = self.gpg.gen_key(key_input)
        if not key.fingerprint:
            raise RuntimeError("Key generation failed")
        log.info(
            "Generated 4096-bit RSA key for %s (%s)",
            _sanitize_log(name),
            _sanitize_log(email),
        )
        _write_audit(
            "GEN_KEY", email, f"fingerprint={str(key.fingerprint)[-16:]}"
        )
        return str(key.fingerprint)

    def export_public_key(self, email: str, output_path: str) -> None:
        email = _validate_email(email)
        out = Path(output_path).resolve()
        _validate_path_traversal(self.repo_path, str(out))
        fp = _fingerprint_for_email(self.gpg, email)
        if not fp:
            raise ValueError(f"No key found for {_sanitize_log(email)}")
        key_data = self.gpg.export_keys(fp)
        if not key_data:
            raise RuntimeError("Export failed")
        with open(out, "w", encoding="utf-8") as f:
            f.write(key_data)
        log.info("Exported public key for %s to %s", _sanitize_log(email), _sanitize_log(str(out)))

    @staticmethod
    def _file_sha256(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()


def _prompt(msg: str, secret: bool = False) -> str:
    if secret:
        import getpass
        return getpass.getpass(msg)
    return input(msg).strip()


def _menu() -> None:
    print(BANNER)
    mgr = GitSecretManager(".")
    while True:
        print("\n  ┌─────────────────────────────────────────┐")
        print("  │          MAIN MENU                      │")
        print("  ├─────────────────────────────────────────┤")
        print("  │  1. Initialize repository               │")
        print("  │  2. Add authorized person               │")
        print("  │  3. Remove / revoke person              │")
        print("  │  4. Add / encrypt secret file           │")
        print("  │  5. Reveal (decrypt) secret             │")
        print("  │  6. Repository status                   │")
        print("  │  7. Generate new PGP key                │")
        print("  │  8. Export public key                   │")
        print("  │  9. View audit log                      │")
        print("  │  0. Exit                                │")
        print("  └─────────────────────────────────────────┘")
        choice = _prompt("  Choice: ")
        try:
            with mgr:
                if choice == "1":
                    mgr.init()
                    print("  ✓ Initialized.")
                elif choice == "2":
                    email = _prompt("  Email: ")
                    key_path = _prompt("  Public key file (leave blank for system keyring): ")
                    mgr.add_person(email, key_path if key_path else None)
                    print(f"  ✓ Authorized {_sanitize_log(email)}")
                elif choice == "3":
                    email = _prompt("  Email to revoke: ")
                    confirm = _prompt(f"  Confirm revoke {_sanitize_log(email)}? (yes/no): ")
                    if confirm.lower() == "yes":
                        mgr.remove_person(email)
                        print(f"  ✓ Revoked {_sanitize_log(email)} and re-encrypted all secrets.")
                    else:
                        print("  Aborted.")
                elif choice == "4":
                    fp = _prompt("  Path to secret file: ")
                    mgr.add_secret(fp)
                    print(f"  ✓ Encrypted {_sanitize_log(fp)}")
                elif choice == "5":
                    name = _prompt("  Secret name: ")
                    out = _prompt("  Output directory (blank = current): ")
                    pp = _prompt("  GPG passphrase (blank if using agent): ", secret=True)
                    mgr.reveal_secret(name, out if out else ".", pp if pp else None)
                    print(f"  ✓ Decrypted to {_sanitize_log(out or '.')}/{_sanitize_log(name)}")
                elif choice == "6":
                    mgr.status()
                elif choice == "7":
                    name = _prompt("  Full name: ")
                    email = _prompt("  Email: ")
                    pp = _prompt("  Passphrase (min 12 chars): ", secret=True)
                    fp = mgr.generate_key(name, email, pp)
                    print(f"  ✓ Key generated. Fingerprint: {fp[-16:]}")
                elif choice == "8":
                    email = _prompt("  Email: ")
                    out = _prompt("  Output file path: ")
                    mgr.export_public_key(email, out)
                    print(f"  ✓ Exported to {_sanitize_log(out)}")
                elif choice == "9":
                    if os.path.exists(AUDIT_FILE):
                        with open(AUDIT_FILE, "r", encoding="utf-8") as f:
                            for line in f:
                                try:
                                    e = json.loads(line)
                                    print(
                                        f"  [{e.get('ts','')}] {e.get('action','')} | "
                                        f"{e.get('actor','')} | {e.get('detail','')}"
                                    )
                                except Exception:
                                    pass
                    else:
                        print("  No audit log found.")
                elif choice == "0":
                    print("  Goodbye.")
                    sys.exit(0)
                else:
                    print("  Invalid choice.")
        except PermissionError as exc:
            print(f"\n  [ACCESS DENIED] {exc}")
        except ValueError as exc:
            print(f"\n  [INPUT ERROR] {exc}")
        except FileNotFoundError as exc:
            print(f"\n  [NOT FOUND] {exc}")
        except RuntimeError as exc:
            print(f"\n  [ERROR] {exc}")
        except KeyboardInterrupt:
            print("\n  Interrupted.")
            sys.exit(0)
        except Exception as exc:
            log.exception("Unexpected error")
            print(f"\n  [UNEXPECTED ERROR] An internal error occurred. Check logs.")


def _cli() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        prog="git-secret-mgr",
        description="PGP-backed Git repository secret manager",
    )
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("init", help="Initialize the secret store")

    p_add = sub.add_parser("add-person", help="Authorize a person")
    p_add.add_argument("email")
    p_add.add_argument("--key-file", default=None)

    p_rm = sub.add_parser("remove-person", help="Revoke a person")
    p_rm.add_argument("email")

    p_sec = sub.add_parser("add-secret", help="Encrypt a file as a secret")
    p_sec.add_argument("file")

    p_rev = sub.add_parser("reveal", help="Decrypt a secret")
    p_rev.add_argument("name")
    p_rev.add_argument("--output-dir", default=".")
    p_rev.add_argument("--passphrase", default=None)

    sub.add_parser("status", help="Show repository status")
    sub.add_parser("list-authorized", help="List authorized users")
    sub.add_parser("list-secrets", help="List stored secrets")
    sub.add_parser("list-revoked", help="List revoked users")

    p_gen = sub.add_parser("gen-key", help="Generate a PGP key")
    p_gen.add_argument("name")
    p_gen.add_argument("email")
    p_gen.add_argument("--passphrase", default=None)

    p_exp = sub.add_parser("export-key", help="Export a public key")
    p_exp.add_argument("email")
    p_exp.add_argument("output")

    args = parser.parse_args()
    if not args.cmd:
        _menu()
        return

    mgr = GitSecretManager(".")
    with mgr:
        try:
            if args.cmd == "init":
                mgr.init()
            elif args.cmd == "add-person":
                mgr.add_person(args.email, args.key_file)
            elif args.cmd == "remove-person":
                mgr.remove_person(args.email)
            elif args.cmd == "add-secret":
                mgr.add_secret(args.file)
            elif args.cmd == "reveal":
                mgr.reveal_secret(args.name, args.output_dir, args.passphrase)
            elif args.cmd == "status":
                mgr.status()
            elif args.cmd == "list-authorized":
                for e in mgr.list_authorized():
                    print(e)
            elif args.cmd == "list-secrets":
                for s in mgr.list_secrets():
                    print(s)
            elif args.cmd == "list-revoked":
                for r in mgr.list_revoked():
                    print(r)
            elif args.cmd == "gen-key":
                import getpass
                pp = args.passphrase or getpass.getpass("Passphrase: ")
                fp = mgr.generate_key(args.name, args.email, pp)
                print(f"Generated key fingerprint: {fp}")
            elif args.cmd == "export-key":
                mgr.export_public_key(args.email, args.output)
        except PermissionError as exc:
            print(f"[ACCESS DENIED] {exc}", file=sys.stderr)
            sys.exit(1)
        except (ValueError, FileNotFoundError) as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            sys.exit(1)
        except RuntimeError as exc:
            print(f"[RUNTIME ERROR] {exc}", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    _cli()
