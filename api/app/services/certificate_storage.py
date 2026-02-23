from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization


SAFE_NAME_RE = re.compile(r"[^a-z0-9]+")
MAX_CERT_FILE_BYTES = 1024 * 1024


class CertificateStorageError(ValueError):
    pass


@dataclass(slots=True)
class StoredCertificatePaths:
    cert_path: str
    key_path: str
    chain_path: str | None


class CertificateStorageService:
    def __init__(self, base_dir: str | Path | None = None) -> None:
        self.base_dir = Path(base_dir or os.getenv("CERT_STORAGE_DIR", "/shared/certs")).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def sanitize_name(name: str) -> str:
        cleaned = SAFE_NAME_RE.sub("-", name.strip().lower()).strip("-")
        return cleaned or "certificate"

    @staticmethod
    def _enforce_size_limit(content: bytes, label: str) -> None:
        if not content:
            raise CertificateStorageError(f"{label} file cannot be empty.")
        if len(content) > MAX_CERT_FILE_BYTES:
            raise CertificateStorageError(f"{label} file exceeds size limit ({MAX_CERT_FILE_BYTES} bytes).")

    @staticmethod
    def _split_pem_certificates(pem_data: bytes) -> list[bytes]:
        marker = b"-----END CERTIFICATE-----"
        parts: list[bytes] = []
        chunks = pem_data.split(marker)
        for chunk in chunks:
            if b"-----BEGIN CERTIFICATE-----" not in chunk:
                continue
            parts.append(chunk + marker + b"\n")
        return parts

    def validate_pem_bundle(self, cert_pem: bytes, key_pem: bytes, chain_pem: bytes | None = None) -> None:
        self._enforce_size_limit(cert_pem, "Certificate")
        self._enforce_size_limit(key_pem, "Private key")
        if chain_pem:
            self._enforce_size_limit(chain_pem, "Chain")

        try:
            cert_obj = x509.load_pem_x509_certificate(cert_pem)
        except Exception as exc:
            raise CertificateStorageError("Certificate PEM is invalid.") from exc

        try:
            private_key = serialization.load_pem_private_key(key_pem, password=None)
        except Exception as exc:
            raise CertificateStorageError("Private key PEM is invalid or encrypted.") from exc

        cert_public = cert_obj.public_key().public_numbers()
        key_public = private_key.public_key().public_numbers()
        if cert_public != key_public:
            raise CertificateStorageError("Certificate and private key do not match.")

        if chain_pem:
            chain_certs = self._split_pem_certificates(chain_pem)
            if not chain_certs:
                raise CertificateStorageError("Chain PEM does not contain any valid certificate blocks.")
            for chain_cert in chain_certs:
                try:
                    x509.load_pem_x509_certificate(chain_cert)
                except Exception as exc:
                    raise CertificateStorageError("Chain PEM contains invalid certificate blocks.") from exc

    def _safe_path(self, filename: str) -> Path:
        candidate = (self.base_dir / filename).resolve()
        if self.base_dir not in candidate.parents and candidate != self.base_dir:
            raise CertificateStorageError("Invalid certificate storage path.")
        return candidate

    @staticmethod
    def _write_file_atomic(path: Path, content: bytes, mode: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="wb", dir=str(path.parent), prefix=f".{path.name}.", delete=False) as tmp_file:
            tmp_file.write(content)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
            temp_path = Path(tmp_file.name)

        os.chmod(temp_path, mode)
        os.replace(temp_path, path)

    def store_certificate_files(
        self,
        certificate_id: int,
        name: str,
        cert_pem: bytes,
        key_pem: bytes,
        chain_pem: bytes | None,
    ) -> StoredCertificatePaths:
        safe_name = self.sanitize_name(name)

        cert_path = self._safe_path(f"{certificate_id}-{safe_name}.crt.pem")
        key_path = self._safe_path(f"{certificate_id}-{safe_name}.key.pem")
        chain_path = self._safe_path(f"{certificate_id}-{safe_name}.chain.pem") if chain_pem else None

        self._write_file_atomic(cert_path, cert_pem, 0o640)
        self._write_file_atomic(key_path, key_pem, 0o600)
        if chain_pem and chain_path:
            self._write_file_atomic(chain_path, chain_pem, 0o640)

        return StoredCertificatePaths(
            cert_path=str(cert_path),
            key_path=str(key_path),
            chain_path=str(chain_path) if chain_path else None,
        )

    def delete_certificate_files(self, cert_path: str, key_path: str, chain_path: str | None) -> None:
        for raw_path in [cert_path, key_path, chain_path]:
            if not raw_path:
                continue
            path = Path(raw_path).resolve()
            if self.base_dir not in path.parents and path != self.base_dir:
                continue
            try:
                path.unlink(missing_ok=True)
            except Exception:
                continue
