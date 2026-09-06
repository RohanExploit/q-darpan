"""Shared fixtures.

Nothing here touches the network. The TLS collector is exercised against a
local ``ssl`` server with a certificate generated at fixture time, which keeps
the suite runnable inside the same air-gapped enclave the tool targets.
"""

from __future__ import annotations

import datetime
import socket
import ssl
import sys
import tarfile
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from elf_builder import AES_SBOX, MD5_T, SHA256_K, build_elf  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def sample_repo() -> Path:
    """A small multi-language source tree with known crypto calls."""
    return FIXTURES / "sample_repo"


@pytest.fixture
def elf_tree(tmp_path: Path) -> Path:
    """A directory holding one synthetic ELF with linkage, symbols and constants."""
    build_elf(
        tmp_path / "bin" / "daemon",
        rodata=b"\x00" * 32 + AES_SBOX + b"\x11" * 8 + SHA256_K + b"\x22" * 8 + MD5_T,
        needed=["libcrypto.so.3", "libc.so.6"],
        symbols=["RSA_generate_key_ex", "EVP_sha256", "malloc"],
    )
    return tmp_path


@pytest.fixture
def image_tarball(tmp_path: Path) -> Path:
    """A synthetic ``docker save`` archive: one layer, one binary, one package DB."""
    layer_dir = tmp_path / "build"
    layer_dir.mkdir()

    binary = build_elf(
        layer_dir / "daemon",
        rodata=AES_SBOX + b"\x00" * 16 + MD5_T,
        needed=["libcrypto.so.3"],
        symbols=["EVP_sha256"],
    )

    status = layer_dir / "status"
    status.write_text(
        "Package: openssl\nStatus: install ok installed\nVersion: 3.0.2-0ubuntu1.15\n"
        "\n"
        "Package: coreutils\nStatus: install ok installed\nVersion: 8.32-4.1\n",
        encoding="utf-8",
    )

    layer_tar = tmp_path / "layer.tar"
    with tarfile.open(layer_tar, "w") as layer:
        layer.add(binary, arcname="usr/sbin/daemon")
        layer.add(status, arcname="var/lib/dpkg/status")

    manifest = tmp_path / "manifest.json"
    manifest.write_text('[{"Layers": ["layer.tar"]}]', encoding="utf-8")

    image = tmp_path / "image.tar"
    with tarfile.open(image, "w") as archive:
        archive.add(layer_tar, arcname="layer.tar")
        archive.add(manifest, arcname="manifest.json")
    return image


def _self_signed(tmp_path: Path):
    """Generate an RSA-2048 self-signed certificate for the local test server."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )

    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


@pytest.fixture
def tls_server(tmp_path: Path):
    """A loopback TLS server presenting an RSA-2048 self-signed certificate.

    Yields ``host:port``. One connection is served per accept loop iteration so
    that both the single-handshake path and the probe paths work.
    """
    cert_path, key_path = _self_signed(tmp_path)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    listener.settimeout(0.5)
    host, port = listener.getsockname()

    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                with context.wrap_socket(client, server_side=True) as tls:
                    tls.recv(1)
            except (ssl.SSLError, OSError):
                pass
            finally:
                try:
                    client.close()
                except OSError:
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield "%s:%d" % (host, port)
    finally:
        stop.set()
        listener.close()
        thread.join(timeout=2)
