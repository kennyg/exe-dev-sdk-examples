"""Token signature tests over real HTTP, checked with ssh-keygen.

Each test starts a local HTTP server, sends real requests through Client,
and verifies the bearer token that reaches the server with `ssh-keygen -Y`.
The signatures come from many generated keys and payloads, so a defect that
fails only some signatures cannot pass by chance.
"""

import base64
import os
import random
import shutil
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from exedev import Client, TokenPermissions, _write_ssh_mpint

pytestmark = pytest.mark.skipif(
    shutil.which("ssh-keygen") is None, reason="ssh-keygen is required"
)

WHOAMI_BODY = '{"email":"user@example.com","ssh_keys":[]}'

KEY_FACTORIES = {
    "ed25519": lambda: ed25519.Ed25519PrivateKey.generate(),
    "ecdsa-p256": lambda: ec.generate_private_key(ec.SECP256R1()),
    "ecdsa-p384": lambda: ec.generate_private_key(ec.SECP384R1()),
    "ecdsa-p521": lambda: ec.generate_private_key(ec.SECP521R1()),
}

# Before the fix, about 1 in 4 P-256 signatures verified. With 120 signatures
# per curve, the chance that all of them pass by luck is below 1e-70.
KEYS_PER_TYPE = 30
MESSAGES_PER_KEY = 4


# ---------------------------------------------------------------------------
# Local exe.dev server
# ---------------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        self.server.requests.append(
            {
                "path": self.path,
                "authorization": self.headers.get("Authorization", ""),
                "body": body,
            }
        )
        data = WHOAMI_BODY.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        pass


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    httpd.requests = []
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()
    httpd.server_close()


def _base_url(httpd) -> str:
    host, port = httpd.server_address[:2]
    return f"http://{host}:{port}"


# ---------------------------------------------------------------------------
# ssh-keygen oracle
# ---------------------------------------------------------------------------


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _split_token(authorization: str) -> tuple[bytes, bytes]:
    assert authorization.startswith("Bearer exe0.")
    _, payload, sig = authorization[len("Bearer ") :].split(".")
    return _b64url_decode(payload), _b64url_decode(sig)


def _armor(sig_blob: bytes) -> bytes:
    b64 = base64.b64encode(sig_blob).decode("ascii")
    lines = [b64[i : i + 70] for i in range(0, len(b64), 70)]
    return (
        "-----BEGIN SSH SIGNATURE-----\n"
        + "\n".join(lines)
        + "\n-----END SSH SIGNATURE-----\n"
    ).encode("ascii")


def _ssh_keygen_verify(
    tmp_path, public_openssh: bytes, payload: bytes, sig_blob: bytes, namespace: str
) -> subprocess.CompletedProcess:
    signers = tmp_path / "allowed_signers"
    signers.write_bytes(b"signer@test " + public_openssh + b"\n")
    sig_file = tmp_path / "token.sig"
    sig_file.write_bytes(_armor(sig_blob))
    return subprocess.run(
        [
            "ssh-keygen", "-Y", "verify",
            "-f", str(signers),
            "-I", "signer@test",
            "-n", namespace,
            "-s", str(sig_file),
        ],
        input=payload,
        capture_output=True,
    )


def _public_openssh(key) -> bytes:
    return key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)


def _private_openssh(key) -> bytes:
    return key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())


def _random_permissions(rng: random.Random) -> TokenPermissions:
    words = ["ls", "whoami", "new", "rm", "share", "ssh-key", "restart"]
    perms = TokenPermissions()
    if rng.random() < 0.7:
        perms.exp = rng.randint(946684800, 4102444800)
    if rng.random() < 0.3:
        perms.nbf = rng.randint(946684800, 4102444800)
    if rng.random() < 0.7:
        perms.cmds = rng.sample(words, rng.randint(1, len(words)))
    if rng.random() < 0.4:
        perms.ctx = {"n": rng.randint(0, 10**9), "s": "x" * rng.randint(0, 300)}
    return perms


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key_type", list(KEY_FACTORIES))
def test_tokens_sent_over_http_verify(server, tmp_path, key_type):
    rng = random.Random(f"tokens-{key_type}")
    failures = []
    for key_index in range(KEYS_PER_TYPE):
        key = KEY_FACTORIES[key_type]()
        public = _public_openssh(key)
        for message_index in range(MESSAGES_PER_KEY):
            perms = _random_permissions(rng)
            client = Client(
                private_key=_private_openssh(key),
                base_url=_base_url(server),
                permissions=perms,
            )
            before = len(server.requests)
            client.whoami()
            assert len(server.requests) == before + 1
            request = server.requests[-1]
            assert request["path"] == "/exec"
            assert request["body"] == "whoami --json"

            payload, sig_blob = _split_token(request["authorization"])
            assert payload == perms.to_json().encode("utf-8")
            result = _ssh_keygen_verify(tmp_path, public, payload, sig_blob, "v0@exe.dev")
            if result.returncode != 0:
                failures.append(
                    f"key {key_index} message {message_index}: "
                    f"{result.stderr.decode(errors='replace').strip()}"
                )
    total = KEYS_PER_TYPE * MESSAGES_PER_KEY
    assert not failures, f"{len(failures)} of {total} {key_type} tokens failed:\n" + "\n".join(failures[:10])


@pytest.mark.parametrize("key_type", list(KEY_FACTORIES))
def test_vm_tokens_verify_only_for_their_namespace(tmp_path, key_type):
    for _ in range(10):
        key = KEY_FACTORIES[key_type]()
        client = Client(private_key=_private_openssh(key))
        payload, sig_blob = _split_token(
            "Bearer " + client.generate_vm_token("my-vm", TokenPermissions(cmds=["ls"]))
        )
        public = _public_openssh(key)
        ok = _ssh_keygen_verify(tmp_path, public, payload, sig_blob, "v0@my-vm.exe.xyz")
        assert ok.returncode == 0, ok.stderr
        wrong = _ssh_keygen_verify(tmp_path, public, payload, sig_blob, "v0@exe.dev")
        assert wrong.returncode != 0


@pytest.mark.parametrize("key_type", ["ecdsa-256", "ecdsa-384", "ecdsa-521"])
def test_ssh_keygen_generated_keys_verify(server, tmp_path, key_type):
    """Load keys that ssh-keygen wrote, so key parsing is also independent."""
    bits = key_type.split("-")[1]
    for i in range(5):
        key_path = tmp_path / f"id_{key_type}_{i}"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ecdsa", "-b", bits, "-N", "", "-f", str(key_path)],
            check=True,
        )
        public = (tmp_path / f"id_{key_type}_{i}.pub").read_bytes().split(b" ")[:2]
        perms = TokenPermissions(exp=4102444799, cmds=["ls"])
        client = Client(private_key=str(key_path), base_url=_base_url(server), permissions=perms)
        client.whoami()
        payload, sig_blob = _split_token(server.requests[-1]["authorization"])
        result = _ssh_keygen_verify(tmp_path, b" ".join(public), payload, sig_blob, "v0@exe.dev")
        assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "value, encoded",
    [
        (0, b""),
        (1, b"\x01"),
        (0x7F, b"\x7f"),
        (0x80, b"\x00\x80"),
        (0xFF, b"\x00\xff"),
        (0x0100, b"\x01\x00"),
        (0x00FF_FFFF, b"\x00\xff\xff\xff"),
        (0x7FFF_FFFF, b"\x7f\xff\xff\xff"),
    ],
)
def test_mpint_encoding(value, encoded):
    assert _write_ssh_mpint(value) == len(encoded).to_bytes(4, "big") + encoded


@pytest.fixture
def ssh_agent():
    if shutil.which("ssh-agent") is None or shutil.which("ssh-add") is None:
        pytest.skip("ssh-agent and ssh-add are required")
    # A Unix socket path must stay short, so do not put it under tmp_path.
    sock_dir = Path(tempfile.mkdtemp(prefix="exa"))
    sock = sock_dir / "s"
    proc = subprocess.Popen(
        ["ssh-agent", "-D", "-a", str(sock)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(100):
            if sock.exists():
                break
            threading.Event().wait(0.05)
        yield str(sock)
    finally:
        proc.terminate()
        proc.wait()
        shutil.rmtree(sock_dir, ignore_errors=True)


@pytest.mark.parametrize("key_type", list(KEY_FACTORIES))
def test_agent_tokens_sent_over_http_verify(server, tmp_path, ssh_agent, key_type):
    key = KEY_FACTORIES[key_type]()
    key_path = tmp_path / "id"
    key_path.write_bytes(_private_openssh(key))
    os.chmod(key_path, 0o600)
    subprocess.run(
        ["ssh-add", "-q", str(key_path)],
        env={**os.environ, "SSH_AUTH_SOCK": ssh_agent},
        check=True,
        capture_output=True,
    )
    rng = random.Random(f"agent-{key_type}")
    for _ in range(10):
        perms = _random_permissions(rng)
        client = Client(agent_sock=ssh_agent, base_url=_base_url(server), permissions=perms)
        client.whoami()
        payload, sig_blob = _split_token(server.requests[-1]["authorization"])
        result = _ssh_keygen_verify(tmp_path, _public_openssh(key), payload, sig_blob, "v0@exe.dev")
        assert result.returncode == 0, result.stderr
