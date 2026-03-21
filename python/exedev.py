"""exe.dev SDK - Python implementation.

A thin wrapper around the exe.dev HTTPS API for programmatic VM management.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import socket
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, ECDSA
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256, SHA512
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_ssh_private_key,
)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

_SAFE_VALUE_RE = re.compile(r"^[a-zA-Z0-9._:@/\-]+$")


def _validate_identifier(value: str) -> None:
    if not _SAFE_VALUE_RE.match(value):
        raise ExeDevError(0, "invalid characters in value")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ExeDevError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"[{status_code}] {message}")


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------


@dataclass
class VM:
    vm_name: str
    status: str
    region: str = ""
    region_display: str = ""
    ssh_dest: str = ""
    https_url: str = ""
    image: str = ""
    shelley_url: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> VM:
        return cls(
            vm_name=d["vm_name"],
            status=d["status"],
            region=d.get("region", ""),
            region_display=d.get("region_display", ""),
            ssh_dest=d.get("ssh_dest", ""),
            https_url=d.get("https_url", ""),
            image=d.get("image", ""),
            shelley_url=d.get("shelley_url", ""),
        )


@dataclass
class NewVMResponse:
    vm_name: str
    ssh_command: str = ""
    ssh_dest: str = ""
    ssh_port: int = 0
    https_url: str = ""
    proxy_port: int = 0
    shelley_url: str = ""
    vscode_url: str = ""
    xterm_url: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> NewVMResponse:
        return cls(
            vm_name=d.get("vm_name", ""),
            ssh_command=d.get("ssh_command", ""),
            ssh_dest=d.get("ssh_dest", ""),
            ssh_port=d.get("ssh_port", 0),
            https_url=d.get("https_url", ""),
            proxy_port=d.get("proxy_port", 0),
            shelley_url=d.get("shelley_url", ""),
            vscode_url=d.get("vscode_url", ""),
            xterm_url=d.get("xterm_url", ""),
        )


@dataclass
class CpResponse:
    name: str = ""
    source: str = ""
    ssh: str = ""
    state: str = ""
    elapsed: float = 0.0

    @classmethod
    def from_dict(cls, d: dict) -> CpResponse:
        return cls(
            name=d.get("name", ""),
            source=d.get("source", ""),
            ssh=d.get("ssh", ""),
            state=d.get("state", ""),
            elapsed=d.get("elapsed", 0.0),
        )


@dataclass
class RmResponse:
    deleted: list[str] = field(default_factory=list)
    failed: list = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> RmResponse:
        return cls(
            deleted=d.get("deleted", []),
            failed=d.get("failed", []),
        )


@dataclass
class RestartResponse:
    status: str = ""
    vm_name: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> RestartResponse:
        return cls(
            status=d.get("status", ""),
            vm_name=d.get("vm_name", ""),
        )


@dataclass
class RenameResponse:
    old_name: str = ""
    new_name: str = ""
    status: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> RenameResponse:
        return cls(
            old_name=d.get("old_name", ""),
            new_name=d.get("new_name", ""),
            status=d.get("status", ""),
        )


@dataclass
class TagResponse:
    tags: list[str] = field(default_factory=list)
    vm_name: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> TagResponse:
        return cls(
            tags=d.get("tags", []),
            vm_name=d.get("vm_name", ""),
        )


@dataclass
class SSHKey:
    name: str
    fingerprint: str
    public_key: str = ""
    added_at: Optional[str] = None
    last_used_at: Optional[str] = None
    current: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> SSHKey:
        return cls(
            name=d.get("name", ""),
            fingerprint=d.get("fingerprint", ""),
            public_key=d.get("public_key", ""),
            added_at=d.get("added_at"),
            last_used_at=d.get("last_used_at"),
            current=d.get("current", False),
        )


@dataclass
class UserInfo:
    email: str
    ssh_keys: list[SSHKey] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> UserInfo:
        return cls(
            email=d["email"],
            ssh_keys=[SSHKey.from_dict(k) for k in d.get("ssh_keys", [])],
        )


@dataclass
class ShareInfo:
    vm_name: str
    status: str
    url: str = ""
    port: Optional[int] = None
    users: list[str] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    team_access: bool = False
    team_shelley: bool = False
    team_ssh: bool = False
    teams: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> ShareInfo:
        return cls(
            vm_name=d["vm_name"],
            status=d.get("status", "private"),
            url=d.get("url", ""),
            port=d.get("port"),
            users=d.get("users", []),
            links=d.get("links", []),
            team_access=d.get("team_access", False),
            team_shelley=d.get("team_shelley", False),
            team_ssh=d.get("team_ssh", False),
            teams=d.get("teams", []),
        )


@dataclass
class ShareUpdateResponse:
    status: str = ""
    share: str = ""
    port: int = 0
    vm_name: str = ""
    team_access: bool = False
    team_shelley: bool = False
    team_ssh: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> ShareUpdateResponse:
        return cls(
            status=d.get("status", ""),
            share=d.get("share", ""),
            port=d.get("port", 0),
            vm_name=d.get("vm_name", ""),
            team_access=d.get("team_access", False),
            team_shelley=d.get("team_shelley", False),
            team_ssh=d.get("team_ssh", False),
        )


@dataclass
class ShareAddLinkResponse:
    status: str = ""
    url: str = ""
    token: str = ""
    vm_name: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> ShareAddLinkResponse:
        return cls(
            status=d.get("status", ""),
            url=d.get("url", ""),
            token=d.get("token", ""),
            vm_name=d.get("vm_name", ""),
        )


@dataclass
class ShareReceiveEmailResponse:
    status: str = ""
    email_enabled: bool = False
    email_address: Optional[str] = None
    vm_name: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> ShareReceiveEmailResponse:
        return cls(
            status=d.get("status", ""),
            email_enabled=d.get("email_enabled", False),
            email_address=d.get("email_address"),
            vm_name=d.get("vm_name", ""),
        )


@dataclass
class TokenPermissions:
    exp: Optional[int] = None
    nbf: Optional[int] = None
    cmds: Optional[list[str]] = None
    ctx: Optional[dict[str, Any]] = None

    def to_json(self) -> str:
        d: dict[str, Any] = {}
        if self.exp is not None:
            d["exp"] = self.exp
        if self.nbf is not None:
            d["nbf"] = self.nbf
        if self.cmds is not None:
            d["cmds"] = self.cmds
        if self.ctx is not None:
            d["ctx"] = self.ctx
        return json.dumps(d, separators=(",", ":"))


# ---------------------------------------------------------------------------
# SSH Signature helpers
# ---------------------------------------------------------------------------


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _write_ssh_string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _read_ssh_string(data: bytes, offset: int) -> tuple[bytes, int]:
    length = struct.unpack(">I", data[offset : offset + 4])[0]
    return data[offset + 4 : offset + 4 + length], offset + 4 + length


# ---------------------------------------------------------------------------
# SSH Agent protocol
# ---------------------------------------------------------------------------

SSH_AGENTC_REQUEST_IDENTITIES = 11
SSH_AGENT_IDENTITIES_ANSWER = 12
SSH_AGENTC_SIGN_REQUEST = 13
SSH_AGENT_SIGN_RESPONSE = 14


def _agent_communicate(sock_path: str, msg: bytes) -> bytes:
    """Send a message to the SSH agent and return the response."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(sock_path)
        sock.sendall(struct.pack(">I", len(msg)) + msg)
        # Read response length
        resp_len_bytes = b""
        while len(resp_len_bytes) < 4:
            chunk = sock.recv(4 - len(resp_len_bytes))
            if not chunk:
                raise ExeDevError(0, "SSH agent connection closed")
            resp_len_bytes += chunk
        resp_len = struct.unpack(">I", resp_len_bytes)[0]
        # Read response body
        resp = b""
        while len(resp) < resp_len:
            chunk = sock.recv(resp_len - len(resp))
            if not chunk:
                raise ExeDevError(0, "SSH agent connection closed")
            resp += chunk
        return resp
    finally:
        sock.close()


def _agent_list_keys(sock_path: str) -> list[tuple[bytes, str]]:
    """List keys from the SSH agent. Returns list of (key_blob, comment)."""
    msg = bytes([SSH_AGENTC_REQUEST_IDENTITIES])
    resp = _agent_communicate(sock_path, msg)
    if resp[0] != SSH_AGENT_IDENTITIES_ANSWER:
        raise ExeDevError(0, "unexpected response from SSH agent")
    nkeys = struct.unpack(">I", resp[1:5])[0]
    keys = []
    offset = 5
    for _ in range(nkeys):
        key_blob, offset = _read_ssh_string(resp, offset)
        comment, offset = _read_ssh_string(resp, offset)
        keys.append((key_blob, comment.decode("utf-8", errors="replace")))
    return keys


def _agent_sign(sock_path: str, key_blob: bytes, data: bytes) -> bytes:
    """Ask the SSH agent to sign data with the given key. Returns raw sig blob."""
    msg = bytes([SSH_AGENTC_SIGN_REQUEST])
    msg += _write_ssh_string(key_blob)
    msg += _write_ssh_string(data)
    msg += struct.pack(">I", 0)  # flags
    resp = _agent_communicate(sock_path, msg)
    if resp[0] != SSH_AGENT_SIGN_RESPONSE:
        raise ExeDevError(0, "SSH agent refused to sign")
    sig_blob, _ = _read_ssh_string(resp, 1)
    return sig_blob


def _agent_sshsig(
    sock_path: str, key_blob: bytes, message: bytes, namespace: str
) -> bytes:
    """Produce an SSHSIG signature using the SSH agent."""
    # Build the SSHSIG signed data (what the agent signs)
    sig_data = b"SSHSIG"
    sig_data += _write_ssh_string(namespace.encode("utf-8"))
    sig_data += _write_ssh_string(b"")  # reserved
    hash_algo = "sha512"
    sig_data += _write_ssh_string(hash_algo.encode("utf-8"))
    h = hashlib.sha512(message).digest()
    sig_data += _write_ssh_string(h)

    # Ask agent to sign
    raw_sig = _agent_sign(sock_path, key_blob, sig_data)

    # Wrap in SSHSIG envelope
    sshsig = b"SSHSIG"
    sshsig += struct.pack(">I", 1)  # version
    sshsig += _write_ssh_string(key_blob)  # public key
    sshsig += _write_ssh_string(namespace.encode("utf-8"))
    sshsig += _write_ssh_string(b"")  # reserved
    sshsig += _write_ssh_string(hash_algo.encode("utf-8"))
    sshsig += _write_ssh_string(raw_sig)

    # PEM-encode
    b64 = base64.b64encode(sshsig).decode("ascii")
    lines = [b64[i : i + 76] for i in range(0, len(b64), 76)]
    pem = (
        "-----BEGIN SSH SIGNATURE-----\n"
        + "\n".join(lines)
        + "\n-----END SSH SIGNATURE-----"
    )
    return pem.encode("utf-8")


def _ssh_sign(private_key: Any, message: bytes, namespace: str) -> bytes:
    """Produce an SSH signature in the SSHSIG format.

    The format is defined in:
    https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig
    """
    # Magic preamble
    sig_data = b"SSHSIG"
    # Namespace
    sig_data += _write_ssh_string(namespace.encode("utf-8"))
    # Reserved (empty)
    sig_data += _write_ssh_string(b"")
    # Hash algorithm
    hash_algo = "sha512"
    sig_data += _write_ssh_string(hash_algo.encode("utf-8"))
    # H(message) — the hash of the message
    import hashlib

    h = hashlib.sha512(message).digest()
    sig_data += _write_ssh_string(h)

    # Now sign sig_data with the private key
    if isinstance(private_key, Ed25519PrivateKey):
        raw_sig = private_key.sign(sig_data)
        sig_algo = b"ssh-ed25519"
        sig_blob = _write_ssh_string(sig_algo) + _write_ssh_string(raw_sig)
        pub_key_blob = _ed25519_pub_blob(private_key)
    elif isinstance(private_key, RSAPrivateKey):
        raw_sig = private_key.sign(sig_data, PKCS1v15(), SHA512())
        sig_algo = b"rsa-sha2-512"
        sig_blob = _write_ssh_string(sig_algo) + _write_ssh_string(raw_sig)
        pub_key_blob = _rsa_pub_blob(private_key)
    elif isinstance(private_key, EllipticCurvePrivateKey):
        raw_sig = private_key.sign(sig_data, ECDSA(SHA256()))
        r, s = decode_dss_signature(raw_sig)
        key_size = private_key.key_size
        byte_len = (key_size + 7) // 8
        ecdsa_sig_blob = _write_ssh_string(
            r.to_bytes(byte_len, "big")
        ) + _write_ssh_string(s.to_bytes(byte_len, "big"))
        curve_name = _ecdsa_curve_name(private_key)
        sig_algo = f"ecdsa-sha2-{curve_name}".encode("utf-8")
        sig_blob = _write_ssh_string(sig_algo) + _write_ssh_string(ecdsa_sig_blob)
        pub_key_blob = _ecdsa_pub_blob(private_key)
    else:
        raise ExeDevError(0, f"unsupported key type: {type(private_key).__name__}")

    # Build the full SSHSIG blob
    # Version
    version = struct.pack(">I", 1)
    # Public key (serialized)
    pub_key = _write_ssh_string(pub_key_blob)
    # Namespace
    ns_bytes = _write_ssh_string(namespace.encode("utf-8"))
    # Reserved
    reserved = _write_ssh_string(b"")
    # Hash algorithm
    hash_alg = _write_ssh_string(hash_algo.encode("utf-8"))
    # Signature
    signature = _write_ssh_string(sig_blob)

    sshsig = b"SSHSIG" + version + pub_key + ns_bytes + reserved + hash_alg + signature

    # Wrap in PEM-like armor
    b64 = base64.b64encode(sshsig).decode("ascii")
    lines = [b64[i : i + 76] for i in range(0, len(b64), 76)]
    pem = (
        "-----BEGIN SSH SIGNATURE-----\n"
        + "\n".join(lines)
        + "\n-----END SSH SIGNATURE-----"
    )
    return pem.encode("utf-8")


def _ed25519_pub_blob(key: Ed25519PrivateKey) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pub = key.public_key()
    raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return _write_ssh_string(b"ssh-ed25519") + _write_ssh_string(raw)


def _rsa_pub_blob(key: RSAPrivateKey) -> bytes:
    pub = key.public_key().public_numbers()
    e_bytes = pub.e.to_bytes((pub.e.bit_length() + 7) // 8, "big")
    n_bytes = pub.n.to_bytes((pub.n.bit_length() + 7) // 8, "big")
    # Ensure leading zero for sign
    if n_bytes[0] & 0x80:
        n_bytes = b"\x00" + n_bytes
    if e_bytes[0] & 0x80:
        e_bytes = b"\x00" + e_bytes
    return (
        _write_ssh_string(b"ssh-rsa")
        + _write_ssh_string(e_bytes)
        + _write_ssh_string(n_bytes)
    )


def _ecdsa_curve_name(key: EllipticCurvePrivateKey) -> str:
    from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, SECP384R1, SECP521R1

    curve = key.curve
    if isinstance(curve, SECP256R1):
        return "nistp256"
    elif isinstance(curve, SECP384R1):
        return "nistp384"
    elif isinstance(curve, SECP521R1):
        return "nistp521"
    raise ExeDevError(0, f"unsupported ECDSA curve: {curve.name}")


def _ecdsa_pub_blob(key: EllipticCurvePrivateKey) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pub = key.public_key()
    point = pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    curve_name = _ecdsa_curve_name(key)
    key_type = f"ecdsa-sha2-{curve_name}".encode("utf-8")
    return (
        _write_ssh_string(key_type)
        + _write_ssh_string(curve_name.encode("utf-8"))
        + _write_ssh_string(point)
    )


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class Client:
    def __init__(
        self,
        private_key: str | bytes | Path | None = None,
        base_url: str = "https://exe.dev",
        permissions: Optional[TokenPermissions] = None,
        agent_sock: Optional[str] = None,
    ):
        self._base_url = base_url.rstrip("/")
        self._default_permissions = permissions or TokenPermissions()

        if private_key is not None:
            self._key = self._load_key(private_key)
            self._agent_sock = None
            self._agent_key_blob = None
        else:
            self._key = None
            self._agent_sock = agent_sock or os.environ.get("SSH_AUTH_SOCK")
            if not self._agent_sock:
                raise ExeDevError(0, "no private key or SSH agent available")
            # Verify agent is connectable and get the first key
            try:
                keys = _agent_list_keys(self._agent_sock)
            except (OSError, ExeDevError):
                raise ExeDevError(0, "cannot connect to SSH agent")
            if not keys:
                raise ExeDevError(0, "SSH agent has no keys")
            self._agent_key_blob = keys[0][0]

    @staticmethod
    def _load_key(source: str | bytes | Path) -> Any:
        if isinstance(source, Path):
            source = source.read_bytes()
        elif isinstance(source, str):
            if os.path.isfile(source):
                source = Path(source).read_bytes()
            else:
                source = source.encode("utf-8")

        # Try PEM first, then OpenSSH format
        for loader in (load_pem_private_key, load_ssh_private_key):
            try:
                key = loader(source, password=None)
                if isinstance(key, (Ed25519PrivateKey, RSAPrivateKey, EllipticCurvePrivateKey)):
                    return key
                raise ExeDevError(0, f"unsupported key type: {type(key).__name__}")
            except Exception as e:
                if isinstance(e, ExeDevError):
                    raise
                continue
        raise ExeDevError(0, "invalid or unreadable private key")

    # -- Token generation ---------------------------------------------------

    def generate_token(self, permissions: Optional[TokenPermissions] = None) -> str:
        return self._make_token(permissions or self._default_permissions, "v0@exe.dev")

    def generate_vm_token(
        self, vm_name: str, permissions: Optional[TokenPermissions] = None
    ) -> str:
        _validate_identifier(vm_name)
        namespace = f"v0@{vm_name}.exe.xyz"
        return self._make_token(permissions or self._default_permissions, namespace)

    def _make_token(self, permissions: TokenPermissions, namespace: str) -> str:
        payload_json = permissions.to_json()
        payload_bytes = payload_json.encode("utf-8")

        # base64url encode payload
        b64_payload = _b64url_encode(payload_bytes)

        # Sign the raw JSON bytes — local key or agent
        if self._key is not None:
            pem_sig = _ssh_sign(self._key, payload_bytes, namespace)
        else:
            pem_sig = _agent_sshsig(
                self._agent_sock, self._agent_key_blob, payload_bytes, namespace
            )

        # Extract signature blob from PEM
        lines = pem_sig.decode("utf-8").strip().split("\n")
        b64_content = "".join(
            line for line in lines if not line.startswith("-----")
        )
        sig_bytes = base64.b64decode(b64_content)
        b64_sig = _b64url_encode(sig_bytes)

        token = f"exe0.{b64_payload}.{b64_sig}"
        if len(token) > 8192:
            raise ExeDevError(0, "token exceeds 8KB limit")
        return token

    # -- Internal exec ------------------------------------------------------

    def _exec(self, command: str) -> str:
        token = self.generate_token()
        url = f"{self._base_url}/exec"
        req = Request(
            url,
            data=command.encode("utf-8"),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "text/plain",
            },
            method="POST",
        )
        try:
            with urlopen(req) as resp:
                return resp.read().decode("utf-8")
        except HTTPError as e:
            body = e.read().decode("utf-8") if e.fp else str(e)
            raise ExeDevError(e.code, body)

    # -- VM Management ------------------------------------------------------

    def ls(self, all: bool = False, detailed: bool = False) -> list[VM]:
        parts = ["ls"]
        if all:
            parts.append("-a")
        if detailed:
            parts.append("-l")
        parts.append("--json")
        body = self._exec(" ".join(parts))
        data = json.loads(body)
        # API returns {"vms": [...]} or bare [...]
        if isinstance(data, dict):
            data = data.get("vms", [])
        return [VM.from_dict(v) for v in data]

    def new(
        self,
        name: Optional[str] = None,
        image: Optional[str] = None,
        command: Optional[str] = None,
        env: Optional[dict[str, str]] = None,
        integration: Optional[list[str]] = None,
        prompt: Optional[str] = None,
        no_email: bool = False,
    ) -> NewVMResponse:
        parts = ["new"]
        if name is not None:
            _validate_identifier(name)
            parts.append(f"--name={name}")
        if image is not None:
            parts.append(f"--image={image}")
        if command is not None:
            parts.append(f"--command={command}")
        if env:
            for k, v in env.items():
                parts.append(f"--env={k}={v}")
        if integration:
            for i in integration:
                parts.append(f"--integration={i}")
        if prompt is not None:
            parts.append(f'--prompt="{prompt}"')
        if no_email:
            parts.append("--no-email")
        parts.append("--json")
        body = self._exec(" ".join(parts))
        return NewVMResponse.from_dict(json.loads(body))

    def rm(self, *vm_names: str) -> RmResponse:
        if not vm_names:
            raise ExeDevError(0, "at least one VM name is required")
        for n in vm_names:
            _validate_identifier(n)
        body = self._exec("rm " + " ".join(vm_names))
        return RmResponse.from_dict(json.loads(body))

    def restart(self, vm_name: str) -> RestartResponse:
        _validate_identifier(vm_name)
        body = self._exec(f"restart {vm_name}")
        return RestartResponse.from_dict(json.loads(body))

    def rename(self, vm_name: str, new_name: str) -> RenameResponse:
        _validate_identifier(vm_name)
        _validate_identifier(new_name)
        body = self._exec(f"rename {vm_name} {new_name}")
        return RenameResponse.from_dict(json.loads(body))

    def cp(self, vm_name: str, new_name: Optional[str] = None) -> CpResponse:
        _validate_identifier(vm_name)
        parts = ["cp", vm_name]
        if new_name is not None:
            _validate_identifier(new_name)
            parts.append(new_name)
        parts.append("--json")
        body = self._exec(" ".join(parts))
        return CpResponse.from_dict(json.loads(body))

    def tag(self, vm_name: str, tag_name: str) -> TagResponse:
        _validate_identifier(vm_name)
        _validate_identifier(tag_name)
        body = self._exec(f"tag {vm_name} {tag_name}")
        return TagResponse.from_dict(json.loads(body))

    def untag(self, vm_name: str, tag_name: str) -> TagResponse:
        _validate_identifier(vm_name)
        _validate_identifier(tag_name)
        body = self._exec(f"tag -d {vm_name} {tag_name}")
        return TagResponse.from_dict(json.loads(body))

    # -- Sharing & Access ---------------------------------------------------

    def share_show(self, vm_name: str) -> ShareInfo:
        _validate_identifier(vm_name)
        body = self._exec(f"share show {vm_name} --json")
        return ShareInfo.from_dict(json.loads(body))

    def share_set_public(self, vm_name: str) -> ShareUpdateResponse:
        _validate_identifier(vm_name)
        body = self._exec(f"share set-public {vm_name}")
        return ShareUpdateResponse.from_dict(json.loads(body))

    def share_set_private(self, vm_name: str) -> ShareUpdateResponse:
        _validate_identifier(vm_name)
        body = self._exec(f"share set-private {vm_name}")
        return ShareUpdateResponse.from_dict(json.loads(body))

    def share_port(self, vm_name: str, port: int) -> ShareUpdateResponse:
        if port < 1 or port > 65535:
            raise ExeDevError(0, "port must be between 1 and 65535")
        _validate_identifier(vm_name)
        body = self._exec(f"share port {vm_name} {port}")
        return ShareUpdateResponse.from_dict(json.loads(body))

    def share_add(self, vm_name: str, email: str) -> None:
        _validate_identifier(vm_name)
        self._exec(f"share add {vm_name} {email}")

    def share_remove(self, vm_name: str, email: str) -> None:
        _validate_identifier(vm_name)
        self._exec(f"share remove {vm_name} {email}")

    def share_add_link(self, vm_name: str) -> ShareAddLinkResponse:
        _validate_identifier(vm_name)
        body = self._exec(f"share add-link {vm_name} --json")
        return ShareAddLinkResponse.from_dict(json.loads(body))

    def share_remove_link(self, vm_name: str) -> None:
        _validate_identifier(vm_name)
        self._exec(f"share remove-link {vm_name}")

    def share_receive_email(self, vm_name: str, enabled: bool) -> ShareReceiveEmailResponse:
        _validate_identifier(vm_name)
        state = "on" if enabled else "off"
        body = self._exec(f"share receive-email {vm_name} {state}")
        return ShareReceiveEmailResponse.from_dict(json.loads(body))

    # -- SSH Key Management -------------------------------------------------

    def ssh_key_list(self) -> list[SSHKey]:
        body = self._exec("ssh-key list --json")
        data = json.loads(body)
        # API returns {"ssh_keys": [...]}
        if isinstance(data, dict):
            data = data.get("ssh_keys", [])
        return [SSHKey.from_dict(k) for k in data]

    def ssh_key_add(self, public_key: str) -> None:
        self._exec(f"ssh-key add {public_key}")

    def ssh_key_remove(self, fingerprint: str) -> None:
        self._exec(f"ssh-key remove {fingerprint}")

    def ssh_key_rename(self, fingerprint: str, new_name: str) -> None:
        self._exec(f"ssh-key rename {fingerprint} {new_name}")

    # -- User ---------------------------------------------------------------

    def whoami(self) -> UserInfo:
        body = self._exec("whoami --json")
        return UserInfo.from_dict(json.loads(body))

    # -- Shelley Agent ------------------------------------------------------

    def shelley_install(self, vm_name: str) -> None:
        _validate_identifier(vm_name)
        self._exec(f"shelley install {vm_name}")

    def shelley_prompt(self, vm_name: str, prompt: str) -> None:
        _validate_identifier(vm_name)
        self._exec(f'shelley prompt {vm_name} "{prompt}"')
