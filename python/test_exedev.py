"""Tests for exe.dev Python SDK — derived from tests.yaml."""

import json
from dataclasses import dataclass
from typing import Optional

import pytest

from exedev import (
    Client,
    ExeDevError,
    TokenPermissions,
    VM,
    SSHKey,
    ShareInfo,
    UserInfo,
    _b64url_decode,
)


# ---------------------------------------------------------------------------
# Test key (ed25519) — generated for testing only, not used anywhere real
# ---------------------------------------------------------------------------

TEST_KEY_PEM = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDYOnCWL+/RkJNAPgZ4FOF/YZji29aaMyo4kO4eiG5UDwAAAIilWPkTpVj5
EwAAAAtzc2gtZWQyNTUxOQAAACDYOnCWL+/RkJNAPgZ4FOF/YZji29aaMyo4kO4eiG5UDw
AAAEA+1GTntsT5m7J5flVw7seFHtMA6jX1+ZEiYhLXdsRJLdg6cJYv79GQk0A+BngU4X9h
mOLb1pozKjiQ7h6IblQPAAAABHRlc3QB
-----END OPENSSH PRIVATE KEY-----"""


# ---------------------------------------------------------------------------
# Mock HTTP helper
# ---------------------------------------------------------------------------


@dataclass
class MockResponse:
    status: int
    body: str


class MockHTTP:
    """Intercepts Client._exec to mock HTTP without actually calling urlopen."""

    def __init__(self):
        self.responses: list[MockResponse] = []
        self.last_command: Optional[str] = None

    def respond(self, status: int, body: str):
        self.responses.append(MockResponse(status, body))

    def mock_exec(self, command: str) -> str:
        self.last_command = command
        if not self.responses:
            raise RuntimeError("No mock response configured")
        resp = self.responses.pop(0)
        if resp.status >= 400:
            raise ExeDevError(resp.status, resp.body)
        return resp.body


@pytest.fixture
def mock_http():
    return MockHTTP()


@pytest.fixture
def client(mock_http):
    c = Client(TEST_KEY_PEM)
    c._exec = mock_http.mock_exec
    return c


# ---------------------------------------------------------------------------
# ls tests — API returns {"vms": [...]}
# ---------------------------------------------------------------------------


class TestLs:
    def test_basic(self, client, mock_http):
        mock_http.respond(
            200,
            '{"vms":[{"vm_name":"web","status":"running","region":"pdx","region_display":"Oregon, USA","ssh_dest":"web.exe.xyz","https_url":"https://web.exe.xyz","image":"boldsoftware/exeuntu","shelley_url":"https://web.shelley.exe.xyz"}]}',
        )
        vms = client.ls()
        assert mock_http.last_command == "ls --json"
        assert len(vms) == 1
        assert vms[0].vm_name == "web"
        assert vms[0].status == "running"
        assert vms[0].region == "pdx"
        assert vms[0].region_display == "Oregon, USA"
        assert vms[0].ssh_dest == "web.exe.xyz"
        assert vms[0].https_url == "https://web.exe.xyz"
        assert vms[0].image == "boldsoftware/exeuntu"

    def test_include_team(self, client, mock_http):
        mock_http.respond(200, '{"vms":[]}')
        client.ls(all=True)
        assert mock_http.last_command == "ls -a --json"

    def test_detailed(self, client, mock_http):
        mock_http.respond(200, '{"vms":[]}')
        client.ls(detailed=True)
        assert mock_http.last_command == "ls -l --json"

    def test_all_flags(self, client, mock_http):
        mock_http.respond(200, '{"vms":[]}')
        client.ls(all=True, detailed=True)
        assert mock_http.last_command == "ls -a -l --json"

    def test_empty_list(self, client, mock_http):
        mock_http.respond(200, '{"vms":[]}')
        vms = client.ls()
        assert vms == []

    def test_multiple(self, client, mock_http):
        mock_http.respond(
            200,
            '{"vms":[{"vm_name":"web","status":"running","region":"pdx","region_display":"Oregon, USA","ssh_dest":"web.exe.xyz","https_url":"https://web.exe.xyz","image":"boldsoftware/exeuntu","shelley_url":"https://web.shelley.exe.xyz"},'
            '{"vm_name":"api","status":"stopped","region":"pdx","region_display":"Oregon, USA","ssh_dest":"api.exe.xyz","https_url":"https://api.exe.xyz","image":"boldsoftware/exeuntu","shelley_url":"https://api.shelley.exe.xyz"}]}',
        )
        vms = client.ls()
        assert len(vms) == 2
        assert vms[0].vm_name == "web"
        assert vms[1].vm_name == "api"
        assert vms[1].status == "stopped"

    def test_auth_error(self, client, mock_http):
        mock_http.respond(401, '{"error":"invalid token"}')
        with pytest.raises(ExeDevError) as exc:
            client.ls()
        assert exc.value.status_code == 401

    def test_unknown_fields_ignored(self, client, mock_http):
        mock_http.respond(
            200,
            '{"vms":[{"vm_name":"web","status":"running","region":"pdx","region_display":"Oregon, USA","ssh_dest":"web.exe.xyz","https_url":"https://web.exe.xyz","image":"boldsoftware/exeuntu","future_field":"should_be_ignored"}]}',
        )
        vms = client.ls()
        assert len(vms) == 1
        assert vms[0].vm_name == "web"


# ---------------------------------------------------------------------------
# new tests
# ---------------------------------------------------------------------------


class TestNew:
    VM_RESP = '{"vm_name":"%s","status":"starting","region":"pdx","region_display":"Oregon, USA","ssh_dest":"%s.exe.xyz","https_url":"https://%s.exe.xyz","image":"boldsoftware/exeuntu","shelley_url":"https://%s.shelley.exe.xyz"}'

    def _vm_resp(self, name):
        return self.VM_RESP % (name, name, name, name)

    def test_no_options(self, client, mock_http):
        mock_http.respond(200, self._vm_resp("zany-fox"))
        vm = client.new()
        assert mock_http.last_command == "new --json"
        assert vm.vm_name == "zany-fox"
        assert vm.status == "starting"

    def test_with_name(self, client, mock_http):
        mock_http.respond(200, self._vm_resp("my-project"))
        vm = client.new(name="my-project")
        assert mock_http.last_command == "new --name=my-project --json"
        assert vm.vm_name == "my-project"

    def test_with_image(self, client, mock_http):
        mock_http.respond(200, self._vm_resp("happy-cat"))
        client.new(image="ubuntu:24.04")
        assert mock_http.last_command == "new --image=ubuntu:24.04 --json"

    def test_with_env_vars(self, client, mock_http):
        mock_http.respond(200, self._vm_resp("api-server"))
        client.new(name="api-server", env={"NODE_ENV": "production", "PORT": "3000"})
        cmd = mock_http.last_command
        assert cmd.startswith("new --name=api-server")
        assert "--env=NODE_ENV=production" in cmd
        assert "--env=PORT=3000" in cmd
        assert cmd.endswith("--json")

    def test_with_integrations(self, client, mock_http):
        mock_http.respond(200, self._vm_resp("dev"))
        client.new(name="dev", integration=["github"])
        assert mock_http.last_command == "new --name=dev --integration=github --json"

    def test_with_command(self, client, mock_http):
        mock_http.respond(200, self._vm_resp("swift-owl"))
        client.new(image="nginx:latest", command="none")
        assert mock_http.last_command == "new --image=nginx:latest --command=none --json"

    def test_no_email(self, client, mock_http):
        mock_http.respond(200, self._vm_resp("quiet-vm"))
        client.new(name="quiet-vm", no_email=True)
        assert mock_http.last_command == "new --name=quiet-vm --no-email --json"

    def test_all_options(self, client, mock_http):
        mock_http.respond(200, self._vm_resp("full"))
        client.new(
            name="full",
            image="ubuntu:24.04",
            command="auto",
            env={"KEY": "val"},
            integration=["github"],
            no_email=True,
        )
        cmd = mock_http.last_command
        assert cmd.startswith("new --name=full --image=ubuntu:24.04 --command=auto")
        assert "--env=KEY=val" in cmd
        assert "--integration=github" in cmd
        assert "--no-email" in cmd
        assert cmd.endswith("--json")

    def test_rate_limited(self, client, mock_http):
        mock_http.respond(429, "rate limited")
        with pytest.raises(ExeDevError) as exc:
            client.new()
        assert exc.value.status_code == 429


# ---------------------------------------------------------------------------
# rm tests
# ---------------------------------------------------------------------------


class TestRm:
    def test_single(self, client, mock_http):
        mock_http.respond(200, "")
        client.rm("old-project")
        assert mock_http.last_command == "rm old-project"

    def test_multiple(self, client, mock_http):
        mock_http.respond(200, "")
        client.rm("vm1", "vm2", "vm3")
        assert mock_http.last_command == "rm vm1 vm2 vm3"

    def test_not_found(self, client, mock_http):
        mock_http.respond(422, '{"error":"vm not found: nonexistent"}')
        with pytest.raises(ExeDevError) as exc:
            client.rm("nonexistent")
        assert exc.value.status_code == 422

    def test_empty_list(self, client, mock_http):
        with pytest.raises(ExeDevError) as exc:
            client.rm()
        assert exc.value.status_code == 0
        assert exc.value.message == "at least one VM name is required"


# ---------------------------------------------------------------------------
# restart tests
# ---------------------------------------------------------------------------


class TestRestart:
    def test_restart(self, client, mock_http):
        mock_http.respond(200, "")
        client.restart("web")
        assert mock_http.last_command == "restart web"

    def test_not_found(self, client, mock_http):
        mock_http.respond(422, '{"error":"vm not found: ghost"}')
        with pytest.raises(ExeDevError) as exc:
            client.restart("ghost")
        assert exc.value.status_code == 422


# ---------------------------------------------------------------------------
# rename tests
# ---------------------------------------------------------------------------


class TestRename:
    def test_rename(self, client, mock_http):
        mock_http.respond(200, "")
        client.rename("old-name", "new-name")
        assert mock_http.last_command == "rename old-name new-name"


# ---------------------------------------------------------------------------
# cp tests
# ---------------------------------------------------------------------------


class TestCp:
    def test_auto_name(self, client, mock_http):
        mock_http.respond(
            200,
            '{"vm_name":"web-copy","status":"starting","region":"pdx","region_display":"Oregon, USA","ssh_dest":"web-copy.exe.xyz","https_url":"https://web-copy.exe.xyz","image":"boldsoftware/exeuntu","shelley_url":"https://web-copy.shelley.exe.xyz"}',
        )
        vm = client.cp("web")
        assert mock_http.last_command == "cp web --json"
        assert vm.vm_name == "web-copy"

    def test_custom_name(self, client, mock_http):
        mock_http.respond(
            200,
            '{"vm_name":"web-staging","status":"starting","region":"pdx","region_display":"Oregon, USA","ssh_dest":"web-staging.exe.xyz","https_url":"https://web-staging.exe.xyz","image":"boldsoftware/exeuntu","shelley_url":"https://web-staging.shelley.exe.xyz"}',
        )
        vm = client.cp("web", new_name="web-staging")
        assert mock_http.last_command == "cp web web-staging --json"
        assert vm.vm_name == "web-staging"


# ---------------------------------------------------------------------------
# tag / untag tests
# ---------------------------------------------------------------------------


class TestTag:
    def test_add_tag(self, client, mock_http):
        mock_http.respond(200, "")
        client.tag("web", "production")
        assert mock_http.last_command == "tag web production"

    def test_remove_tag(self, client, mock_http):
        mock_http.respond(200, "")
        client.untag("web", "staging")
        assert mock_http.last_command == "tag -d web staging"


# ---------------------------------------------------------------------------
# share tests
# ---------------------------------------------------------------------------


class TestShare:
    def test_show(self, client, mock_http):
        mock_http.respond(
            200,
            '{"vm_name":"web","status":"private","url":"https://web.exe.xyz","port":8080,"users":["alice@example.com"],"links":[],"team_access":false,"team_shelley":false,"team_ssh":false,"teams":[]}',
        )
        result = client.share_show("web")
        assert mock_http.last_command == "share show web --json"
        assert isinstance(result, ShareInfo)
        assert result.vm_name == "web"
        assert result.status == "private"
        assert result.port == 8080
        assert result.users == ["alice@example.com"]
        assert result.links == []
        assert result.team_access is False

    def test_show_public_with_link(self, client, mock_http):
        mock_http.respond(
            200,
            '{"vm_name":"web","status":"public","url":"https://web.exe.xyz","port":null,"users":[],"links":["https://exe.dev/s/abc123"],"team_access":true,"team_shelley":false,"team_ssh":true,"teams":["engineering"]}',
        )
        result = client.share_show("web")
        assert result.status == "public"
        assert result.links == ["https://exe.dev/s/abc123"]
        assert result.team_access is True

    def test_set_public(self, client, mock_http):
        mock_http.respond(200, "")
        client.share_set_public("web")
        assert mock_http.last_command == "share set-public web"

    def test_set_private(self, client, mock_http):
        mock_http.respond(200, "")
        client.share_set_private("web")
        assert mock_http.last_command == "share set-private web"

    def test_port(self, client, mock_http):
        mock_http.respond(200, "")
        client.share_port("web", 3000)
        assert mock_http.last_command == "share port web 3000"

    def test_port_invalid_zero(self, client, mock_http):
        with pytest.raises(ExeDevError) as exc:
            client.share_port("web", 0)
        assert exc.value.status_code == 0
        assert exc.value.message == "port must be between 1 and 65535"

    def test_port_invalid_too_high(self, client, mock_http):
        with pytest.raises(ExeDevError) as exc:
            client.share_port("web", 70000)
        assert exc.value.status_code == 0
        assert exc.value.message == "port must be between 1 and 65535"

    def test_add_user(self, client, mock_http):
        mock_http.respond(200, "")
        client.share_add("web", "alice@example.com")
        assert mock_http.last_command == "share add web alice@example.com"

    def test_remove_user(self, client, mock_http):
        mock_http.respond(200, "")
        client.share_remove("web", "alice@example.com")
        assert mock_http.last_command == "share remove web alice@example.com"

    def test_add_link(self, client, mock_http):
        mock_http.respond(200, '{"link":"https://exe.dev/s/xyz789"}')
        link = client.share_add_link("web")
        assert mock_http.last_command == "share add-link web --json"
        assert link == "https://exe.dev/s/xyz789"

    def test_remove_link(self, client, mock_http):
        mock_http.respond(200, "")
        client.share_remove_link("web")
        assert mock_http.last_command == "share remove-link web"

    def test_receive_email_on(self, client, mock_http):
        mock_http.respond(200, "")
        client.share_receive_email("web", True)
        assert mock_http.last_command == "share receive-email web on"

    def test_receive_email_off(self, client, mock_http):
        mock_http.respond(200, "")
        client.share_receive_email("web", False)
        assert mock_http.last_command == "share receive-email web off"


# ---------------------------------------------------------------------------
# ssh_key tests — API returns {"ssh_keys": [...]}
# ---------------------------------------------------------------------------


class TestSSHKey:
    def test_list(self, client, mock_http):
        mock_http.respond(
            200,
            '{"ssh_keys":[{"name":"laptop","fingerprint":"SHA256:abc123","public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample","added_at":"2024-01-15T00:00:00Z","last_used_at":"2024-06-01T12:00:00Z","current":false}]}',
        )
        keys = client.ssh_key_list()
        assert mock_http.last_command == "ssh-key list --json"
        assert len(keys) == 1
        assert keys[0].name == "laptop"
        assert keys[0].fingerprint == "SHA256:abc123"
        assert keys[0].public_key == "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"

    def test_list_empty(self, client, mock_http):
        mock_http.respond(200, '{"ssh_keys":[]}')
        keys = client.ssh_key_list()
        assert keys == []

    def test_add(self, client, mock_http):
        mock_http.respond(200, "")
        client.ssh_key_add("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample laptop")
        assert (
            mock_http.last_command
            == "ssh-key add ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample laptop"
        )

    def test_remove(self, client, mock_http):
        mock_http.respond(200, "")
        client.ssh_key_remove("SHA256:abc123")
        assert mock_http.last_command == "ssh-key remove SHA256:abc123"

    def test_rename(self, client, mock_http):
        mock_http.respond(200, "")
        client.ssh_key_rename("SHA256:abc123", "work-laptop")
        assert mock_http.last_command == "ssh-key rename SHA256:abc123 work-laptop"


# ---------------------------------------------------------------------------
# whoami tests — API returns {"email":..., "ssh_keys":[...]}
# ---------------------------------------------------------------------------


class TestWhoami:
    def test_basic(self, client, mock_http):
        mock_http.respond(
            200,
            '{"email":"user@example.com","ssh_keys":[{"name":"laptop","fingerprint":"SHA256:abc123","public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample","added_at":"2024-01-15T00:00:00Z","last_used_at":"2024-06-01T12:00:00Z","current":false}]}',
        )
        info = client.whoami()
        assert mock_http.last_command == "whoami --json"
        assert info.email == "user@example.com"
        assert len(info.ssh_keys) == 1
        assert info.ssh_keys[0].name == "laptop"

    def test_forbidden(self, client, mock_http):
        mock_http.respond(403, '{"error":"command not allowed"}')
        with pytest.raises(ExeDevError) as exc:
            client.whoami()
        assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# shelley tests
# ---------------------------------------------------------------------------


class TestShelley:
    def test_install(self, client, mock_http):
        mock_http.respond(200, "")
        client.shelley_install("dev")
        assert mock_http.last_command == "shelley install dev"

    def test_prompt(self, client, mock_http):
        mock_http.respond(200, "")
        client.shelley_prompt("dev", "create a hello world app")
        assert mock_http.last_command == 'shelley prompt dev "create a hello world app"'


# ---------------------------------------------------------------------------
# input validation tests
# ---------------------------------------------------------------------------


class TestValidation:
    def test_reject_spaces(self, client, mock_http):
        with pytest.raises(ExeDevError) as exc:
            client.rm("bad name")
        assert exc.value.status_code == 0
        assert exc.value.message == "invalid characters in value"

    def test_reject_semicolons(self, client, mock_http):
        with pytest.raises(ExeDevError) as exc:
            client.restart("vm;rm -rf /")
        assert exc.value.status_code == 0
        assert exc.value.message == "invalid characters in value"

    def test_reject_pipes(self, client, mock_http):
        with pytest.raises(ExeDevError) as exc:
            client.restart("vm|cat /etc/passwd")
        assert exc.value.status_code == 0
        assert exc.value.message == "invalid characters in value"

    def test_accept_hyphens(self, client, mock_http):
        mock_http.respond(200, "")
        client.restart("my-cool-vm")
        assert mock_http.last_command == "restart my-cool-vm"

    def test_accept_underscores(self, client, mock_http):
        mock_http.respond(200, "")
        client.restart("my_vm_2")
        assert mock_http.last_command == "restart my_vm_2"


# ---------------------------------------------------------------------------
# token generation tests
# ---------------------------------------------------------------------------


class TestTokenGeneration:
    def test_empty_permissions(self):
        client = Client(TEST_KEY_PEM)
        token = client.generate_token()
        assert token.startswith("exe0.")
        parts = token.split(".")
        assert len(parts) == 3
        payload = _b64url_decode(parts[1]).decode("utf-8")
        assert payload == "{}"

    def test_permissions_with_expiry(self):
        client = Client(TEST_KEY_PEM)
        perms = TokenPermissions(exp=1735689600)
        token = client.generate_token(perms)
        assert token.startswith("exe0.")
        parts = token.split(".")
        assert len(parts) == 3
        payload = _b64url_decode(parts[1]).decode("utf-8")
        assert payload == '{"exp":1735689600}'

    def test_permissions_with_cmds(self):
        client = Client(TEST_KEY_PEM)
        perms = TokenPermissions(cmds=["ls", "whoami"])
        token = client.generate_token(perms)
        parts = token.split(".")
        payload = _b64url_decode(parts[1]).decode("utf-8")
        assert payload == '{"cmds":["ls","whoami"]}'

    def test_permissions_all_fields(self):
        client = Client(TEST_KEY_PEM)
        perms = TokenPermissions(
            exp=1735689600, nbf=1735686000, cmds=["ls"], ctx={"role": "readonly"}
        )
        token = client.generate_token(perms)
        parts = token.split(".")
        payload_data = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
        assert set(payload_data.keys()) == {"exp", "nbf", "cmds", "ctx"}

    def test_vm_scoped_token(self):
        client = Client(TEST_KEY_PEM)
        token = client.generate_vm_token("my-vm")
        assert token.startswith("exe0.")
        parts = token.split(".")
        assert len(parts) == 3


# ---------------------------------------------------------------------------
# error response tests
# ---------------------------------------------------------------------------


class TestErrorResponses:
    @pytest.mark.parametrize(
        "status,body",
        [
            (400, '{"error":"empty request body"}'),
            (401, '{"error":"token expired"}'),
            (403, '{"error":"command not in cmds list"}'),
            (404, '{"error":"unknown command"}'),
            (413, "request body too large"),
            (429, "too many requests"),
            (500, "internal server error"),
            (504, "command timed out"),
        ],
    )
    def test_error_code(self, client, mock_http, status, body):
        mock_http.respond(status, body)
        with pytest.raises(ExeDevError) as exc:
            client.ls()
        assert exc.value.status_code == status
        assert exc.value.message == body

    def test_422_rm(self, client, mock_http):
        mock_http.respond(422, '{"error":"vm not found"}')
        with pytest.raises(ExeDevError) as exc:
            client.rm("ghost")
        assert exc.value.status_code == 422
        assert exc.value.message == '{"error":"vm not found"}'
