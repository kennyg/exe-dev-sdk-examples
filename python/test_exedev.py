"""Tests for exe.dev Python SDK — derived from tests.yaml v0.2.0."""

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
    NewVMResponse,
    CpResponse,
    RmResponse,
    RestartResponse,
    RenameResponse,
    TagResponse,
    ShareUpdateResponse,
    ShareAddLinkResponse,
    ShareReceiveEmailResponse,
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
            '{"vms":[{"vm_name":"my-app","status":"running","region":"pdx","region_display":"Oregon, USA","ssh_dest":"my-app.exe.xyz","https_url":"https://my-app.exe.xyz","image":"boldsoftware/exeuntu","shelley_url":"https://my-app.shelley.exe.xyz"}]}',
        )
        vms = client.ls()
        assert mock_http.last_command == "ls --json"
        assert len(vms) == 1
        assert vms[0].vm_name == "my-app"
        assert vms[0].status == "running"
        assert vms[0].region == "pdx"
        assert vms[0].region_display == "Oregon, USA"
        assert vms[0].ssh_dest == "my-app.exe.xyz"
        assert vms[0].https_url == "https://my-app.exe.xyz"
        assert vms[0].image == "boldsoftware/exeuntu"
        assert vms[0].shelley_url == "https://my-app.shelley.exe.xyz"

    def test_include_team(self, client, mock_http):
        mock_http.respond(200, '{"vms":[]}')
        result = client.ls(all=True)
        assert mock_http.last_command == "ls -a --json"
        assert result == []

    def test_detailed(self, client, mock_http):
        mock_http.respond(200, '{"vms":[]}')
        result = client.ls(detailed=True)
        assert mock_http.last_command == "ls -l --json"
        assert result == []

    def test_all_flags(self, client, mock_http):
        mock_http.respond(200, '{"vms":[]}')
        result = client.ls(all=True, detailed=True)
        assert mock_http.last_command == "ls -a -l --json"
        assert result == []

    def test_empty_list(self, client, mock_http):
        mock_http.respond(200, '{"vms":[]}')
        vms = client.ls()
        assert mock_http.last_command == "ls --json"
        assert vms == []

    def test_multiple(self, client, mock_http):
        mock_http.respond(
            200,
            '{"vms":[{"vm_name":"my-app","status":"running","region":"pdx","region_display":"Oregon, USA","ssh_dest":"my-app.exe.xyz","https_url":"https://my-app.exe.xyz","image":"boldsoftware/exeuntu","shelley_url":"https://my-app.shelley.exe.xyz"},{"vm_name":"dev-server","status":"running","region":"pdx","region_display":"Oregon, USA","ssh_dest":"dev-server.exe.xyz","https_url":"https://dev-server.exe.xyz","image":"boldsoftware/exeuntu","shelley_url":"https://dev-server.shelley.exe.xyz"}]}',
        )
        vms = client.ls()
        assert len(vms) == 2
        assert vms[0].vm_name == "my-app"
        assert vms[0].status == "running"
        assert vms[0].region == "pdx"
        assert vms[1].vm_name == "dev-server"
        assert vms[1].status == "running"
        assert vms[1].region == "pdx"

    def test_auth_error(self, client, mock_http):
        mock_http.respond(401, '{"error":"invalid token"}')
        with pytest.raises(ExeDevError) as exc:
            client.ls()
        assert exc.value.status_code == 401
        assert exc.value.message == '{"error":"invalid token"}'

    def test_unknown_fields_ignored(self, client, mock_http):
        mock_http.respond(
            200,
            '{"vms":[{"vm_name":"my-app","status":"running","region":"pdx","region_display":"Oregon, USA","ssh_dest":"my-app.exe.xyz","https_url":"https://my-app.exe.xyz","image":"boldsoftware/exeuntu","shelley_url":"https://my-app.shelley.exe.xyz","future_field":"should_be_ignored"}]}',
        )
        vms = client.ls()
        assert len(vms) == 1
        assert vms[0].vm_name == "my-app"
        assert vms[0].status == "running"
        assert vms[0].region == "pdx"


# ---------------------------------------------------------------------------
# new tests — API returns NewVMResponse
# ---------------------------------------------------------------------------


class TestNew:
    def test_no_options(self, client, mock_http):
        mock_http.respond(
            200,
            '{"vm_name":"example-vm","ssh_command":"ssh example-vm.exe.xyz","ssh_dest":"example-vm.exe.xyz","ssh_port":22,"https_url":"https://example-vm.exe.xyz","proxy_port":8000,"shelley_url":"https://example-vm.shelley.exe.xyz","vscode_url":"vscode://vscode-remote/ssh-remote+example-vm.exe.xyz/home/exedev?windowId=_blank","xterm_url":"https://example-vm.xterm.exe.xyz"}',
        )
        result = client.new()
        assert mock_http.last_command == "new --json"
        assert isinstance(result, NewVMResponse)
        assert result.vm_name == "example-vm"
        assert result.ssh_command == "ssh example-vm.exe.xyz"
        assert result.ssh_dest == "example-vm.exe.xyz"
        assert result.ssh_port == 22
        assert result.https_url == "https://example-vm.exe.xyz"
        assert result.proxy_port == 8000
        assert result.shelley_url == "https://example-vm.shelley.exe.xyz"
        assert result.vscode_url == "vscode://vscode-remote/ssh-remote+example-vm.exe.xyz/home/exedev?windowId=_blank"
        assert result.xterm_url == "https://example-vm.xterm.exe.xyz"

    def test_with_name(self, client, mock_http):
        mock_http.respond(
            200,
            '{"vm_name":"my-project","ssh_command":"ssh my-project.exe.xyz","ssh_dest":"my-project.exe.xyz","ssh_port":22,"https_url":"https://my-project.exe.xyz","proxy_port":8000,"shelley_url":"https://my-project.shelley.exe.xyz","vscode_url":"vscode://vscode-remote/ssh-remote+my-project.exe.xyz/home/exedev?windowId=_blank","xterm_url":"https://my-project.xterm.exe.xyz"}',
        )
        result = client.new(name="my-project")
        assert mock_http.last_command == "new --name=my-project --json"
        assert isinstance(result, NewVMResponse)
        assert result.vm_name == "my-project"
        assert result.ssh_command == "ssh my-project.exe.xyz"
        assert result.proxy_port == 8000

    def test_with_image(self, client, mock_http):
        mock_http.respond(
            200,
            '{"vm_name":"happy-cat","ssh_command":"ssh happy-cat.exe.xyz","ssh_dest":"happy-cat.exe.xyz","ssh_port":22,"https_url":"https://happy-cat.exe.xyz","proxy_port":8000,"shelley_url":"https://happy-cat.shelley.exe.xyz","vscode_url":"vscode://vscode-remote/ssh-remote+happy-cat.exe.xyz/home/exedev?windowId=_blank","xterm_url":"https://happy-cat.xterm.exe.xyz"}',
        )
        result = client.new(image="ubuntu:24.04")
        assert mock_http.last_command == "new --image=ubuntu:24.04 --json"
        assert isinstance(result, NewVMResponse)
        assert result.vm_name == "happy-cat"
        assert result.ssh_command == "ssh happy-cat.exe.xyz"

    def test_with_env_vars(self, client, mock_http):
        mock_http.respond(
            200,
            '{"vm_name":"api-server","ssh_command":"ssh api-server.exe.xyz","ssh_dest":"api-server.exe.xyz","ssh_port":22,"https_url":"https://api-server.exe.xyz","proxy_port":8000,"shelley_url":"https://api-server.shelley.exe.xyz","vscode_url":"vscode://vscode-remote/ssh-remote+api-server.exe.xyz/home/exedev?windowId=_blank","xterm_url":"https://api-server.xterm.exe.xyz"}',
        )
        result = client.new(name="api-server", env={"NODE_ENV": "production", "PORT": "3000"})
        cmd = mock_http.last_command
        assert cmd.startswith("new --name=api-server")
        assert "--env=NODE_ENV=production" in cmd
        assert "--env=PORT=3000" in cmd
        assert cmd.endswith("--json")
        assert isinstance(result, NewVMResponse)
        assert result.vm_name == "api-server"
        assert result.ssh_command == "ssh api-server.exe.xyz"

    def test_with_integrations(self, client, mock_http):
        mock_http.respond(
            200,
            '{"vm_name":"dev","ssh_command":"ssh dev.exe.xyz","ssh_dest":"dev.exe.xyz","ssh_port":22,"https_url":"https://dev.exe.xyz","proxy_port":8000,"shelley_url":"https://dev.shelley.exe.xyz","vscode_url":"vscode://vscode-remote/ssh-remote+dev.exe.xyz/home/exedev?windowId=_blank","xterm_url":"https://dev.xterm.exe.xyz"}',
        )
        result = client.new(name="dev", integration=["github"])
        assert mock_http.last_command == "new --name=dev --integration=github --json"
        assert isinstance(result, NewVMResponse)
        assert result.vm_name == "dev"
        assert result.ssh_command == "ssh dev.exe.xyz"

    def test_with_command(self, client, mock_http):
        mock_http.respond(
            200,
            '{"vm_name":"swift-owl","ssh_command":"ssh swift-owl.exe.xyz","ssh_dest":"swift-owl.exe.xyz","ssh_port":22,"https_url":"https://swift-owl.exe.xyz","proxy_port":8000,"shelley_url":"https://swift-owl.shelley.exe.xyz","vscode_url":"vscode://vscode-remote/ssh-remote+swift-owl.exe.xyz/home/exedev?windowId=_blank","xterm_url":"https://swift-owl.xterm.exe.xyz"}',
        )
        result = client.new(image="nginx:latest", command="none")
        assert mock_http.last_command == "new --image=nginx:latest --command=none --json"
        assert isinstance(result, NewVMResponse)
        assert result.vm_name == "swift-owl"
        assert result.ssh_command == "ssh swift-owl.exe.xyz"

    def test_no_email(self, client, mock_http):
        mock_http.respond(
            200,
            '{"vm_name":"quiet-vm","ssh_command":"ssh quiet-vm.exe.xyz","ssh_dest":"quiet-vm.exe.xyz","ssh_port":22,"https_url":"https://quiet-vm.exe.xyz","proxy_port":8000,"shelley_url":"https://quiet-vm.shelley.exe.xyz","vscode_url":"vscode://vscode-remote/ssh-remote+quiet-vm.exe.xyz/home/exedev?windowId=_blank","xterm_url":"https://quiet-vm.xterm.exe.xyz"}',
        )
        result = client.new(name="quiet-vm", no_email=True)
        assert mock_http.last_command == "new --name=quiet-vm --no-email --json"
        assert isinstance(result, NewVMResponse)
        assert result.vm_name == "quiet-vm"
        assert result.ssh_command == "ssh quiet-vm.exe.xyz"

    def test_all_options(self, client, mock_http):
        mock_http.respond(
            200,
            '{"vm_name":"full","ssh_command":"ssh full.exe.xyz","ssh_dest":"full.exe.xyz","ssh_port":22,"https_url":"https://full.exe.xyz","proxy_port":8000,"shelley_url":"https://full.shelley.exe.xyz","vscode_url":"vscode://vscode-remote/ssh-remote+full.exe.xyz/home/exedev?windowId=_blank","xterm_url":"https://full.xterm.exe.xyz"}',
        )
        result = client.new(
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
        assert isinstance(result, NewVMResponse)
        assert result.vm_name == "full"
        assert result.ssh_command == "ssh full.exe.xyz"

    def test_rate_limited(self, client, mock_http):
        mock_http.respond(429, "rate limited")
        with pytest.raises(ExeDevError) as exc:
            client.new()
        assert exc.value.status_code == 429
        assert exc.value.message == "rate limited"


# ---------------------------------------------------------------------------
# rm tests — API returns {"deleted":[...],"failed":[]}
# ---------------------------------------------------------------------------


class TestRm:
    def test_single(self, client, mock_http):
        mock_http.respond(200, '{"deleted":["old-project"],"failed":[]}')
        result = client.rm("old-project")
        assert mock_http.last_command == "rm old-project"
        assert isinstance(result, RmResponse)
        assert result.deleted == ["old-project"]
        assert result.failed == []

    def test_multiple(self, client, mock_http):
        mock_http.respond(200, '{"deleted":["vm1","vm2","vm3"],"failed":[]}')
        result = client.rm("vm1", "vm2", "vm3")
        assert mock_http.last_command == "rm vm1 vm2 vm3"
        assert isinstance(result, RmResponse)
        assert result.deleted == ["vm1", "vm2", "vm3"]
        assert result.failed == []

    def test_not_found(self, client, mock_http):
        mock_http.respond(422, '{"error":"vm not found: nonexistent"}')
        with pytest.raises(ExeDevError) as exc:
            client.rm("nonexistent")
        assert exc.value.status_code == 422
        assert exc.value.message == '{"error":"vm not found: nonexistent"}'

    def test_empty_list(self, client, mock_http):
        with pytest.raises(ExeDevError) as exc:
            client.rm()
        assert exc.value.status_code == 0
        assert exc.value.message == "at least one VM name is required"


# ---------------------------------------------------------------------------
# restart tests — API returns {"status":"restarted","vm_name":"..."}
# ---------------------------------------------------------------------------


class TestRestart:
    def test_restart(self, client, mock_http):
        mock_http.respond(200, '{"status":"restarted","vm_name":"example-vm"}')
        result = client.restart("example-vm")
        assert mock_http.last_command == "restart example-vm"
        assert isinstance(result, RestartResponse)
        assert result.status == "restarted"
        assert result.vm_name == "example-vm"

    def test_not_found(self, client, mock_http):
        mock_http.respond(422, '{"error":"vm not found: ghost"}')
        with pytest.raises(ExeDevError) as exc:
            client.restart("ghost")
        assert exc.value.status_code == 422
        assert exc.value.message == '{"error":"vm not found: ghost"}'


# ---------------------------------------------------------------------------
# rename tests — API returns {"new_name":"...","old_name":"...","status":"renamed"}
# ---------------------------------------------------------------------------


class TestRename:
    def test_rename(self, client, mock_http):
        mock_http.respond(
            200,
            '{"new_name":"example-vm-renamed","old_name":"example-vm","status":"renamed"}',
        )
        result = client.rename("example-vm", "example-vm-renamed")
        assert mock_http.last_command == "rename example-vm example-vm-renamed"
        assert isinstance(result, RenameResponse)
        assert result.old_name == "example-vm"
        assert result.new_name == "example-vm-renamed"
        assert result.status == "renamed"


# ---------------------------------------------------------------------------
# cp tests — API returns CpResponse (uses "name"/"state", not "vm_name"/"status")
# ---------------------------------------------------------------------------


class TestCp:
    def test_auto_name(self, client, mock_http):
        mock_http.respond(
            200,
            '{"elapsed":1.06002825,"name":"example-vm-copy","source":"example-vm-renamed","ssh":"example-vm-copy.exe.xyz","state":"starting"}',
        )
        result = client.cp("example-vm-renamed")
        assert mock_http.last_command == "cp example-vm-renamed --json"
        assert isinstance(result, CpResponse)
        assert result.name == "example-vm-copy"
        assert result.source == "example-vm-renamed"
        assert result.ssh == "example-vm-copy.exe.xyz"
        assert result.state == "starting"
        assert result.elapsed == 1.06002825

    def test_custom_name(self, client, mock_http):
        mock_http.respond(
            200,
            '{"elapsed":0.95,"name":"web-staging","source":"web","ssh":"web-staging.exe.xyz","state":"starting"}',
        )
        result = client.cp("web", new_name="web-staging")
        assert mock_http.last_command == "cp web web-staging --json"
        assert isinstance(result, CpResponse)
        assert result.name == "web-staging"
        assert result.source == "web"
        assert result.ssh == "web-staging.exe.xyz"
        assert result.state == "starting"


# ---------------------------------------------------------------------------
# tag tests — API returns {"tags":[...],"vm_name":"..."}
# ---------------------------------------------------------------------------


class TestTag:
    def test_add_tag(self, client, mock_http):
        mock_http.respond(200, '{"tags":["testtag"],"vm_name":"example-vm"}')
        result = client.tag("example-vm", "testtag")
        assert mock_http.last_command == "tag example-vm testtag"
        assert isinstance(result, TagResponse)
        assert result.tags == ["testtag"]
        assert result.vm_name == "example-vm"

    def test_add_tag_invalid_hyphen(self, client, mock_http):
        mock_http.respond(
            422,
            '{"error":"invalid tag name \\"test-tag\\": must match [a-z][a-z0-9_]*"}',
        )
        with pytest.raises(ExeDevError) as exc:
            client.tag("example-vm", "test-tag")
        assert exc.value.status_code == 422


# ---------------------------------------------------------------------------
# untag tests — API returns TagResponse
# ---------------------------------------------------------------------------


class TestUntag:
    def test_remove_tag(self, client, mock_http):
        mock_http.respond(200, '{"tags":[],"vm_name":"example-vm"}')
        result = client.untag("example-vm", "testtag")
        assert mock_http.last_command == "tag -d example-vm testtag"
        assert isinstance(result, TagResponse)
        assert result.tags == []
        assert result.vm_name == "example-vm"


# ---------------------------------------------------------------------------
# share_show tests — API returns ShareInfo
# ---------------------------------------------------------------------------


class TestShareShow:
    def test_show_private(self, client, mock_http):
        mock_http.respond(
            200,
            '{"links":[],"port":8000,"status":"private","team_access":false,"team_shelley":false,"team_ssh":false,"teams":[],"url":"https://my-app.exe.xyz","users":[],"vm_name":"my-app"}',
        )
        result = client.share_show("my-app")
        assert mock_http.last_command == "share show my-app --json"
        assert isinstance(result, ShareInfo)
        assert result.vm_name == "my-app"
        assert result.status == "private"
        assert result.url == "https://my-app.exe.xyz"
        assert isinstance(result.port, int)
        assert result.port == 8000
        assert result.users == []
        assert result.links == []
        assert result.team_access is False
        assert result.team_shelley is False
        assert result.team_ssh is False
        assert result.teams == []

    def test_show_public(self, client, mock_http):
        mock_http.respond(
            200,
            '{"links":[],"port":3000,"status":"public","team_access":false,"team_shelley":false,"team_ssh":false,"teams":[],"url":"https://example-vm.exe.xyz","users":[],"vm_name":"example-vm"}',
        )
        result = client.share_show("example-vm")
        assert mock_http.last_command == "share show example-vm --json"
        assert isinstance(result, ShareInfo)
        assert result.vm_name == "example-vm"
        assert result.status == "public"
        assert result.url == "https://example-vm.exe.xyz"
        assert isinstance(result.port, int)
        assert result.port == 3000
        assert result.links == []
        assert result.team_access is False

    def test_show_fresh(self, client, mock_http):
        mock_http.respond(
            200,
            '{"links":[],"port":8000,"status":"private","team_access":false,"team_shelley":false,"team_ssh":false,"teams":[],"url":"https://example-vm.exe.xyz","users":[],"vm_name":"example-vm"}',
        )
        result = client.share_show("example-vm")
        assert mock_http.last_command == "share show example-vm --json"
        assert isinstance(result, ShareInfo)
        assert result.vm_name == "example-vm"
        assert result.status == "private"
        assert isinstance(result.port, int)
        assert result.port == 8000


# ---------------------------------------------------------------------------
# share_set_public / share_set_private tests — API returns ShareUpdateResponse
# ---------------------------------------------------------------------------


class TestShareSetPublic:
    def test_set_public(self, client, mock_http):
        mock_http.respond(
            200,
            '{"port":8000,"share":"public","status":"updated","team_access":false,"team_shelley":false,"team_ssh":false,"vm_name":"example-vm"}',
        )
        result = client.share_set_public("example-vm")
        assert mock_http.last_command == "share set-public example-vm"
        assert isinstance(result, ShareUpdateResponse)
        assert result.status == "updated"
        assert result.share == "public"
        assert result.port == 8000
        assert result.vm_name == "example-vm"
        assert result.team_access is False
        assert result.team_shelley is False
        assert result.team_ssh is False


class TestShareSetPrivate:
    def test_set_private(self, client, mock_http):
        mock_http.respond(
            200,
            '{"port":3000,"share":"private","status":"updated","team_access":false,"team_shelley":false,"team_ssh":false,"vm_name":"example-vm"}',
        )
        result = client.share_set_private("example-vm")
        assert mock_http.last_command == "share set-private example-vm"
        assert isinstance(result, ShareUpdateResponse)
        assert result.status == "updated"
        assert result.share == "private"
        assert result.port == 3000
        assert result.vm_name == "example-vm"
        assert result.team_access is False
        assert result.team_shelley is False
        assert result.team_ssh is False


# ---------------------------------------------------------------------------
# share_port tests — API returns ShareUpdateResponse
# ---------------------------------------------------------------------------


class TestSharePort:
    def test_set_port(self, client, mock_http):
        mock_http.respond(
            200,
            '{"port":3000,"share":"public","status":"updated","team_access":false,"team_shelley":false,"team_ssh":false,"vm_name":"example-vm"}',
        )
        result = client.share_port("example-vm", 3000)
        assert mock_http.last_command == "share port example-vm 3000"
        assert isinstance(result, ShareUpdateResponse)
        assert result.status == "updated"
        assert result.share == "public"
        assert result.port == 3000
        assert result.vm_name == "example-vm"

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


# ---------------------------------------------------------------------------
# share_add / share_remove tests — void responses
# ---------------------------------------------------------------------------


class TestShareAddRemove:
    def test_add_user(self, client, mock_http):
        mock_http.respond(200, "")
        client.share_add("web", "alice@example.com")
        assert mock_http.last_command == "share add web alice@example.com"

    def test_remove_user(self, client, mock_http):
        mock_http.respond(200, "")
        client.share_remove("web", "alice@example.com")
        assert mock_http.last_command == "share remove web alice@example.com"


# ---------------------------------------------------------------------------
# share_add_link tests — API returns ShareAddLinkResponse
# ---------------------------------------------------------------------------


class TestShareAddLink:
    def test_add_link(self, client, mock_http):
        mock_http.respond(
            200,
            '{"status":"success","token":"GNFM5GK72LOIQ32TVZOBDPJI4I","url":"https://example-vm.exe.xyz?share=GNFM5GK72LOIQ32TVZOBDPJI4I","vm_name":"example-vm"}',
        )
        result = client.share_add_link("example-vm")
        assert mock_http.last_command == "share add-link example-vm --json"
        assert isinstance(result, ShareAddLinkResponse)
        assert result.status == "success"
        assert result.token == "GNFM5GK72LOIQ32TVZOBDPJI4I"
        assert result.url == "https://example-vm.exe.xyz?share=GNFM5GK72LOIQ32TVZOBDPJI4I"
        assert result.vm_name == "example-vm"


# ---------------------------------------------------------------------------
# share_remove_link tests — void response
# ---------------------------------------------------------------------------


class TestShareRemoveLink:
    def test_remove_link(self, client, mock_http):
        mock_http.respond(200, "")
        client.share_remove_link("web")
        assert mock_http.last_command == "share remove-link web"


# ---------------------------------------------------------------------------
# share_receive_email tests — API returns ShareReceiveEmailResponse
# ---------------------------------------------------------------------------


class TestShareReceiveEmail:
    def test_enable_email(self, client, mock_http):
        mock_http.respond(
            200,
            '{"email_address":"anything@example-vm.exe.xyz","email_enabled":true,"status":"success","vm_name":"example-vm"}',
        )
        result = client.share_receive_email("example-vm", True)
        assert mock_http.last_command == "share receive-email example-vm on"
        assert isinstance(result, ShareReceiveEmailResponse)
        assert result.email_enabled is True
        assert result.status == "success"
        assert result.vm_name == "example-vm"
        assert result.email_address == "anything@example-vm.exe.xyz"

    def test_disable_email(self, client, mock_http):
        mock_http.respond(
            200,
            '{"email_enabled":false,"status":"success","vm_name":"example-vm"}',
        )
        result = client.share_receive_email("example-vm", False)
        assert mock_http.last_command == "share receive-email example-vm off"
        assert isinstance(result, ShareReceiveEmailResponse)
        assert result.email_enabled is False
        assert result.status == "success"
        assert result.vm_name == "example-vm"


# ---------------------------------------------------------------------------
# ssh_key tests — API returns {"ssh_keys": [...]}
# ---------------------------------------------------------------------------


class TestSSHKey:
    def test_list(self, client, mock_http):
        mock_http.respond(
            200,
            '{"ssh_keys":[{"public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyData","fingerprint":"SHA256:ExampleFingerprint123","name":"key-1","added_at":"2026-01-01T12:58:15Z","last_used_at":"2026-03-21T11:36:27Z","current":false}]}',
        )
        keys = client.ssh_key_list()
        assert mock_http.last_command == "ssh-key list --json"
        assert len(keys) == 1
        assert keys[0].name == "key-1"
        assert keys[0].fingerprint == "SHA256:ExampleFingerprint123"
        assert keys[0].public_key == "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyData"
        assert keys[0].added_at == "2026-01-01T12:58:15Z"
        assert keys[0].last_used_at == "2026-03-21T11:36:27Z"
        assert keys[0].current is False

    def test_list_empty(self, client, mock_http):
        mock_http.respond(200, '{"ssh_keys":[]}')
        keys = client.ssh_key_list()
        assert mock_http.last_command == "ssh-key list --json"
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
# Note: whoami ssh_keys do NOT include added_at/last_used_at
# ---------------------------------------------------------------------------


class TestWhoami:
    def test_basic(self, client, mock_http):
        mock_http.respond(
            200,
            '{"email":"user@example.com","ssh_keys":[{"public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyData","fingerprint":"SHA256:ExampleFingerprint123","name":"key-1","current":false}]}',
        )
        info = client.whoami()
        assert mock_http.last_command == "whoami --json"
        assert isinstance(info, UserInfo)
        assert info.email == "user@example.com"
        assert len(info.ssh_keys) == 1
        assert info.ssh_keys[0].name == "key-1"
        assert info.ssh_keys[0].fingerprint == "SHA256:ExampleFingerprint123"
        assert info.ssh_keys[0].public_key == "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyData"
        assert info.ssh_keys[0].current is False

    def test_forbidden(self, client, mock_http):
        mock_http.respond(403, '{"error":"command not allowed"}')
        with pytest.raises(ExeDevError) as exc:
            client.whoami()
        assert exc.value.status_code == 403
        assert exc.value.message == '{"error":"command not allowed"}'


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
        mock_http.respond(200, '{"status":"restarted","vm_name":"my-cool-vm"}')
        result = client.restart("my-cool-vm")
        assert mock_http.last_command == "restart my-cool-vm"
        assert isinstance(result, RestartResponse)
        assert result.status == "restarted"
        assert result.vm_name == "my-cool-vm"

    def test_accept_underscores(self, client, mock_http):
        mock_http.respond(200, '{"status":"restarted","vm_name":"my_vm_2"}')
        result = client.restart("my_vm_2")
        assert mock_http.last_command == "restart my_vm_2"
        assert isinstance(result, RestartResponse)
        assert result.status == "restarted"
        assert result.vm_name == "my_vm_2"


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
        assert token.startswith("exe0.")
        parts = token.split(".")
        assert len(parts) == 3
        payload = _b64url_decode(parts[1]).decode("utf-8")
        assert payload == '{"cmds":["ls","whoami"]}'

    def test_permissions_all_fields(self):
        client = Client(TEST_KEY_PEM)
        perms = TokenPermissions(
            exp=1735689600, nbf=1735686000, cmds=["ls"], ctx={"role": "readonly"}
        )
        token = client.generate_token(perms)
        assert token.startswith("exe0.")
        parts = token.split(".")
        assert len(parts) == 3
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
