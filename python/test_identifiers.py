"""Identifier validation regression tests, over real HTTP.

Each test drives the client against a local HTTP server that records every
request. An invalid identifier must raise ExeDevError with status 0, and the
server must see no request at all.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from exedev import Client, ExeDevError

from test_exedev import TEST_KEY_PEM


# Response bodies from the verified fixtures, keyed by the command's first word.
RESPONSES = {
    "new": '{"vm_name":"example-vm","ssh_command":"ssh example-vm.exe.xyz","ssh_dest":"example-vm.exe.xyz","ssh_port":22,"https_url":"https://example-vm.exe.xyz","proxy_port":8000,"shelley_url":"https://example-vm.shelley.exe.xyz","vscode_url":"vscode://vscode-remote/ssh-remote+example-vm.exe.xyz/home/exedev?windowId=_blank"}',
    "rm": '{"deleted":["example-vm-copy"],"failed":[]}',
    "restart": '{"status":"restarted","vm_name":"example-vm"}',
    "rename": '{"new_name":"example-vm-renamed","old_name":"example-vm","status":"renamed"}',
    "cp": '{"elapsed":1.06002825,"name":"example-vm-copy","source":"example-vm-renamed","ssh":"example-vm-copy.exe.xyz","state":"starting"}',
    "tag": '{"tags":["testtag"],"vm_name":"example-vm"}',
    "share show": '{"links":[],"port":8000,"status":"private","team_access":false,"team_shelley":false,"team_ssh":false,"teams":[],"url":"https://example-vm.exe.xyz","users":[],"vm_name":"example-vm"}',
    "share add-link": '{"status":"success","token":"GNFM5GK72LOIQ32TVZOBDPJI4I","url":"https://example-vm.exe.xyz?share=GNFM5GK72LOIQ32TVZOBDPJI4I","vm_name":"example-vm"}',
    "share receive-email": '{"email_enabled":false,"status":"success","vm_name":"example-vm"}',
    "share": '{"port":8000,"share":"public","status":"updated","team_access":false,"team_shelley":false,"team_ssh":false,"vm_name":"example-vm"}',
}


class RecordingServer:
    """A local exe.dev stand-in that records each request and replays a fixture."""

    def __init__(self):
        self.requests: list[dict] = []
        recorded = self.requests

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                command = body.decode("utf-8")
                recorded.append({"path": self.path, "body": command})
                reply = "{}"
                for prefix in sorted(RESPONSES, key=len, reverse=True):
                    if command.startswith(prefix):
                        reply = RESPONSES[prefix]
                        break
                data = reply.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._httpd.timeout = 0.05
        self.url = f"http://127.0.0.1:{self._httpd.server_port}"
        # A stop flag, not serve_forever(): shutdown() deadlocks if it runs
        # before serve_forever() starts, which happens when no request is sent.
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            self._httpd.handle_request()

    def close(self):
        self._stop.set()
        self._thread.join()
        self._httpd.server_close()


@pytest.fixture(scope="module")
def shared_server():
    s = RecordingServer()
    yield s
    s.close()


@pytest.fixture
def server(shared_server):
    shared_server.requests.clear()
    return shared_server


@pytest.fixture
def client(server):
    return Client(TEST_KEY_PEM, base_url=server.url)


# Each entry calls one method with the identifier under test in one argument.
# The other arguments hold valid values.
CALLS = {
    "new(name)": lambda c, v: c.new(name=v),
    "rm(first)": lambda c, v: c.rm(v),
    "rm(second)": lambda c, v: c.rm("dev", v),
    "restart": lambda c, v: c.restart(v),
    "rename(vm_name)": lambda c, v: c.rename(v, "dev2"),
    "rename(new_name)": lambda c, v: c.rename("dev", v),
    "cp(vm_name)": lambda c, v: c.cp(v),
    "cp(new_name)": lambda c, v: c.cp("dev", v),
    "tag(vm_name)": lambda c, v: c.tag(v, "t1"),
    "tag(tag_name)": lambda c, v: c.tag("dev", v),
    "untag(vm_name)": lambda c, v: c.untag(v, "t1"),
    "untag(tag_name)": lambda c, v: c.untag("dev", v),
    "share_show": lambda c, v: c.share_show(v),
    "share_set_public": lambda c, v: c.share_set_public(v),
    "share_set_private": lambda c, v: c.share_set_private(v),
    "share_port": lambda c, v: c.share_port(v, 3000),
    "share_add": lambda c, v: c.share_add(v, "user@example.com"),
    "share_remove": lambda c, v: c.share_remove(v, "user@example.com"),
    "share_add_link": lambda c, v: c.share_add_link(v),
    "share_remove_link": lambda c, v: c.share_remove_link(v),
    "share_receive_email": lambda c, v: c.share_receive_email(v, True),
    "ssh_key_rename(new_name)": lambda c, v: c.ssh_key_rename("SHA256:abc123", v),
    "shelley_install": lambda c, v: c.shelley_install(v),
    "shelley_prompt": lambda c, v: c.shelley_prompt(v, "hello"),
    "generate_vm_token": lambda c, v: c.generate_vm_token(v),
}

INVALID_CHARS = {
    "dot-dot": "..",
    "parent dir": "../etc",
    "slash": "vm/x",
    "absolute path": "/etc/passwd",
    "dot": "vm.x",
    "colon": "vm:x",
    "at": "vm@x",
    "space": "vm name",
    "semicolon": "vm;ls",
    "pipe": "vm|ls",
    "ampersand": "vm&ls",
    "subshell": "vm$(id)",
    "backtick": "vm`id`",
    "single quote": "vm'x",
    "double quote": 'vm"x',
    "redirect": "vm>out",
    "glob": "vm*",
    "trailing newline": "vm\n",
    "newline": "vm\nls",
    "tab": "vm\tx",
    "nul": "vm\x00x",
    "leading hyphen": "-d",
    "long flag": "--help",
    "leading underscore": "_vm",
    "cyrillic a": "vаm",
    "greek omicron": "vm-ο",
    "fullwidth letters": "ｖｍ",
    "unicode hyphen": "vm‐x",
    "non-breaking hyphen": "vm‑x",
    "fullwidth digit": "vm１",
    "zero-width space": "vm​x",
    "accented letter": "vm-é",
}


@pytest.mark.parametrize("call", CALLS)
@pytest.mark.parametrize("value", INVALID_CHARS.values(), ids=INVALID_CHARS.keys())
def test_invalid_characters_never_reach_the_server(client, server, call, value):
    with pytest.raises(ExeDevError) as exc:
        CALLS[call](client, value)
    assert exc.value.status_code == 0
    assert exc.value.message == "invalid characters in value"
    assert server.requests == []


@pytest.mark.parametrize("call", CALLS)
def test_empty_identifier_never_reaches_the_server(client, server, call):
    with pytest.raises(ExeDevError) as exc:
        CALLS[call](client, "")
    assert exc.value.status_code == 0
    assert exc.value.message == "value must not be empty"
    assert server.requests == []


@pytest.mark.parametrize("call", CALLS)
def test_too_long_identifier_never_reaches_the_server(client, server, call):
    with pytest.raises(ExeDevError) as exc:
        CALLS[call](client, "a" * 64)
    assert exc.value.status_code == 0
    assert exc.value.message == "value exceeds 63 characters"
    assert server.requests == []


@pytest.mark.parametrize("call", CALLS)
@pytest.mark.parametrize("value", [None, 7, b"dev"], ids=["none", "int", "bytes"])
def test_non_string_identifier_never_reaches_the_server(client, server, call, value):
    if value is None and call in ("new(name)", "cp(new_name)"):
        pytest.skip("None means the optional name is omitted")
    with pytest.raises(ExeDevError) as exc:
        CALLS[call](client, value)
    assert exc.value.status_code == 0
    assert server.requests == []


VALID = ["a", "0", "dev", "my-cool-vm", "my_vm_2", "9lives", "A-B_c", "a" * 63]


@pytest.mark.parametrize("value", VALID)
def test_valid_identifiers_are_sent_unchanged(client, server, value):
    client.restart(value)
    client.rename(value, value)
    client.tag(value, value)
    client.rm(value, value)
    client.new(name=value)
    assert [r["body"] for r in server.requests] == [
        f"restart {value}",
        f"rename {value} {value}",
        f"tag {value} {value}",
        f"rm {value} {value}",
        f"new --name={value} --json",
    ]
    assert {r["path"] for r in server.requests} == {"/exec"}


def test_restart_parent_dir_is_rejected_before_the_request(client, server):
    with pytest.raises(ExeDevError) as exc:
        client.restart("../etc")
    assert (exc.value.status_code, exc.value.message) == (0, "invalid characters in value")
    assert server.requests == []
    # The same client still works for a valid name afterwards.
    result = client.restart("example-vm")
    assert result.status == "restarted"
    assert server.requests == [{"path": "/exec", "body": "restart example-vm"}]


def test_one_bad_name_in_rm_sends_nothing(client, server):
    with pytest.raises(ExeDevError):
        client.rm("vm1", "vm2", "../vm3")
    assert server.requests == []
