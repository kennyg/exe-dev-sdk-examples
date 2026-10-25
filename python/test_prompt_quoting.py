"""Regression tests: a prompt reaches the server as exactly one shell word.

The client talks to a real HTTP server on 127.0.0.1. Each test checks the
request body two ways: with `shlex.split` (POSIX mode) and by running it in
`/bin/sh` with `shelley` and `new` defined as functions that print their
arguments. Both must give back the exact prompt.
"""

import shlex
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from exedev import Client
from test_exedev import TEST_KEY_PEM

PROMPTS = [
    'say "hi"; echo pwned',
    "it's here",
    "back\\slash",
    "trailing backslash\\",
    'escaped \\" quote',
    "$(echo pwned)",
    "`echo pwned`",
    "$HOME ${HOME} $1 $$",
    "line one\nline two",
    "backslash then newline\\\nnext",
    "crlf\r\nline",
    "a; b && c || d | e > f < g & h",
    "tab\there",
    "!history !! !-1",
    "*glob? [abc] ~user {a,b}",
    "非ASCII テキスト — café, emoji 🚀",
    "",
    " leading and trailing spaces ",
    "\"'\\$`;\n",
]

NEW_VM_BODY = (
    '{"vm_name":"dev","ssh_command":"ssh dev.exe.xyz","ssh_dest":"dev.exe.xyz",'
    '"ssh_port":22,"https_url":"https://dev.exe.xyz","proxy_port":8000,'
    '"shelley_url":"https://dev.shelley.exe.xyz",'
    '"vscode_url":"vscode://vscode-remote/ssh-remote+dev.exe.xyz/home/exedev?windowId=_blank",'
    '"xterm_url":"https://dev.xterm.exe.xyz"}'
)


class RecordingServer:
    """Records every POST /exec body. Answers `new` with a VM and others with 200."""

    def __init__(self):
        self.bodies: list[str] = []
        state = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"])).decode("utf-8")
                state.bodies.append(body)
                reply = NEW_VM_BODY.encode() if body.startswith("new ") else b""
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, args=(0.01,), daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server():
    s = RecordingServer()
    yield s
    s.close()


@pytest.fixture
def client(server):
    return Client(TEST_KEY_PEM, base_url=server.url)


def sh_words(body: str) -> list[str]:
    """Run body in /bin/sh, where the command prints each argument NUL-terminated."""
    script = (
        "shelley() { printf '%s\\0' shelley \"$@\"; }\n"
        "new() { printf '%s\\0' new \"$@\"; }\n" + body
    )
    out = subprocess.run(["/bin/sh", "-c", script], capture_output=True, check=True)
    return out.stdout.decode("utf-8").split("\0")[:-1]


needs_sh = pytest.mark.skipif(shutil.which("sh") is None, reason="needs /bin/sh")


@pytest.mark.parametrize("prompt", PROMPTS)
class TestShelleyPromptQuoting:
    def test_shlex_gives_exact_prompt(self, client, server, prompt):
        client.shelley_prompt("dev", prompt)
        assert len(server.bodies) == 1
        assert shlex.split(server.bodies[0]) == ["shelley", "prompt", "dev", prompt]

    @needs_sh
    def test_sh_gives_exact_prompt(self, client, server, prompt):
        client.shelley_prompt("dev", prompt)
        assert sh_words(server.bodies[0]) == ["shelley", "prompt", "dev", prompt]


@pytest.mark.parametrize("prompt", PROMPTS)
class TestNewPromptQuoting:
    def test_shlex_gives_exact_prompt(self, client, server, prompt):
        client.new(name="dev", prompt=prompt)
        assert len(server.bodies) == 1
        assert shlex.split(server.bodies[0]) == ["new", "--name=dev", f"--prompt={prompt}", "--json"]

    @needs_sh
    def test_sh_gives_exact_prompt(self, client, server, prompt):
        client.new(name="dev", prompt=prompt)
        assert sh_words(server.bodies[0]) == ["new", "--name=dev", f"--prompt={prompt}", "--json"]


def test_plain_prompt_keeps_spec_form(client, server):
    client.shelley_prompt("dev", "create a hello world app")
    assert server.bodies == ['shelley prompt dev "create a hello world app"']


def test_breakout_prompt_is_escaped(client, server):
    client.shelley_prompt("dev", 'say "hi"; echo $(id) `id` \\')
    want = r'''shelley prompt dev "say "'"'"hi"'"'"; echo "'$'"(id) "'`'"id"'`'" "'\'""'''
    assert server.bodies == [want]
