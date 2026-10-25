"""Shared fixtures: a local HTTP server that stands in for exe.dev."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from exedev import Client

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
