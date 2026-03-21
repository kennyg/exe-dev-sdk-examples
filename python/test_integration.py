"""Integration tests for exe.dev Python SDK.

These tests hit the real API. They are skipped unless the required
environment variables are set.

Required env vars:
    EXEDEV_AGENT_SOCK   - Path to SSH agent socket (e.g. 1Password agent)
    EXEDEV_TEST_VM      - Name of a VM to test against (read-only operations only)

Optional env vars:
    EXEDEV_KEY_FILE     - Path to SSH private key (used instead of agent if set)
"""

import os

import pytest

from exedev import Client

AGENT_SOCK = os.environ.get("EXEDEV_AGENT_SOCK")
KEY_FILE = os.environ.get("EXEDEV_KEY_FILE")
TEST_VM = os.environ.get("EXEDEV_TEST_VM")

skip_no_auth = pytest.mark.skipif(
    not AGENT_SOCK and not KEY_FILE,
    reason="Set EXEDEV_AGENT_SOCK or EXEDEV_KEY_FILE to run integration tests",
)

skip_no_vm = pytest.mark.skipif(
    not TEST_VM,
    reason="Set EXEDEV_TEST_VM to run VM-specific integration tests",
)


def make_client() -> Client:
    if KEY_FILE:
        return Client(private_key=KEY_FILE)
    return Client(agent_sock=AGENT_SOCK)


@skip_no_auth
class TestIntegration:
    def test_whoami(self):
        c = make_client()
        info = c.whoami()
        assert info.email
        assert isinstance(info.ssh_keys, list)

    def test_ls(self):
        c = make_client()
        vms = c.ls()
        assert isinstance(vms, list)

    def test_ssh_key_list(self):
        c = make_client()
        keys = c.ssh_key_list()
        assert isinstance(keys, list)
        assert len(keys) > 0

    def test_generate_token(self):
        c = make_client()
        token = c.generate_token()
        assert token.startswith("exe0.")
        assert token.count(".") == 2

    @skip_no_vm
    def test_share_show(self):
        c = make_client()
        share = c.share_show(TEST_VM)
        assert share.vm_name == TEST_VM
        assert share.status in ("private", "public")

    @skip_no_vm
    def test_vm_in_ls(self):
        c = make_client()
        vms = c.ls()
        names = [vm.vm_name for vm in vms]
        assert TEST_VM in names, f"{TEST_VM} not found in {names}"
