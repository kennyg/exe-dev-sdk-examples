"""Identifier validation regression tests, over real HTTP.

Each test drives the client against the local recording HTTP server from
conftest.py. An invalid identifier must raise ExeDevError with status 0, and the
server must see no request at all.
"""

import pytest

from exedev import ExeDevError


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


FINGERPRINT_CALLS = {
    "ssh_key_remove": lambda c, v: c.ssh_key_remove(v),
    "ssh_key_rename(fingerprint)": lambda c, v: c.ssh_key_rename(v, "work-laptop"),
}

INVALID_FINGERPRINTS = {
    "command": "SHA256:x; rm -rf /",
    "parent dir": "../etc --all",
    "dot-dot in digest": "SHA256:../etc",
    "space": "SHA256:abc def",
    "subshell": "SHA256:$(id)",
    "trailing newline": "SHA256:abc123\n",
    "no prefix": "abc123",
    "md5": "MD5:aa:bb:cc",
    "lower-case prefix": "sha256:abc123",
    "empty digest": "SHA256:",
    "empty": "",
    "too long": "SHA256:" + "a" * 44,
    "double padding": "SHA256:abc==",
    "cyrillic a": "SHA256:аbc",
    "leading hyphen": "-SHA256:abc",
    "non-string": None,
}


@pytest.mark.parametrize("call", FINGERPRINT_CALLS)
@pytest.mark.parametrize("value", INVALID_FINGERPRINTS.values(), ids=INVALID_FINGERPRINTS.keys())
def test_invalid_fingerprint_never_reaches_the_server(client, server, call, value):
    with pytest.raises(ExeDevError) as exc:
        FINGERPRINT_CALLS[call](client, value)
    assert (exc.value.status_code, exc.value.message) == (0, "invalid fingerprint")
    assert server.requests == []


VALID_FINGERPRINTS = [
    "SHA256:abc123",
    "SHA256:ExampleFingerprint123",
    "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8",
    "SHA256:a+b/c=",
]


@pytest.mark.parametrize("value", VALID_FINGERPRINTS)
def test_valid_fingerprints_are_sent_unchanged(client, server, value):
    client.ssh_key_remove(value)
    client.ssh_key_rename(value, "work-laptop")
    assert [r["body"] for r in server.requests] == [
        f"ssh-key remove {value}",
        f"ssh-key rename {value} work-laptop",
    ]
