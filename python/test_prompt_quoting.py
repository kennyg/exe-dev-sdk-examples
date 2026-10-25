"""Prompt quoting regression tests, over real HTTP.

Each test sends a prompt through the client to a local recording server,
from conftest.py, then splits the request body into words with /bin/sh. The prompt must come
back as exactly one word, unchanged, and nothing in it may run.
"""

import subprocess

import pytest


def sh_words(body: str) -> list[str]:
    """Split body into POSIX shell words with a real shell."""
    out = subprocess.run(
        ["sh", "-c", 'eval "set -- $1"; printf "%s\\0" "$@"', "sh", body],
        capture_output=True,
        check=True,
        text=True,
    ).stdout
    return out.split("\0")[:-1]


PROMPTS = {
    "plain": "create a hello world app",
    "double quotes": 'say "hi"; echo pwned',
    "closing quote": '"; echo pwned; "',
    "single quote": "it's fine",
    "backslash": "a\\b",
    "trailing backslash": "ends with \\",
    "backslash before quote": '\\"; echo pwned; \\"',
    "command substitution": "$(echo pwned)",
    "backticks": "`echo pwned`",
    "variable": "$HOME and ${PATH}",
    "arithmetic": "$((1+1))",
    "semicolon and pipe": "a; b | c && d",
    "newline": "line one\nline two",
    "glob": "*.py ?",
    "history": "!! and !$",
    "unicode": "café — “quoted”",
    "empty": "",
}


@pytest.mark.parametrize("prompt", PROMPTS.values(), ids=PROMPTS.keys())
def test_shelley_prompt_is_one_unchanged_word(client, server, prompt):
    client.shelley_prompt("dev", prompt)
    assert len(server.requests) == 1
    assert sh_words(server.requests[0]["body"]) == ["shelley", "prompt", "dev", prompt]


@pytest.mark.parametrize("prompt", PROMPTS.values(), ids=PROMPTS.keys())
def test_new_prompt_is_one_unchanged_word(client, server, prompt):
    client.new(name="dev", prompt=prompt)
    assert len(server.requests) == 1
    assert sh_words(server.requests[0]["body"]) == [
        "new",
        "--name=dev",
        f"--prompt={prompt}",
        "--json",
    ]


WIRE = {
    "create a hello world app": '"create a hello world app"',
    'say "hi"; echo pwned': '"say \\"hi\\"; echo pwned"',
    "a\\b": '"a\\\\b"',
    "$(id) `id`": '"\\$(id) \\`id\\`"',
}


@pytest.mark.parametrize("prompt", WIRE)
def test_prompt_wire_format(client, server, prompt):
    client.shelley_prompt("dev", prompt)
    client.new(prompt=prompt)
    assert [r["body"] for r in server.requests] == [
        f"shelley prompt dev {WIRE[prompt]}",
        f"new --prompt={WIRE[prompt]} --json",
    ]
