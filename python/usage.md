# exe.dev Python SDK — Usage

## Quick Start

```python
from exedev import Client

client = Client("~/.ssh/exe_dev_api")

# List VMs
for vm in client.ls():
    print(f"{vm.vm_name}: {vm.status}")

# Create a VM
vm = client.new(name="my-app", image="ubuntu:24.04")
print(f"Created {vm.vm_name} at {vm.https_url}")
```

## Authentication

The SDK authenticates by signing tokens with your SSH private key. Point the `Client` at your key:

```python
# File path
client = Client("~/.ssh/exe_dev_api")

# PEM string
client = Client(key_pem_string)

# Bytes
client = Client(key_bytes)
```

Generate a dedicated key for API use:

```bash
ssh-keygen -t ed25519 -C api -f ~/.ssh/exe_dev_api
cat ~/.ssh/exe_dev_api.pub | ssh exe.dev ssh-key add
```

## Method Reference

### VM Management

| Method | Returns | Description |
|--------|---------|-------------|
| `ls(all?, detailed?)` | `list[VM]` | List VMs |
| `new(name?, image?, command?, env?, integration?, prompt?, no_email?)` | `VM` | Create VM |
| `rm(*vm_names)` | `None` | Delete VMs |
| `restart(vm_name)` | `None` | Reboot VM |
| `rename(vm_name, new_name)` | `None` | Rename VM |
| `cp(vm_name, new_name?)` | `VM` | Clone VM |
| `tag(vm_name, tag_name)` | `None` | Add tag |
| `untag(vm_name, tag_name)` | `None` | Remove tag |

### Sharing & Access

| Method | Returns | Description |
|--------|---------|-------------|
| `share_show(vm_name?)` | `ShareInfo` or `list[ShareInfo]` | Show sharing config |
| `share_set_public(vm_name)` | `None` | Make proxy public |
| `share_set_private(vm_name)` | `None` | Make proxy private |
| `share_port(vm_name, port)` | `None` | Set proxy port |
| `share_add(vm_name, email)` | `None` | Share with user |
| `share_remove(vm_name, email)` | `None` | Revoke access |
| `share_add_link(vm_name)` | `str` | Create share link |
| `share_remove_link(vm_name)` | `None` | Revoke share link |
| `share_receive_email(vm_name, enabled)` | `None` | Toggle inbound email |

### SSH Keys

| Method | Returns | Description |
|--------|---------|-------------|
| `ssh_key_list()` | `list[SSHKey]` | List keys |
| `ssh_key_add(public_key)` | `None` | Add key |
| `ssh_key_remove(fingerprint)` | `None` | Remove key |
| `ssh_key_rename(fingerprint, new_name)` | `None` | Rename key |

### Other

| Method | Returns | Description |
|--------|---------|-------------|
| `whoami()` | `UserInfo` | Get user info |
| `shelley_install(vm_name)` | `None` | Install Shelley agent |
| `shelley_prompt(vm_name, prompt)` | `None` | Send prompt to Shelley |
| `generate_token(permissions?)` | `str` | Generate API token |
| `generate_vm_token(vm_name, permissions?)` | `str` | Generate VM-scoped token |

## Error Handling

All API errors raise `ExeDevError` with `status_code` and `message`:

```python
from exedev import Client, ExeDevError

client = Client("~/.ssh/exe_dev_api")
try:
    client.rm("nonexistent")
except ExeDevError as e:
    print(f"Error {e.status_code}: {e.message}")
```

### Name Validation

VM names, tag names and SSH key names must be 1 to 63 ASCII letters, digits, hyphens or underscores, and must start with a letter or digit. The SDK checks every name before it builds a request. A bad name raises `ExeDevError` with status code 0, and no request goes to the server:

| Name | Message |
|------|---------|
| `""` | `value must not be empty` |
| `../etc`, `vm.x`, `vm/x`, `vm:x`, `vm@x`, `-d`, `vаm` (Cyrillic `а`) | `invalid characters in value` |
| 64 or more characters | `value exceeds 63 characters` |

SSH key fingerprints must have the form `ssh-keygen` prints, `SHA256:` and a base64 digest of at most 43 characters, such as `SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8`. Any other fingerprint gets the message `invalid fingerprint`, and no request goes to the server.

The SDK puts a prompt into the command in double quotes. Each run of `\`, `"`, `$` or backticks goes in single quotes inside them, so the server receives the prompt text unchanged.

## Token Generation

Generate tokens for use outside the SDK (e.g. git credentials):

```python
from exedev import Client, TokenPermissions

client = Client("~/.ssh/exe_dev_api")

# Unrestricted token
token = client.generate_token()

# Scoped token with expiry
from time import time
perms = TokenPermissions(
    exp=int(time()) + 3600,
    cmds=["ls", "whoami"],
)
token = client.generate_token(perms)

# VM-scoped token
vm_token = client.generate_vm_token("my-vm")
```
