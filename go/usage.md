# exe.dev Go SDK Usage

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"

    exedev "github.com/kennyg/exe-dev-sdk-examples/go"
)

func main() {
    key, _ := os.ReadFile(os.ExpandEnv("$HOME/.ssh/id_ed25519"))
    client, err := exedev.NewClient(key)
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()

    // List VMs
    vms, _ := client.Ls(ctx, false, false)
    for _, vm := range vms {
        fmt.Printf("%s (%s)\n", vm.VMName, vm.Status)
    }

    // Create a VM
    resp, _ := client.New(ctx, exedev.NewOpts{Name: strPtr("my-vm")})
    fmt.Println(resp.SSHCommand)
}

func strPtr(s string) *string { return &s }
```

## Authentication

### Local SSH Key

```go
key, err := os.ReadFile("/path/to/id_ed25519")
client, err := exedev.NewClient(key)
```

### SSH Agent (1Password, macOS Keychain, etc.)

```go
client, err := exedev.NewClient(nil) // uses SSH_AUTH_SOCK
```

## Method Reference

### VM Management

| Method | Signature | Returns |
|--------|-----------|---------|
| `Ls` | `(ctx, all bool, detailed bool)` | `([]VM, error)` |
| `New` | `(ctx, opts NewOpts)` | `(*NewVMResponse, error)` |
| `Rm` | `(ctx, vmNames ...string)` | `(*RmResponse, error)` |
| `Restart` | `(ctx, vmName string)` | `(*RestartResponse, error)` |
| `Rename` | `(ctx, vmName, newName string)` | `(*RenameResponse, error)` |
| `Cp` | `(ctx, vmName string, newName *string)` | `(*CpResponse, error)` |
| `Tag` | `(ctx, vmName, tagName string)` | `(*TagResponse, error)` |
| `Untag` | `(ctx, vmName, tagName string)` | `(*TagResponse, error)` |

### Sharing & Access

| Method | Signature | Returns |
|--------|-----------|---------|
| `ShareShow` | `(ctx, vmName string)` | `(*ShareInfo, error)` |
| `ShareSetPublic` | `(ctx, vmName string)` | `(*ShareUpdateResponse, error)` |
| `ShareSetPrivate` | `(ctx, vmName string)` | `(*ShareUpdateResponse, error)` |
| `SharePort` | `(ctx, vmName string, port int)` | `(*ShareUpdateResponse, error)` |
| `ShareAdd` | `(ctx, vmName, email string)` | `error` |
| `ShareRemove` | `(ctx, vmName, email string)` | `error` |
| `ShareAddLink` | `(ctx, vmName string)` | `(*ShareAddLinkResponse, error)` |
| `ShareRemoveLink` | `(ctx, vmName string)` | `error` |
| `ShareReceiveEmail` | `(ctx, vmName string, enabled bool)` | `(*ShareReceiveEmailResponse, error)` |

### SSH Key Management

| Method | Signature | Returns |
|--------|-----------|---------|
| `SSHKeyList` | `(ctx)` | `([]SSHKey, error)` |
| `SSHKeyAdd` | `(ctx, publicKey string)` | `error` |
| `SSHKeyRemove` | `(ctx, fingerprint string)` | `error` |
| `SSHKeyRename` | `(ctx, fingerprint, newName string)` | `error` |

### User & Shelley

| Method | Signature | Returns |
|--------|-----------|---------|
| `Whoami` | `(ctx)` | `(*UserInfo, error)` |
| `ShelleyInstall` | `(ctx, vmName string)` | `error` |
| `ShelleyPrompt` | `(ctx, vmName, prompt string)` | `error` |

### Token Generation

| Method | Signature | Returns |
|--------|-----------|---------|
| `GenerateToken` | `(permissions *TokenPermissions)` | `(string, error)` |
| `GenerateVMToken` | `(vmName string, permissions *TokenPermissions)` | `(string, error)` |

## Error Handling

```go
vms, err := client.Ls(ctx, false, false)
if err != nil {
    var exeErr *exedev.ExeDevError
    if errors.As(err, &exeErr) {
        fmt.Printf("API error %d: %s\n", exeErr.StatusCode, exeErr.Message)
    }
}
```

### Name Validation

VM names, tag names and SSH key names must be 1 to 63 ASCII letters, digits, hyphens or underscores, and must start with a letter or digit. The SDK checks every name before it builds a request. A bad name returns an `*ExeDevError` with status code 0, and no request goes to the server:

| Name | Message |
|------|---------|
| `""` | `value must not be empty` |
| `../etc`, `vm.x`, `vm/x`, `vm:x`, `vm@x`, `-d`, `vаm` (Cyrillic `а`) | `invalid characters in value` |
| 64 or more characters | `value exceeds 63 characters` |

SSH key fingerprints must have the form `ssh-keygen` prints, `SHA256:` and a base64 digest of at most 43 characters, such as `SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8`. Any other fingerprint gets the message `invalid fingerprint`, and no request goes to the server.

The SDK puts a prompt into the command in double quotes and escapes `\`, `"`, `$` and backticks, so the server receives the prompt text unchanged.

## Token Generation

```go
// Global token
token, err := client.GenerateToken(nil)

// Token with permissions
token, err := client.GenerateToken(&exedev.TokenPermissions{
    Exp:  int64Ptr(1735689600),
    Cmds: []string{"ls", "whoami"},
})

// VM-scoped token
token, err := client.GenerateVMToken("my-vm", nil)
```

## Client Options

```go
client, err := exedev.NewClient(key,
    exedev.WithBaseURL("https://staging.exe.dev"),
    exedev.WithPermissions(exedev.TokenPermissions{
        Cmds: []string{"ls", "whoami"},
    }),
)
```
