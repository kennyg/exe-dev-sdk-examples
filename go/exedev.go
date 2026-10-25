// Package exedev provides a Go SDK for the exe.dev HTTPS API.
//
// It wraps the exe.dev API, handling token generation, command execution,
// and response parsing. Authentication uses SSH private keys to sign
// tokens locally — no passwords or API keys leave the client.
package exedev

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

// Identifiers (VM, tag and key names) become shell words in the command
// body and DNS labels in "{vm}.exe.xyz". Only ASCII letters, digits, hyphens
// and underscores are allowed. A leading hyphen would read as a flag, and a
// DNS label holds at most 63 characters.
var identifierRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

const maxIdentifierLen = 63

func validateIdentifier(value string) error {
	if value == "" {
		return &ExeDevError{StatusCode: 0, Message: "value must not be empty"}
	}
	if !identifierRe.MatchString(value) {
		return &ExeDevError{StatusCode: 0, Message: "invalid characters in value"}
	}
	if len(value) > maxIdentifierLen {
		return &ExeDevError{StatusCode: 0, Message: fmt.Sprintf("value exceeds %d characters", maxIdentifierLen)}
	}
	return nil
}

// fingerprintRe matches an SSH key fingerprint as ssh-keygen prints it:
// "SHA256:" and the base64 SHA-256 digest, 43 characters without padding.
var fingerprintRe = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{1,43}=?$`)

func validateFingerprint(value string) error {
	if !fingerprintRe.MatchString(value) {
		return &ExeDevError{StatusCode: 0, Message: "invalid fingerprint"}
	}
	return nil
}

// shellSafeRe is the character set that needs no quoting, the same set as
// Python's shlex.quote.
var shellSafeRe = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

// shellQuote returns value as one POSIX shell word. It is defence in depth
// after validation: a valid identifier or fingerprint comes back unchanged.
func shellQuote(value string) string {
	if shellSafeRe.MatchString(value) {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

// doubleQuoteSpecial matches runs of the only characters that are special
// inside POSIX shell double quotes (XCU 2.2.3).
var doubleQuoteSpecial = regexp.MustCompile("[\\\\\"$`]+")

// doubleQuote quotes value as one POSIX shell word, in double quotes. Each run
// of special characters goes in single quotes instead, where no character is
// special. The adjacent quoted parts join into one word that expands to
// exactly value. The form uses no backslash escapes, so sh and other POSIX
// word splitters all agree on it.
func doubleQuote(value string) string {
	return `"` + doubleQuoteSpecial.ReplaceAllStringFunc(value, func(run string) string {
		return `"'` + run + `'"`
	}) + `"`
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

// ExeDevError represents an error returned by the exe.dev API or a local
// validation error (StatusCode == 0).
type ExeDevError struct {
	StatusCode int    `json:"status_code"`
	Message    string `json:"message"`
}

func (e *ExeDevError) Error() string {
	return fmt.Sprintf("[%d] %s", e.StatusCode, e.Message)
}

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

// VM represents a virtual machine as returned by ls --json.
type VM struct {
	VMName        string `json:"vm_name"`
	Status        string `json:"status"`
	Region        string `json:"region"`
	RegionDisplay string `json:"region_display"`
	SSHDest       string `json:"ssh_dest"`
	HTTPSURL      string `json:"https_url"`
	Image         string `json:"image"`
	ShelleyURL    string `json:"shelley_url"`
}

// NewVMResponse is returned by the new command.
type NewVMResponse struct {
	VMName     string `json:"vm_name"`
	SSHCommand string `json:"ssh_command"`
	SSHDest    string `json:"ssh_dest"`
	SSHPort    int    `json:"ssh_port"`
	HTTPSURL   string `json:"https_url"`
	ProxyPort  int    `json:"proxy_port"`
	ShelleyURL string `json:"shelley_url"`
	VSCodeURL  string `json:"vscode_url"`
	XtermURL   string `json:"xterm_url"`
}

// CpResponse is returned by the cp command.
type CpResponse struct {
	Name    string  `json:"name"`
	Source  string  `json:"source"`
	SSH     string  `json:"ssh"`
	State   string  `json:"state"`
	Elapsed float64 `json:"elapsed"`
}

// RmResponse is returned by the rm command.
type RmResponse struct {
	Deleted []string `json:"deleted"`
	Failed  []any    `json:"failed"`
}

// RestartResponse is returned by the restart command.
type RestartResponse struct {
	Status string `json:"status"`
	VMName string `json:"vm_name"`
}

// RenameResponse is returned by the rename command.
type RenameResponse struct {
	OldName string `json:"old_name"`
	NewName string `json:"new_name"`
	Status  string `json:"status"`
}

// TagResponse is returned by the tag and untag commands.
type TagResponse struct {
	Tags   []string `json:"tags"`
	VMName string   `json:"vm_name"`
}

// SSHKey represents a registered SSH key.
type SSHKey struct {
	Name        string  `json:"name"`
	Fingerprint string  `json:"fingerprint"`
	PublicKey   string  `json:"public_key"`
	AddedAt     *string `json:"added_at"`
	LastUsedAt  *string `json:"last_used_at"`
	Current     bool    `json:"current"`
}

// UserInfo is returned by the whoami command.
type UserInfo struct {
	Email   string   `json:"email"`
	SSHKeys []SSHKey `json:"ssh_keys"`
}

// ShareInfo is returned by the share show command.
type ShareInfo struct {
	VMName      string `json:"vm_name"`
	Status      string `json:"status"`
	URL         string `json:"url"`
	Port        int    `json:"port"`
	Users       []any  `json:"users"`
	Links       []any  `json:"links"`
	TeamAccess  bool   `json:"team_access"`
	TeamShelley bool   `json:"team_shelley"`
	TeamSSH     bool   `json:"team_ssh"`
	Teams       []any  `json:"teams"`
}

// ShareUpdateResponse is returned by share set-public, set-private, and port commands.
type ShareUpdateResponse struct {
	Status      string `json:"status"`
	Share       string `json:"share"`
	Port        int    `json:"port"`
	VMName      string `json:"vm_name"`
	TeamAccess  bool   `json:"team_access"`
	TeamShelley bool   `json:"team_shelley"`
	TeamSSH     bool   `json:"team_ssh"`
}

// ShareAddLinkResponse is returned by the share add-link command.
type ShareAddLinkResponse struct {
	Status string `json:"status"`
	URL    string `json:"url"`
	Token  string `json:"token"`
	VMName string `json:"vm_name"`
}

// ShareReceiveEmailResponse is returned by the share receive-email command.
type ShareReceiveEmailResponse struct {
	Status       string  `json:"status"`
	EmailEnabled bool    `json:"email_enabled"`
	EmailAddress *string `json:"email_address"`
	VMName       string  `json:"vm_name"`
}

// TokenPermissions controls what a token is allowed to do.
type TokenPermissions struct {
	Exp  *int64         `json:"exp,omitempty"`
	Nbf  *int64         `json:"nbf,omitempty"`
	Cmds []string       `json:"cmds,omitempty"`
	Ctx  map[string]any `json:"ctx,omitempty"`
}

func (tp *TokenPermissions) toJSON() string {
	if tp == nil {
		return "{}"
	}
	d := make(map[string]any)
	if tp.Exp != nil {
		d["exp"] = *tp.Exp
	}
	if tp.Nbf != nil {
		d["nbf"] = *tp.Nbf
	}
	if tp.Cmds != nil {
		d["cmds"] = tp.Cmds
	}
	if tp.Ctx != nil {
		d["ctx"] = tp.Ctx
	}
	b, _ := json.Marshal(d)
	return string(b)
}

// ---------------------------------------------------------------------------
// NewOpts holds optional parameters for creating a new VM.
// ---------------------------------------------------------------------------

// NewOpts contains optional parameters for creating a VM.
type NewOpts struct {
	Name        *string
	Image       *string
	Command     *string
	Env         map[string]string
	Integration []string
	Prompt      *string
	NoEmail     bool
}

// ---------------------------------------------------------------------------
// Option pattern
// ---------------------------------------------------------------------------

// Option configures the Client.
type Option func(*Client)

// WithBaseURL sets the API base URL.
func WithBaseURL(url string) Option {
	return func(c *Client) {
		c.baseURL = strings.TrimRight(url, "/")
	}
}

// WithPermissions sets default token permissions.
func WithPermissions(p TokenPermissions) Option {
	return func(c *Client) {
		c.defaultPermissions = &p
	}
}

// WithAgentSock sets the SSH agent socket path.
func WithAgentSock(path string) Option {
	return func(c *Client) {
		c.agentSock = path
	}
}

// ---------------------------------------------------------------------------
// SSH Signature helpers
// ---------------------------------------------------------------------------

func b64urlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func writeSSHString(data []byte) []byte {
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buf, uint32(len(data)))
	copy(buf[4:], data)
	return buf
}

// sshSign produces an SSHSIG format signature using a local private key.
func sshSign(signer ssh.Signer, message []byte, namespace string) ([]byte, error) {
	// Build the SSHSIG signed data
	sigData := []byte("SSHSIG")
	sigData = append(sigData, writeSSHString([]byte(namespace))...)
	sigData = append(sigData, writeSSHString([]byte{})...) // reserved
	sigData = append(sigData, writeSSHString([]byte("sha512"))...)
	h := sha512.Sum512(message)
	sigData = append(sigData, writeSSHString(h[:])...)

	// Determine the algorithm to request
	pubKey := signer.PublicKey()
	keyType := pubKey.Type()
	var algoName string
	switch keyType {
	case "ssh-rsa":
		algoName = "rsa-sha2-512"
	default:
		algoName = keyType
	}

	// Sign
	sig, err := signer.(ssh.AlgorithmSigner).SignWithAlgorithm(rand.Reader, sigData, algoName)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	// Build the raw signature blob (algorithm string + signature bytes)
	sigBlob := writeSSHString([]byte(sig.Format))
	sigBlob = append(sigBlob, writeSSHString(sig.Blob)...)

	// Build the full SSHSIG envelope
	sshsig := []byte("SSHSIG")
	// version = 1
	ver := make([]byte, 4)
	binary.BigEndian.PutUint32(ver, 1)
	sshsig = append(sshsig, ver...)
	sshsig = append(sshsig, writeSSHString(pubKey.Marshal())...)
	sshsig = append(sshsig, writeSSHString([]byte(namespace))...)
	sshsig = append(sshsig, writeSSHString([]byte{})...) // reserved
	sshsig = append(sshsig, writeSSHString([]byte("sha512"))...)
	sshsig = append(sshsig, writeSSHString(sigBlob)...)

	// PEM-encode
	b64 := base64.StdEncoding.EncodeToString(sshsig)
	var lines []string
	for i := 0; i < len(b64); i += 76 {
		end := i + 76
		if end > len(b64) {
			end = len(b64)
		}
		lines = append(lines, b64[i:end])
	}
	pem := "-----BEGIN SSH SIGNATURE-----\n" +
		strings.Join(lines, "\n") +
		"\n-----END SSH SIGNATURE-----"

	return []byte(pem), nil
}

// agentSSHSig produces an SSHSIG format signature using an SSH agent.
func agentSSHSig(agentClient agent.ExtendedAgent, key ssh.PublicKey, message []byte, namespace string) ([]byte, error) {
	// Build the SSHSIG signed data
	sigData := []byte("SSHSIG")
	sigData = append(sigData, writeSSHString([]byte(namespace))...)
	sigData = append(sigData, writeSSHString([]byte{})...) // reserved
	sigData = append(sigData, writeSSHString([]byte("sha512"))...)
	h := sha512.Sum512(message)
	sigData = append(sigData, writeSSHString(h[:])...)

	// Ask agent to sign
	sig, err := agentClient.Sign(key, sigData)
	if err != nil {
		return nil, fmt.Errorf("agent signing failed: %w", err)
	}

	// Build the raw signature blob
	sigBlob := writeSSHString([]byte(sig.Format))
	sigBlob = append(sigBlob, writeSSHString(sig.Blob)...)

	// Build the full SSHSIG envelope
	sshsig := []byte("SSHSIG")
	ver := make([]byte, 4)
	binary.BigEndian.PutUint32(ver, 1)
	sshsig = append(sshsig, ver...)
	sshsig = append(sshsig, writeSSHString(key.Marshal())...)
	sshsig = append(sshsig, writeSSHString([]byte(namespace))...)
	sshsig = append(sshsig, writeSSHString([]byte{})...) // reserved
	sshsig = append(sshsig, writeSSHString([]byte("sha512"))...)
	sshsig = append(sshsig, writeSSHString(sigBlob)...)

	// PEM-encode
	b64 := base64.StdEncoding.EncodeToString(sshsig)
	var lines []string
	for i := 0; i < len(b64); i += 76 {
		end := i + 76
		if end > len(b64) {
			end = len(b64)
		}
		lines = append(lines, b64[i:end])
	}
	pem := "-----BEGIN SSH SIGNATURE-----\n" +
		strings.Join(lines, "\n") +
		"\n-----END SSH SIGNATURE-----"

	return []byte(pem), nil
}

// extractSigBlob extracts the binary content from a PEM-encoded SSH signature.
func extractSigBlob(pemSig []byte) ([]byte, error) {
	lines := strings.Split(string(pemSig), "\n")
	var b64Parts []string
	for _, line := range lines {
		if strings.HasPrefix(line, "-----") {
			continue
		}
		b64Parts = append(b64Parts, strings.TrimSpace(line))
	}
	b64Content := strings.Join(b64Parts, "")
	return base64.StdEncoding.DecodeString(b64Content)
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// Client is the exe.dev API client. Create one with NewClient.
type Client struct {
	baseURL            string
	defaultPermissions *TokenPermissions
	signer             ssh.Signer
	agentSock          string
	agentClient        agent.ExtendedAgent
	agentKey           ssh.PublicKey
	httpClient         *http.Client
}

// NewClient creates a new exe.dev API client.
//
// privateKey is the SSH private key in PEM or OpenSSH format. Pass nil to
// use SSH agent authentication instead.
func NewClient(privateKey []byte, opts ...Option) (*Client, error) {
	c := &Client{
		baseURL:    "https://exe.dev",
		httpClient: http.DefaultClient,
	}

	for _, opt := range opts {
		opt(c)
	}

	if privateKey != nil {
		signer, err := ssh.ParsePrivateKey(privateKey)
		if err != nil {
			return nil, &ExeDevError{StatusCode: 0, Message: "invalid or unreadable private key"}
		}
		c.signer = signer
	} else {
		// SSH agent mode
		sock := c.agentSock
		if sock == "" {
			sock = os.Getenv("SSH_AUTH_SOCK")
		}
		if sock == "" {
			return nil, &ExeDevError{StatusCode: 0, Message: "no private key or SSH agent available"}
		}
		c.agentSock = sock

		conn, err := net.Dial("unix", sock)
		if err != nil {
			return nil, &ExeDevError{StatusCode: 0, Message: "cannot connect to SSH agent"}
		}

		agentClient := agent.NewClient(conn)
		keys, err := agentClient.List()
		if err != nil {
			conn.Close()
			return nil, &ExeDevError{StatusCode: 0, Message: "cannot connect to SSH agent"}
		}
		if len(keys) == 0 {
			conn.Close()
			return nil, &ExeDevError{StatusCode: 0, Message: "SSH agent has no keys"}
		}

		c.agentClient = agentClient
		c.agentKey = keys[0]
	}

	return c, nil
}

// ---------------------------------------------------------------------------
// Token generation
// ---------------------------------------------------------------------------

// GenerateToken generates an API token with the given permissions.
func (c *Client) GenerateToken(permissions *TokenPermissions) (string, error) {
	return c.makeToken(permissions, "v0@exe.dev")
}

// GenerateVMToken generates a token scoped to a specific VM.
func (c *Client) GenerateVMToken(vmName string, permissions *TokenPermissions) (string, error) {
	if err := validateIdentifier(vmName); err != nil {
		return "", err
	}
	namespace := fmt.Sprintf("v0@%s.exe.xyz", vmName)
	return c.makeToken(permissions, namespace)
}

func (c *Client) makeToken(permissions *TokenPermissions, namespace string) (string, error) {
	perms := permissions
	if perms == nil {
		if c.defaultPermissions != nil {
			perms = c.defaultPermissions
		}
	}

	payloadJSON := "{}"
	if perms != nil {
		payloadJSON = perms.toJSON()
	}
	payloadBytes := []byte(payloadJSON)

	b64Payload := b64urlEncode(payloadBytes)

	// Sign the raw JSON bytes
	var pemSig []byte
	var err error
	if c.signer != nil {
		pemSig, err = sshSign(c.signer, payloadBytes, namespace)
	} else {
		pemSig, err = agentSSHSig(c.agentClient, c.agentKey, payloadBytes, namespace)
	}
	if err != nil {
		return "", &ExeDevError{StatusCode: 0, Message: fmt.Sprintf("signing failed: %v", err)}
	}

	sigBytes, err := extractSigBlob(pemSig)
	if err != nil {
		return "", &ExeDevError{StatusCode: 0, Message: fmt.Sprintf("failed to extract signature: %v", err)}
	}
	b64Sig := b64urlEncode(sigBytes)

	token := fmt.Sprintf("exe0.%s.%s", b64Payload, b64Sig)
	if len(token) > 8192 {
		return "", &ExeDevError{StatusCode: 0, Message: "token exceeds 8KB limit"}
	}
	return token, nil
}

// ---------------------------------------------------------------------------
// Internal exec
// ---------------------------------------------------------------------------

func (c *Client) exec(ctx context.Context, command string) (string, error) {
	token, err := c.GenerateToken(nil)
	if err != nil {
		return "", err
	}

	url := c.baseURL + "/exec"
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(command))
	if err != nil {
		return "", &ExeDevError{StatusCode: 0, Message: fmt.Sprintf("failed to create request: %v", err)}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "text/plain")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", &ExeDevError{StatusCode: 0, Message: fmt.Sprintf("request failed: %v", err)}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", &ExeDevError{StatusCode: 0, Message: fmt.Sprintf("failed to read response: %v", err)}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", &ExeDevError{StatusCode: resp.StatusCode, Message: string(body)}
	}

	return string(body), nil
}

// ---------------------------------------------------------------------------
// VM Management
// ---------------------------------------------------------------------------

// Ls lists VMs.
func (c *Client) Ls(ctx context.Context, all bool, detailed bool) ([]VM, error) {
	parts := []string{"ls"}
	if all {
		parts = append(parts, "-a")
	}
	if detailed {
		parts = append(parts, "-l")
	}
	parts = append(parts, "--json")

	body, err := c.exec(ctx, strings.Join(parts, " "))
	if err != nil {
		return nil, err
	}

	var wrapper struct {
		VMs []VM `json:"vms"`
	}
	if err := json.Unmarshal([]byte(body), &wrapper); err != nil {
		return nil, &ExeDevError{StatusCode: 0, Message: fmt.Sprintf("failed to parse response: %v", err)}
	}
	return wrapper.VMs, nil
}

// New creates a new VM.
func (c *Client) New(ctx context.Context, opts NewOpts) (*NewVMResponse, error) {
	parts := []string{"new"}
	if opts.Name != nil {
		if err := validateIdentifier(*opts.Name); err != nil {
			return nil, err
		}
		parts = append(parts, fmt.Sprintf("--name=%s", shellQuote(*opts.Name)))
	}
	if opts.Image != nil {
		parts = append(parts, fmt.Sprintf("--image=%s", *opts.Image))
	}
	if opts.Command != nil {
		parts = append(parts, fmt.Sprintf("--command=%s", *opts.Command))
	}
	// Go map order is random, so sort the keys for a stable command.
	for _, k := range slices.Sorted(maps.Keys(opts.Env)) {
		parts = append(parts, fmt.Sprintf("--env=%s=%s", k, opts.Env[k]))
	}
	for _, i := range opts.Integration {
		parts = append(parts, fmt.Sprintf("--integration=%s", i))
	}
	if opts.Prompt != nil {
		parts = append(parts, "--prompt="+doubleQuote(*opts.Prompt))
	}
	if opts.NoEmail {
		parts = append(parts, "--no-email")
	}
	parts = append(parts, "--json")

	body, err := c.exec(ctx, strings.Join(parts, " "))
	if err != nil {
		return nil, err
	}

	var resp NewVMResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return nil, &ExeDevError{StatusCode: 0, Message: fmt.Sprintf("failed to parse response: %v", err)}
	}
	return &resp, nil
}

// Rm deletes one or more VMs.
func (c *Client) Rm(ctx context.Context, vmNames ...string) (*RmResponse, error) {
	if len(vmNames) == 0 {
		return nil, &ExeDevError{StatusCode: 0, Message: "at least one VM name is required"}
	}
	names := make([]string, len(vmNames))
	for i, n := range vmNames {
		if err := validateIdentifier(n); err != nil {
			return nil, err
		}
		names[i] = shellQuote(n)
	}

	body, err := c.exec(ctx, "rm "+strings.Join(names, " "))
	if err != nil {
		return nil, err
	}

	var resp RmResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return nil, &ExeDevError{StatusCode: 0, Message: fmt.Sprintf("failed to parse response: %v", err)}
	}
	return &resp, nil
}

// Restart reboots a VM.
func (c *Client) Restart(ctx context.Context, vmName string) (*RestartResponse, error) {
	if err := validateIdentifier(vmName); err != nil {
		return nil, err
	}

	body, err := c.exec(ctx, fmt.Sprintf("restart %s", shellQuote(vmName)))
	if err != nil {
		return nil, err
	}

	var resp RestartResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return nil, &ExeDevError{StatusCode: 0, Message: fmt.Sprintf("failed to parse response: %v", err)}
	}
	return &resp, nil
}

// Rename renames a VM.
func (c *Client) Rename(ctx context.Context, vmName, newName string) (*RenameResponse, error) {
	if err := validateIdentifier(vmName); err != nil {
		return nil, err
	}
	if err := validateIdentifier(newName); err != nil {
		return nil, err
	}

	body, err := c.exec(ctx, fmt.Sprintf("rename %s %s", shellQuote(vmName), shellQuote(newName)))
	if err != nil {
		return nil, err
	}

	var resp RenameResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return nil, &ExeDevError{StatusCode: 0, Message: fmt.Sprintf("failed to parse response: %v", err)}
	}
	return &resp, nil
}

// Cp clones a VM.
func (c *Client) Cp(ctx context.Context, vmName string, newName *string) (*CpResponse, error) {
	if err := validateIdentifier(vmName); err != nil {
		return nil, err
	}
	parts := []string{"cp", shellQuote(vmName)}
	if newName != nil {
		if err := validateIdentifier(*newName); err != nil {
			return nil, err
		}
		parts = append(parts, shellQuote(*newName))
	}
	parts = append(parts, "--json")

	body, err := c.exec(ctx, strings.Join(parts, " "))
	if err != nil {
		return nil, err
	}

	var resp CpResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return nil, &ExeDevError{StatusCode: 0, Message: fmt.Sprintf("failed to parse response: %v", err)}
	}
	return &resp, nil
}

// Tag adds a tag to a VM.
func (c *Client) Tag(ctx context.Context, vmName, tagName string) (*TagResponse, error) {
	if err := validateIdentifier(vmName); err != nil {
		return nil, err
	}
	if err := validateIdentifier(tagName); err != nil {
		return nil, err
	}

	body, err := c.exec(ctx, fmt.Sprintf("tag %s %s", shellQuote(vmName), shellQuote(tagName)))
	if err != nil {
		return nil, err
	}

	var resp TagResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return nil, &ExeDevError{StatusCode: 0, Message: fmt.Sprintf("failed to parse response: %v", err)}
	}
	return &resp, nil
}

// Untag removes a tag from a VM.
func (c *Client) Untag(ctx context.Context, vmName, tagName string) (*TagResponse, error) {
	if err := validateIdentifier(vmName); err != nil {
		return nil, err
	}
	if err := validateIdentifier(tagName); err != nil {
		return nil, err
	}

	body, err := c.exec(ctx, fmt.Sprintf("tag -d %s %s", shellQuote(vmName), shellQuote(tagName)))
	if err != nil {
		return nil, err
	}

	var resp TagResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return nil, &ExeDevError{StatusCode: 0, Message: fmt.Sprintf("failed to parse response: %v", err)}
	}
	return &resp, nil
}

// ---------------------------------------------------------------------------
// Sharing & Access
// ---------------------------------------------------------------------------

// ShareShow shows sharing configuration for a VM.
func (c *Client) ShareShow(ctx context.Context, vmName string) (*ShareInfo, error) {
	if err := validateIdentifier(vmName); err != nil {
		return nil, err
	}

	body, err := c.exec(ctx, fmt.Sprintf("share show %s --json", shellQuote(vmName)))
	if err != nil {
		return nil, err
	}

	var resp ShareInfo
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return nil, &ExeDevError{StatusCode: 0, Message: fmt.Sprintf("failed to parse response: %v", err)}
	}
	return &resp, nil
}

// ShareSetPublic makes a VM's HTTP proxy publicly accessible.
func (c *Client) ShareSetPublic(ctx context.Context, vmName string) (*ShareUpdateResponse, error) {
	if err := validateIdentifier(vmName); err != nil {
		return nil, err
	}

	body, err := c.exec(ctx, fmt.Sprintf("share set-public %s", shellQuote(vmName)))
	if err != nil {
		return nil, err
	}

	var resp ShareUpdateResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return nil, &ExeDevError{StatusCode: 0, Message: fmt.Sprintf("failed to parse response: %v", err)}
	}
	return &resp, nil
}

// ShareSetPrivate makes a VM's HTTP proxy private.
func (c *Client) ShareSetPrivate(ctx context.Context, vmName string) (*ShareUpdateResponse, error) {
	if err := validateIdentifier(vmName); err != nil {
		return nil, err
	}

	body, err := c.exec(ctx, fmt.Sprintf("share set-private %s", shellQuote(vmName)))
	if err != nil {
		return nil, err
	}

	var resp ShareUpdateResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return nil, &ExeDevError{StatusCode: 0, Message: fmt.Sprintf("failed to parse response: %v", err)}
	}
	return &resp, nil
}

// SharePort sets the proxy target port.
func (c *Client) SharePort(ctx context.Context, vmName string, port int) (*ShareUpdateResponse, error) {
	if port < 1 || port > 65535 {
		return nil, &ExeDevError{StatusCode: 0, Message: "port must be between 1 and 65535"}
	}
	if err := validateIdentifier(vmName); err != nil {
		return nil, err
	}

	body, err := c.exec(ctx, fmt.Sprintf("share port %s %d", shellQuote(vmName), port))
	if err != nil {
		return nil, err
	}

	var resp ShareUpdateResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return nil, &ExeDevError{StatusCode: 0, Message: fmt.Sprintf("failed to parse response: %v", err)}
	}
	return &resp, nil
}

// ShareAdd shares VM access with a user by email.
func (c *Client) ShareAdd(ctx context.Context, vmName, email string) error {
	if err := validateIdentifier(vmName); err != nil {
		return err
	}
	_, err := c.exec(ctx, fmt.Sprintf("share add %s %s", shellQuote(vmName), email))
	return err
}

// ShareRemove revokes a user's VM access.
func (c *Client) ShareRemove(ctx context.Context, vmName, email string) error {
	if err := validateIdentifier(vmName); err != nil {
		return err
	}
	_, err := c.exec(ctx, fmt.Sprintf("share remove %s %s", shellQuote(vmName), email))
	return err
}

// ShareAddLink creates a shareable link for a VM.
func (c *Client) ShareAddLink(ctx context.Context, vmName string) (*ShareAddLinkResponse, error) {
	if err := validateIdentifier(vmName); err != nil {
		return nil, err
	}

	body, err := c.exec(ctx, fmt.Sprintf("share add-link %s --json", shellQuote(vmName)))
	if err != nil {
		return nil, err
	}

	var resp ShareAddLinkResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return nil, &ExeDevError{StatusCode: 0, Message: fmt.Sprintf("failed to parse response: %v", err)}
	}
	return &resp, nil
}

// ShareRemoveLink revokes a VM's share link.
func (c *Client) ShareRemoveLink(ctx context.Context, vmName string) error {
	if err := validateIdentifier(vmName); err != nil {
		return err
	}
	_, err := c.exec(ctx, fmt.Sprintf("share remove-link %s", shellQuote(vmName)))
	return err
}

// ShareReceiveEmail enables or disables inbound email for a VM.
func (c *Client) ShareReceiveEmail(ctx context.Context, vmName string, enabled bool) (*ShareReceiveEmailResponse, error) {
	if err := validateIdentifier(vmName); err != nil {
		return nil, err
	}
	state := "off"
	if enabled {
		state = "on"
	}

	body, err := c.exec(ctx, fmt.Sprintf("share receive-email %s %s", shellQuote(vmName), state))
	if err != nil {
		return nil, err
	}

	var resp ShareReceiveEmailResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return nil, &ExeDevError{StatusCode: 0, Message: fmt.Sprintf("failed to parse response: %v", err)}
	}
	return &resp, nil
}

// ---------------------------------------------------------------------------
// SSH Key Management
// ---------------------------------------------------------------------------

// SSHKeyList lists registered SSH keys.
func (c *Client) SSHKeyList(ctx context.Context) ([]SSHKey, error) {
	body, err := c.exec(ctx, "ssh-key list --json")
	if err != nil {
		return nil, err
	}

	var wrapper struct {
		SSHKeys []SSHKey `json:"ssh_keys"`
	}
	if err := json.Unmarshal([]byte(body), &wrapper); err != nil {
		return nil, &ExeDevError{StatusCode: 0, Message: fmt.Sprintf("failed to parse response: %v", err)}
	}
	return wrapper.SSHKeys, nil
}

// SSHKeyAdd registers a new SSH public key.
func (c *Client) SSHKeyAdd(ctx context.Context, publicKey string) error {
	_, err := c.exec(ctx, fmt.Sprintf("ssh-key add %s", publicKey))
	return err
}

// SSHKeyRemove removes a registered SSH key by fingerprint.
func (c *Client) SSHKeyRemove(ctx context.Context, fingerprint string) error {
	if err := validateFingerprint(fingerprint); err != nil {
		return err
	}
	_, err := c.exec(ctx, fmt.Sprintf("ssh-key remove %s", shellQuote(fingerprint)))
	return err
}

// SSHKeyRename renames a registered SSH key.
func (c *Client) SSHKeyRename(ctx context.Context, fingerprint, newName string) error {
	if err := validateFingerprint(fingerprint); err != nil {
		return err
	}
	if err := validateIdentifier(newName); err != nil {
		return err
	}
	_, err := c.exec(ctx, fmt.Sprintf("ssh-key rename %s %s", shellQuote(fingerprint), shellQuote(newName)))
	return err
}

// ---------------------------------------------------------------------------
// User
// ---------------------------------------------------------------------------

// Whoami returns current user information.
func (c *Client) Whoami(ctx context.Context) (*UserInfo, error) {
	body, err := c.exec(ctx, "whoami --json")
	if err != nil {
		return nil, err
	}

	var resp UserInfo
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return nil, &ExeDevError{StatusCode: 0, Message: fmt.Sprintf("failed to parse response: %v", err)}
	}
	return &resp, nil
}

// ---------------------------------------------------------------------------
// Shelley Agent
// ---------------------------------------------------------------------------

// ShelleyInstall installs or updates Shelley on a VM.
func (c *Client) ShelleyInstall(ctx context.Context, vmName string) error {
	if err := validateIdentifier(vmName); err != nil {
		return err
	}
	_, err := c.exec(ctx, fmt.Sprintf("shelley install %s", shellQuote(vmName)))
	return err
}

// ShelleyPrompt sends a prompt to Shelley on a VM.
func (c *Client) ShelleyPrompt(ctx context.Context, vmName, prompt string) error {
	if err := validateIdentifier(vmName); err != nil {
		return err
	}
	_, err := c.exec(ctx, fmt.Sprintf("shelley prompt %s %s", shellQuote(vmName), doubleQuote(prompt)))
	return err
}

// ---------------------------------------------------------------------------
// Helpers for NewOpts — convenience for setting optional string fields
// ---------------------------------------------------------------------------

// StringPtr returns a pointer to the given string. Useful for setting
// optional fields in NewOpts.
func StringPtr(s string) *string {
	return &s
}

// Int64Ptr returns a pointer to the given int64. Useful for setting
// optional fields in TokenPermissions.
func Int64Ptr(i int64) *int64 {
	return &i
}
