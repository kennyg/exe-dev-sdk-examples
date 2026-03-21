package exedev

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"encoding/pem"

	"golang.org/x/crypto/ssh"
)

// ---------------------------------------------------------------------------
// Test key generation — ed25519 key pair in SSH PEM format
// ---------------------------------------------------------------------------

var testKeyPEM []byte

func init() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic("failed to generate test key: " + err.Error())
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		panic("failed to create SSH signer: " + err.Error())
	}
	_ = pub
	_ = signer

	// Marshal the private key to OpenSSH PEM format.
	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		panic("failed to marshal private key: " + err.Error())
	}
	testKeyPEM = pem.EncodeToMemory(pemBlock)
}

// ---------------------------------------------------------------------------
// Mock HTTP server helper
// ---------------------------------------------------------------------------

type mockResult struct {
	server *httptest.Server
	body   func() string // returns captured request body
}

func mockServer(statusCode int, responseBody string) mockResult {
	var capturedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		capturedBody = string(bodyBytes)
		w.WriteHeader(statusCode)
		fmt.Fprint(w, responseBody)
	}))
	return mockResult{
		server: srv,
		body:   func() string { return capturedBody },
	}
}

func newTestClient(t *testing.T, m mockResult) *Client {
	t.Helper()
	c, err := NewClient(testKeyPEM, WithBaseURL(m.server.URL))
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	return c
}

func assertExeDevError(t *testing.T, err error, wantStatus int, wantMessage string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var exeErr *ExeDevError
	if !errors.As(err, &exeErr) {
		t.Fatalf("expected *ExeDevError, got %T: %v", err, err)
	}
	if exeErr.StatusCode != wantStatus {
		t.Errorf("StatusCode = %d, want %d", exeErr.StatusCode, wantStatus)
	}
	if exeErr.Message != wantMessage {
		t.Errorf("Message = %q, want %q", exeErr.Message, wantMessage)
	}
}

func assertCommand(t *testing.T, body func() string, want string) {
	t.Helper()
	got := body()
	if got != want {
		t.Errorf("command = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// TestLs
// ---------------------------------------------------------------------------

func TestLs(t *testing.T) {
	t.Run("test_basic", func(t *testing.T) {
		m := mockServer(200, `{"vms":[{"vm_name":"my-app","status":"running","region":"pdx","region_display":"Oregon, USA","ssh_dest":"my-app.exe.xyz","https_url":"https://my-app.exe.xyz","image":"boldsoftware/exeuntu","shelley_url":"https://my-app.shelley.exe.xyz"}]}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		vms, err := c.Ls(context.Background(), false, false)
		if err != nil {
			t.Fatalf("Ls() error: %v", err)
		}
		assertCommand(t, m.body, "ls --json")
		if len(vms) != 1 {
			t.Fatalf("len(vms) = %d, want 1", len(vms))
		}
		if vms[0].VMName != "my-app" {
			t.Errorf("VMName = %q, want %q", vms[0].VMName, "my-app")
		}
		if vms[0].Status != "running" {
			t.Errorf("Status = %q, want %q", vms[0].Status, "running")
		}
		if vms[0].Region != "pdx" {
			t.Errorf("Region = %q, want %q", vms[0].Region, "pdx")
		}
		if vms[0].RegionDisplay != "Oregon, USA" {
			t.Errorf("RegionDisplay = %q, want %q", vms[0].RegionDisplay, "Oregon, USA")
		}
		if vms[0].SSHDest != "my-app.exe.xyz" {
			t.Errorf("SSHDest = %q, want %q", vms[0].SSHDest, "my-app.exe.xyz")
		}
		if vms[0].HTTPSURL != "https://my-app.exe.xyz" {
			t.Errorf("HTTPSURL = %q, want %q", vms[0].HTTPSURL, "https://my-app.exe.xyz")
		}
		if vms[0].Image != "boldsoftware/exeuntu" {
			t.Errorf("Image = %q, want %q", vms[0].Image, "boldsoftware/exeuntu")
		}
		if vms[0].ShelleyURL != "https://my-app.shelley.exe.xyz" {
			t.Errorf("ShelleyURL = %q, want %q", vms[0].ShelleyURL, "https://my-app.shelley.exe.xyz")
		}
	})

	t.Run("test_include_team", func(t *testing.T) {
		m := mockServer(200, `{"vms":[]}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		vms, err := c.Ls(context.Background(), true, false)
		if err != nil {
			t.Fatalf("Ls() error: %v", err)
		}
		assertCommand(t, m.body, "ls -a --json")
		if len(vms) != 0 {
			t.Errorf("len(vms) = %d, want 0", len(vms))
		}
	})

	t.Run("test_detailed", func(t *testing.T) {
		m := mockServer(200, `{"vms":[]}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		vms, err := c.Ls(context.Background(), false, true)
		if err != nil {
			t.Fatalf("Ls() error: %v", err)
		}
		assertCommand(t, m.body, "ls -l --json")
		if len(vms) != 0 {
			t.Errorf("len(vms) = %d, want 0", len(vms))
		}
	})

	t.Run("test_all_flags", func(t *testing.T) {
		m := mockServer(200, `{"vms":[]}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		vms, err := c.Ls(context.Background(), true, true)
		if err != nil {
			t.Fatalf("Ls() error: %v", err)
		}
		assertCommand(t, m.body, "ls -a -l --json")
		if len(vms) != 0 {
			t.Errorf("len(vms) = %d, want 0", len(vms))
		}
	})

	t.Run("test_empty", func(t *testing.T) {
		m := mockServer(200, `{"vms":[]}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		vms, err := c.Ls(context.Background(), false, false)
		if err != nil {
			t.Fatalf("Ls() error: %v", err)
		}
		assertCommand(t, m.body, "ls --json")
		if len(vms) != 0 {
			t.Errorf("len(vms) = %d, want 0", len(vms))
		}
	})

	t.Run("test_multiple", func(t *testing.T) {
		m := mockServer(200, `{"vms":[{"vm_name":"my-app","status":"running","region":"pdx","region_display":"Oregon, USA","ssh_dest":"my-app.exe.xyz","https_url":"https://my-app.exe.xyz","image":"boldsoftware/exeuntu","shelley_url":"https://my-app.shelley.exe.xyz"},{"vm_name":"dev-server","status":"running","region":"pdx","region_display":"Oregon, USA","ssh_dest":"dev-server.exe.xyz","https_url":"https://dev-server.exe.xyz","image":"boldsoftware/exeuntu","shelley_url":"https://dev-server.shelley.exe.xyz"}]}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		vms, err := c.Ls(context.Background(), false, false)
		if err != nil {
			t.Fatalf("Ls() error: %v", err)
		}
		assertCommand(t, m.body, "ls --json")
		if len(vms) != 2 {
			t.Fatalf("len(vms) = %d, want 2", len(vms))
		}
		if vms[0].VMName != "my-app" {
			t.Errorf("vms[0].VMName = %q, want %q", vms[0].VMName, "my-app")
		}
		if vms[0].Status != "running" {
			t.Errorf("vms[0].Status = %q, want %q", vms[0].Status, "running")
		}
		if vms[0].Region != "pdx" {
			t.Errorf("vms[0].Region = %q, want %q", vms[0].Region, "pdx")
		}
		if vms[1].VMName != "dev-server" {
			t.Errorf("vms[1].VMName = %q, want %q", vms[1].VMName, "dev-server")
		}
		if vms[1].Status != "running" {
			t.Errorf("vms[1].Status = %q, want %q", vms[1].Status, "running")
		}
		if vms[1].Region != "pdx" {
			t.Errorf("vms[1].Region = %q, want %q", vms[1].Region, "pdx")
		}
	})

	t.Run("test_auth_error", func(t *testing.T) {
		m := mockServer(401, `{"error":"invalid token"}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		_, err := c.Ls(context.Background(), false, false)
		assertExeDevError(t, err, 401, `{"error":"invalid token"}`)
	})

	t.Run("test_unknown_fields", func(t *testing.T) {
		m := mockServer(200, `{"vms":[{"vm_name":"my-app","status":"running","region":"pdx","region_display":"Oregon, USA","ssh_dest":"my-app.exe.xyz","https_url":"https://my-app.exe.xyz","image":"boldsoftware/exeuntu","shelley_url":"https://my-app.shelley.exe.xyz","future_field":"should_be_ignored"}]}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		vms, err := c.Ls(context.Background(), false, false)
		if err != nil {
			t.Fatalf("Ls() error: %v", err)
		}
		if len(vms) != 1 {
			t.Fatalf("len(vms) = %d, want 1", len(vms))
		}
		if vms[0].VMName != "my-app" {
			t.Errorf("VMName = %q, want %q", vms[0].VMName, "my-app")
		}
		if vms[0].Status != "running" {
			t.Errorf("Status = %q, want %q", vms[0].Status, "running")
		}
		if vms[0].Region != "pdx" {
			t.Errorf("Region = %q, want %q", vms[0].Region, "pdx")
		}
	})
}

// ---------------------------------------------------------------------------
// TestNew
// ---------------------------------------------------------------------------

func TestNew(t *testing.T) {
	t.Run("test_no_options", func(t *testing.T) {
		m := mockServer(200, `{"vm_name":"example-vm","ssh_command":"ssh example-vm.exe.xyz","ssh_dest":"example-vm.exe.xyz","ssh_port":22,"https_url":"https://example-vm.exe.xyz","proxy_port":8000,"shelley_url":"https://example-vm.shelley.exe.xyz","vscode_url":"vscode://vscode-remote/ssh-remote+example-vm.exe.xyz/home/exedev?windowId=_blank","xterm_url":"https://example-vm.xterm.exe.xyz"}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		result, err := c.New(context.Background(), NewOpts{})
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		assertCommand(t, m.body, "new --json")
		if result.VMName != "example-vm" {
			t.Errorf("VMName = %q, want %q", result.VMName, "example-vm")
		}
		if result.SSHCommand != "ssh example-vm.exe.xyz" {
			t.Errorf("SSHCommand = %q, want %q", result.SSHCommand, "ssh example-vm.exe.xyz")
		}
		if result.SSHDest != "example-vm.exe.xyz" {
			t.Errorf("SSHDest = %q, want %q", result.SSHDest, "example-vm.exe.xyz")
		}
		if result.SSHPort != 22 {
			t.Errorf("SSHPort = %d, want %d", result.SSHPort, 22)
		}
		if result.HTTPSURL != "https://example-vm.exe.xyz" {
			t.Errorf("HTTPSURL = %q, want %q", result.HTTPSURL, "https://example-vm.exe.xyz")
		}
		if result.ProxyPort != 8000 {
			t.Errorf("ProxyPort = %d, want %d", result.ProxyPort, 8000)
		}
		if result.ShelleyURL != "https://example-vm.shelley.exe.xyz" {
			t.Errorf("ShelleyURL = %q, want %q", result.ShelleyURL, "https://example-vm.shelley.exe.xyz")
		}
		if result.VSCodeURL != "vscode://vscode-remote/ssh-remote+example-vm.exe.xyz/home/exedev?windowId=_blank" {
			t.Errorf("VSCodeURL = %q, want %q", result.VSCodeURL, "vscode://vscode-remote/ssh-remote+example-vm.exe.xyz/home/exedev?windowId=_blank")
		}
		if result.XtermURL != "https://example-vm.xterm.exe.xyz" {
			t.Errorf("XtermURL = %q, want %q", result.XtermURL, "https://example-vm.xterm.exe.xyz")
		}
	})

	t.Run("test_with_name", func(t *testing.T) {
		m := mockServer(200, `{"vm_name":"my-project","ssh_command":"ssh my-project.exe.xyz","ssh_dest":"my-project.exe.xyz","ssh_port":22,"https_url":"https://my-project.exe.xyz","proxy_port":8000,"shelley_url":"https://my-project.shelley.exe.xyz","vscode_url":"vscode://vscode-remote/ssh-remote+my-project.exe.xyz/home/exedev?windowId=_blank","xterm_url":"https://my-project.xterm.exe.xyz"}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		result, err := c.New(context.Background(), NewOpts{Name: strPtr("my-project")})
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		assertCommand(t, m.body, "new --name=my-project --json")
		if result.VMName != "my-project" {
			t.Errorf("VMName = %q, want %q", result.VMName, "my-project")
		}
		if result.SSHCommand != "ssh my-project.exe.xyz" {
			t.Errorf("SSHCommand = %q, want %q", result.SSHCommand, "ssh my-project.exe.xyz")
		}
		if result.ProxyPort != 8000 {
			t.Errorf("ProxyPort = %d, want %d", result.ProxyPort, 8000)
		}
	})

	t.Run("test_with_image", func(t *testing.T) {
		m := mockServer(200, `{"vm_name":"happy-cat","ssh_command":"ssh happy-cat.exe.xyz","ssh_dest":"happy-cat.exe.xyz","ssh_port":22,"https_url":"https://happy-cat.exe.xyz","proxy_port":8000,"shelley_url":"https://happy-cat.shelley.exe.xyz","vscode_url":"vscode://vscode-remote/ssh-remote+happy-cat.exe.xyz/home/exedev?windowId=_blank","xterm_url":"https://happy-cat.xterm.exe.xyz"}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		result, err := c.New(context.Background(), NewOpts{Image: strPtr("ubuntu:24.04")})
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		assertCommand(t, m.body, "new --image=ubuntu:24.04 --json")
		if result.VMName != "happy-cat" {
			t.Errorf("VMName = %q, want %q", result.VMName, "happy-cat")
		}
		if result.SSHCommand != "ssh happy-cat.exe.xyz" {
			t.Errorf("SSHCommand = %q, want %q", result.SSHCommand, "ssh happy-cat.exe.xyz")
		}
	})

	t.Run("test_with_env", func(t *testing.T) {
		m := mockServer(200, `{"vm_name":"api-server","ssh_command":"ssh api-server.exe.xyz","ssh_dest":"api-server.exe.xyz","ssh_port":22,"https_url":"https://api-server.exe.xyz","proxy_port":8000,"shelley_url":"https://api-server.shelley.exe.xyz","vscode_url":"vscode://vscode-remote/ssh-remote+api-server.exe.xyz/home/exedev?windowId=_blank","xterm_url":"https://api-server.xterm.exe.xyz"}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		result, err := c.New(context.Background(), NewOpts{
			Name: strPtr("api-server"),
			Env:  map[string]string{"NODE_ENV": "production", "PORT": "3000"},
		})
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		cmd := m.body()
		if !strings.HasPrefix(cmd, "new --name=api-server") {
			t.Errorf("command should start with 'new --name=api-server', got %q", cmd)
		}
		if !strings.Contains(cmd, "--env=NODE_ENV=production") {
			t.Errorf("command should contain --env=NODE_ENV=production, got %q", cmd)
		}
		if !strings.Contains(cmd, "--env=PORT=3000") {
			t.Errorf("command should contain --env=PORT=3000, got %q", cmd)
		}
		if !strings.HasSuffix(cmd, "--json") {
			t.Errorf("command should end with --json, got %q", cmd)
		}
		if result.VMName != "api-server" {
			t.Errorf("VMName = %q, want %q", result.VMName, "api-server")
		}
		if result.SSHCommand != "ssh api-server.exe.xyz" {
			t.Errorf("SSHCommand = %q, want %q", result.SSHCommand, "ssh api-server.exe.xyz")
		}
	})

	t.Run("test_with_integrations", func(t *testing.T) {
		m := mockServer(200, `{"vm_name":"dev","ssh_command":"ssh dev.exe.xyz","ssh_dest":"dev.exe.xyz","ssh_port":22,"https_url":"https://dev.exe.xyz","proxy_port":8000,"shelley_url":"https://dev.shelley.exe.xyz","vscode_url":"vscode://vscode-remote/ssh-remote+dev.exe.xyz/home/exedev?windowId=_blank","xterm_url":"https://dev.xterm.exe.xyz"}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		result, err := c.New(context.Background(), NewOpts{
			Name:        strPtr("dev"),
			Integration: []string{"github"},
		})
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		assertCommand(t, m.body, "new --name=dev --integration=github --json")
		if result.VMName != "dev" {
			t.Errorf("VMName = %q, want %q", result.VMName, "dev")
		}
		if result.SSHCommand != "ssh dev.exe.xyz" {
			t.Errorf("SSHCommand = %q, want %q", result.SSHCommand, "ssh dev.exe.xyz")
		}
	})

	t.Run("test_with_command", func(t *testing.T) {
		m := mockServer(200, `{"vm_name":"swift-owl","ssh_command":"ssh swift-owl.exe.xyz","ssh_dest":"swift-owl.exe.xyz","ssh_port":22,"https_url":"https://swift-owl.exe.xyz","proxy_port":8000,"shelley_url":"https://swift-owl.shelley.exe.xyz","vscode_url":"vscode://vscode-remote/ssh-remote+swift-owl.exe.xyz/home/exedev?windowId=_blank","xterm_url":"https://swift-owl.xterm.exe.xyz"}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		result, err := c.New(context.Background(), NewOpts{
			Image:   strPtr("nginx:latest"),
			Command: strPtr("none"),
		})
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		assertCommand(t, m.body, "new --image=nginx:latest --command=none --json")
		if result.VMName != "swift-owl" {
			t.Errorf("VMName = %q, want %q", result.VMName, "swift-owl")
		}
		if result.SSHCommand != "ssh swift-owl.exe.xyz" {
			t.Errorf("SSHCommand = %q, want %q", result.SSHCommand, "ssh swift-owl.exe.xyz")
		}
	})

	t.Run("test_no_email", func(t *testing.T) {
		m := mockServer(200, `{"vm_name":"quiet-vm","ssh_command":"ssh quiet-vm.exe.xyz","ssh_dest":"quiet-vm.exe.xyz","ssh_port":22,"https_url":"https://quiet-vm.exe.xyz","proxy_port":8000,"shelley_url":"https://quiet-vm.shelley.exe.xyz","vscode_url":"vscode://vscode-remote/ssh-remote+quiet-vm.exe.xyz/home/exedev?windowId=_blank","xterm_url":"https://quiet-vm.xterm.exe.xyz"}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		result, err := c.New(context.Background(), NewOpts{
			Name:    strPtr("quiet-vm"),
			NoEmail: true,
		})
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		assertCommand(t, m.body, "new --name=quiet-vm --no-email --json")
		if result.VMName != "quiet-vm" {
			t.Errorf("VMName = %q, want %q", result.VMName, "quiet-vm")
		}
		if result.SSHCommand != "ssh quiet-vm.exe.xyz" {
			t.Errorf("SSHCommand = %q, want %q", result.SSHCommand, "ssh quiet-vm.exe.xyz")
		}
	})

	t.Run("test_all_options", func(t *testing.T) {
		m := mockServer(200, `{"vm_name":"full","ssh_command":"ssh full.exe.xyz","ssh_dest":"full.exe.xyz","ssh_port":22,"https_url":"https://full.exe.xyz","proxy_port":8000,"shelley_url":"https://full.shelley.exe.xyz","vscode_url":"vscode://vscode-remote/ssh-remote+full.exe.xyz/home/exedev?windowId=_blank","xterm_url":"https://full.xterm.exe.xyz"}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		result, err := c.New(context.Background(), NewOpts{
			Name:        strPtr("full"),
			Image:       strPtr("ubuntu:24.04"),
			Command:     strPtr("auto"),
			Env:         map[string]string{"KEY": "val"},
			Integration: []string{"github"},
			NoEmail:     true,
		})
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		cmd := m.body()
		if !strings.HasPrefix(cmd, "new --name=full --image=ubuntu:24.04 --command=auto") {
			t.Errorf("command should start with expected prefix, got %q", cmd)
		}
		if !strings.Contains(cmd, "--env=KEY=val") {
			t.Errorf("command should contain --env=KEY=val, got %q", cmd)
		}
		if !strings.Contains(cmd, "--integration=github") {
			t.Errorf("command should contain --integration=github, got %q", cmd)
		}
		if !strings.Contains(cmd, "--no-email") {
			t.Errorf("command should contain --no-email, got %q", cmd)
		}
		if !strings.HasSuffix(cmd, "--json") {
			t.Errorf("command should end with --json, got %q", cmd)
		}
		if result.VMName != "full" {
			t.Errorf("VMName = %q, want %q", result.VMName, "full")
		}
		if result.SSHCommand != "ssh full.exe.xyz" {
			t.Errorf("SSHCommand = %q, want %q", result.SSHCommand, "ssh full.exe.xyz")
		}
	})

	t.Run("test_rate_limited", func(t *testing.T) {
		m := mockServer(429, "rate limited")
		defer m.server.Close()
		c := newTestClient(t, m)
		_, err := c.New(context.Background(), NewOpts{})
		assertExeDevError(t, err, 429, "rate limited")
	})
}

// ---------------------------------------------------------------------------
// TestRm
// ---------------------------------------------------------------------------

func TestRm(t *testing.T) {
	t.Run("test_single", func(t *testing.T) {
		m := mockServer(200, `{"deleted":["old-project"],"failed":[]}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		result, err := c.Rm(context.Background(), "old-project")
		if err != nil {
			t.Fatalf("Rm() error: %v", err)
		}
		assertCommand(t, m.body, "rm old-project")
		if len(result.Deleted) != 1 || result.Deleted[0] != "old-project" {
			t.Errorf("Deleted = %v, want [old-project]", result.Deleted)
		}
		if len(result.Failed) != 0 {
			t.Errorf("Failed = %v, want []", result.Failed)
		}
	})

	t.Run("test_multiple", func(t *testing.T) {
		m := mockServer(200, `{"deleted":["vm1","vm2","vm3"],"failed":[]}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		result, err := c.Rm(context.Background(), "vm1", "vm2", "vm3")
		if err != nil {
			t.Fatalf("Rm() error: %v", err)
		}
		assertCommand(t, m.body, "rm vm1 vm2 vm3")
		if len(result.Deleted) != 3 {
			t.Fatalf("len(Deleted) = %d, want 3", len(result.Deleted))
		}
		expected := []string{"vm1", "vm2", "vm3"}
		for i, v := range expected {
			if result.Deleted[i] != v {
				t.Errorf("Deleted[%d] = %q, want %q", i, result.Deleted[i], v)
			}
		}
		if len(result.Failed) != 0 {
			t.Errorf("Failed = %v, want []", result.Failed)
		}
	})

	t.Run("test_not_found", func(t *testing.T) {
		m := mockServer(422, `{"error":"vm not found: nonexistent"}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		_, err := c.Rm(context.Background(), "nonexistent")
		assertExeDevError(t, err, 422, `{"error":"vm not found: nonexistent"}`)
	})

	t.Run("test_empty_list", func(t *testing.T) {
		// No mock server needed — should fail locally before making a request.
		m := mockServer(200, "")
		defer m.server.Close()
		c := newTestClient(t, m)
		_, err := c.Rm(context.Background())
		assertExeDevError(t, err, 0, "at least one VM name is required")
	})
}

// ---------------------------------------------------------------------------
// TestRestart
// ---------------------------------------------------------------------------

func TestRestart(t *testing.T) {
	t.Run("test_restart", func(t *testing.T) {
		m := mockServer(200, `{"status":"restarted","vm_name":"example-vm"}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		result, err := c.Restart(context.Background(), "example-vm")
		if err != nil {
			t.Fatalf("Restart() error: %v", err)
		}
		assertCommand(t, m.body, "restart example-vm")
		if result.Status != "restarted" {
			t.Errorf("Status = %q, want %q", result.Status, "restarted")
		}
		if result.VMName != "example-vm" {
			t.Errorf("VMName = %q, want %q", result.VMName, "example-vm")
		}
	})

	t.Run("test_not_found", func(t *testing.T) {
		m := mockServer(422, `{"error":"vm not found: ghost"}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		_, err := c.Restart(context.Background(), "ghost")
		assertExeDevError(t, err, 422, `{"error":"vm not found: ghost"}`)
	})
}

// ---------------------------------------------------------------------------
// TestRename
// ---------------------------------------------------------------------------

func TestRename(t *testing.T) {
	t.Run("test_rename", func(t *testing.T) {
		m := mockServer(200, `{"new_name":"example-vm-renamed","old_name":"example-vm","status":"renamed"}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		result, err := c.Rename(context.Background(), "example-vm", "example-vm-renamed")
		if err != nil {
			t.Fatalf("Rename() error: %v", err)
		}
		assertCommand(t, m.body, "rename example-vm example-vm-renamed")
		if result.OldName != "example-vm" {
			t.Errorf("OldName = %q, want %q", result.OldName, "example-vm")
		}
		if result.NewName != "example-vm-renamed" {
			t.Errorf("NewName = %q, want %q", result.NewName, "example-vm-renamed")
		}
		if result.Status != "renamed" {
			t.Errorf("Status = %q, want %q", result.Status, "renamed")
		}
	})
}

// ---------------------------------------------------------------------------
// TestCp
// ---------------------------------------------------------------------------

func TestCp(t *testing.T) {
	t.Run("test_auto_name", func(t *testing.T) {
		m := mockServer(200, `{"elapsed":1.06002825,"name":"example-vm-copy","source":"example-vm-renamed","ssh":"example-vm-copy.exe.xyz","state":"starting"}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		result, err := c.Cp(context.Background(), "example-vm-renamed", nil)
		if err != nil {
			t.Fatalf("Cp() error: %v", err)
		}
		assertCommand(t, m.body, "cp example-vm-renamed --json")
		if result.Name != "example-vm-copy" {
			t.Errorf("Name = %q, want %q", result.Name, "example-vm-copy")
		}
		if result.Source != "example-vm-renamed" {
			t.Errorf("Source = %q, want %q", result.Source, "example-vm-renamed")
		}
		if result.SSH != "example-vm-copy.exe.xyz" {
			t.Errorf("SSH = %q, want %q", result.SSH, "example-vm-copy.exe.xyz")
		}
		if result.State != "starting" {
			t.Errorf("State = %q, want %q", result.State, "starting")
		}
		if result.Elapsed != 1.06002825 {
			t.Errorf("Elapsed = %f, want %f", result.Elapsed, 1.06002825)
		}
	})

	t.Run("test_custom_name", func(t *testing.T) {
		m := mockServer(200, `{"elapsed":0.95,"name":"web-staging","source":"web","ssh":"web-staging.exe.xyz","state":"starting"}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		result, err := c.Cp(context.Background(), "web", strPtr("web-staging"))
		if err != nil {
			t.Fatalf("Cp() error: %v", err)
		}
		assertCommand(t, m.body, "cp web web-staging --json")
		if result.Name != "web-staging" {
			t.Errorf("Name = %q, want %q", result.Name, "web-staging")
		}
		if result.Source != "web" {
			t.Errorf("Source = %q, want %q", result.Source, "web")
		}
		if result.SSH != "web-staging.exe.xyz" {
			t.Errorf("SSH = %q, want %q", result.SSH, "web-staging.exe.xyz")
		}
		if result.State != "starting" {
			t.Errorf("State = %q, want %q", result.State, "starting")
		}
	})
}

// ---------------------------------------------------------------------------
// TestTag
// ---------------------------------------------------------------------------

func TestTag(t *testing.T) {
	t.Run("test_add", func(t *testing.T) {
		m := mockServer(200, `{"tags":["testtag"],"vm_name":"example-vm"}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		result, err := c.Tag(context.Background(), "example-vm", "testtag")
		if err != nil {
			t.Fatalf("Tag() error: %v", err)
		}
		assertCommand(t, m.body, "tag example-vm testtag")
		if len(result.Tags) != 1 || result.Tags[0] != "testtag" {
			t.Errorf("Tags = %v, want [testtag]", result.Tags)
		}
		if result.VMName != "example-vm" {
			t.Errorf("VMName = %q, want %q", result.VMName, "example-vm")
		}
	})

	t.Run("test_invalid_hyphen", func(t *testing.T) {
		m := mockServer(422, `{"error":"invalid tag name \"test-tag\": must match [a-z][a-z0-9_]*"}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		_, err := c.Tag(context.Background(), "example-vm", "test-tag")
		assertExeDevError(t, err, 422, `{"error":"invalid tag name \"test-tag\": must match [a-z][a-z0-9_]*"}`)
	})
}

// ---------------------------------------------------------------------------
// TestUntag
// ---------------------------------------------------------------------------

func TestUntag(t *testing.T) {
	t.Run("test_remove", func(t *testing.T) {
		m := mockServer(200, `{"tags":[],"vm_name":"example-vm"}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		result, err := c.Untag(context.Background(), "example-vm", "testtag")
		if err != nil {
			t.Fatalf("Untag() error: %v", err)
		}
		assertCommand(t, m.body, "tag -d example-vm testtag")
		if len(result.Tags) != 0 {
			t.Errorf("Tags = %v, want []", result.Tags)
		}
		if result.VMName != "example-vm" {
			t.Errorf("VMName = %q, want %q", result.VMName, "example-vm")
		}
	})
}

// ---------------------------------------------------------------------------
// TestShareShow
// ---------------------------------------------------------------------------

func TestShareShow(t *testing.T) {
	t.Run("test_private", func(t *testing.T) {
		m := mockServer(200, `{"links":[],"port":8000,"status":"private","team_access":false,"team_shelley":false,"team_ssh":false,"teams":[],"url":"https://my-app.exe.xyz","users":[],"vm_name":"my-app"}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		result, err := c.ShareShow(context.Background(), "my-app")
		if err != nil {
			t.Fatalf("ShareShow() error: %v", err)
		}
		assertCommand(t, m.body, "share show my-app --json")
		if result.VMName != "my-app" {
			t.Errorf("VMName = %q, want %q", result.VMName, "my-app")
		}
		if result.Status != "private" {
			t.Errorf("Status = %q, want %q", result.Status, "private")
		}
		if result.URL != "https://my-app.exe.xyz" {
			t.Errorf("URL = %q, want %q", result.URL, "https://my-app.exe.xyz")
		}
		if result.Port != 8000 {
			t.Errorf("Port = %d, want %d", result.Port, 8000)
		}
		if len(result.Users) != 0 {
			t.Errorf("Users = %v, want []", result.Users)
		}
		if len(result.Links) != 0 {
			t.Errorf("Links = %v, want []", result.Links)
		}
		if result.TeamAccess != false {
			t.Errorf("TeamAccess = %v, want false", result.TeamAccess)
		}
		if result.TeamShelley != false {
			t.Errorf("TeamShelley = %v, want false", result.TeamShelley)
		}
		if result.TeamSSH != false {
			t.Errorf("TeamSSH = %v, want false", result.TeamSSH)
		}
		if len(result.Teams) != 0 {
			t.Errorf("Teams = %v, want []", result.Teams)
		}
	})

	t.Run("test_public", func(t *testing.T) {
		m := mockServer(200, `{"links":[],"port":3000,"status":"public","team_access":false,"team_shelley":false,"team_ssh":false,"teams":[],"url":"https://example-vm.exe.xyz","users":[],"vm_name":"example-vm"}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		result, err := c.ShareShow(context.Background(), "example-vm")
		if err != nil {
			t.Fatalf("ShareShow() error: %v", err)
		}
		assertCommand(t, m.body, "share show example-vm --json")
		if result.VMName != "example-vm" {
			t.Errorf("VMName = %q, want %q", result.VMName, "example-vm")
		}
		if result.Status != "public" {
			t.Errorf("Status = %q, want %q", result.Status, "public")
		}
		if result.URL != "https://example-vm.exe.xyz" {
			t.Errorf("URL = %q, want %q", result.URL, "https://example-vm.exe.xyz")
		}
		if result.Port != 3000 {
			t.Errorf("Port = %d, want %d", result.Port, 3000)
		}
		if len(result.Links) != 0 {
			t.Errorf("Links = %v, want []", result.Links)
		}
		if result.TeamAccess != false {
			t.Errorf("TeamAccess = %v, want false", result.TeamAccess)
		}
	})

	t.Run("test_fresh", func(t *testing.T) {
		m := mockServer(200, `{"links":[],"port":8000,"status":"private","team_access":false,"team_shelley":false,"team_ssh":false,"teams":[],"url":"https://example-vm.exe.xyz","users":[],"vm_name":"example-vm"}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		result, err := c.ShareShow(context.Background(), "example-vm")
		if err != nil {
			t.Fatalf("ShareShow() error: %v", err)
		}
		assertCommand(t, m.body, "share show example-vm --json")
		if result.VMName != "example-vm" {
			t.Errorf("VMName = %q, want %q", result.VMName, "example-vm")
		}
		if result.Status != "private" {
			t.Errorf("Status = %q, want %q", result.Status, "private")
		}
		if result.Port != 8000 {
			t.Errorf("Port = %d, want %d", result.Port, 8000)
		}
	})
}

// ---------------------------------------------------------------------------
// TestShareSetPublic
// ---------------------------------------------------------------------------

func TestShareSetPublic(t *testing.T) {
	m := mockServer(200, `{"port":8000,"share":"public","status":"updated","team_access":false,"team_shelley":false,"team_ssh":false,"vm_name":"example-vm"}`)
	defer m.server.Close()
	c := newTestClient(t, m)
	result, err := c.ShareSetPublic(context.Background(), "example-vm")
	if err != nil {
		t.Fatalf("ShareSetPublic() error: %v", err)
	}
	assertCommand(t, m.body, "share set-public example-vm")
	if result.Status != "updated" {
		t.Errorf("Status = %q, want %q", result.Status, "updated")
	}
	if result.Share != "public" {
		t.Errorf("Share = %q, want %q", result.Share, "public")
	}
	if result.Port != 8000 {
		t.Errorf("Port = %d, want %d", result.Port, 8000)
	}
	if result.VMName != "example-vm" {
		t.Errorf("VMName = %q, want %q", result.VMName, "example-vm")
	}
	if result.TeamAccess != false {
		t.Errorf("TeamAccess = %v, want false", result.TeamAccess)
	}
	if result.TeamShelley != false {
		t.Errorf("TeamShelley = %v, want false", result.TeamShelley)
	}
	if result.TeamSSH != false {
		t.Errorf("TeamSSH = %v, want false", result.TeamSSH)
	}
}

// ---------------------------------------------------------------------------
// TestShareSetPrivate
// ---------------------------------------------------------------------------

func TestShareSetPrivate(t *testing.T) {
	m := mockServer(200, `{"port":3000,"share":"private","status":"updated","team_access":false,"team_shelley":false,"team_ssh":false,"vm_name":"example-vm"}`)
	defer m.server.Close()
	c := newTestClient(t, m)
	result, err := c.ShareSetPrivate(context.Background(), "example-vm")
	if err != nil {
		t.Fatalf("ShareSetPrivate() error: %v", err)
	}
	assertCommand(t, m.body, "share set-private example-vm")
	if result.Status != "updated" {
		t.Errorf("Status = %q, want %q", result.Status, "updated")
	}
	if result.Share != "private" {
		t.Errorf("Share = %q, want %q", result.Share, "private")
	}
	if result.Port != 3000 {
		t.Errorf("Port = %d, want %d", result.Port, 3000)
	}
	if result.VMName != "example-vm" {
		t.Errorf("VMName = %q, want %q", result.VMName, "example-vm")
	}
	if result.TeamAccess != false {
		t.Errorf("TeamAccess = %v, want false", result.TeamAccess)
	}
	if result.TeamShelley != false {
		t.Errorf("TeamShelley = %v, want false", result.TeamShelley)
	}
	if result.TeamSSH != false {
		t.Errorf("TeamSSH = %v, want false", result.TeamSSH)
	}
}

// ---------------------------------------------------------------------------
// TestSharePort
// ---------------------------------------------------------------------------

func TestSharePort(t *testing.T) {
	t.Run("test_set_port", func(t *testing.T) {
		m := mockServer(200, `{"port":3000,"share":"public","status":"updated","team_access":false,"team_shelley":false,"team_ssh":false,"vm_name":"example-vm"}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		result, err := c.SharePort(context.Background(), "example-vm", 3000)
		if err != nil {
			t.Fatalf("SharePort() error: %v", err)
		}
		assertCommand(t, m.body, "share port example-vm 3000")
		if result.Status != "updated" {
			t.Errorf("Status = %q, want %q", result.Status, "updated")
		}
		if result.Share != "public" {
			t.Errorf("Share = %q, want %q", result.Share, "public")
		}
		if result.Port != 3000 {
			t.Errorf("Port = %d, want %d", result.Port, 3000)
		}
		if result.VMName != "example-vm" {
			t.Errorf("VMName = %q, want %q", result.VMName, "example-vm")
		}
	})

	t.Run("test_invalid_zero", func(t *testing.T) {
		m := mockServer(200, "")
		defer m.server.Close()
		c := newTestClient(t, m)
		_, err := c.SharePort(context.Background(), "web", 0)
		assertExeDevError(t, err, 0, "port must be between 1 and 65535")
	})

	t.Run("test_invalid_too_high", func(t *testing.T) {
		m := mockServer(200, "")
		defer m.server.Close()
		c := newTestClient(t, m)
		_, err := c.SharePort(context.Background(), "web", 70000)
		assertExeDevError(t, err, 0, "port must be between 1 and 65535")
	})
}

// ---------------------------------------------------------------------------
// TestShareAdd
// ---------------------------------------------------------------------------

func TestShareAdd(t *testing.T) {
	t.Run("test_share_add", func(t *testing.T) {
		m := mockServer(200, "")
		defer m.server.Close()
		c := newTestClient(t, m)
		err := c.ShareAdd(context.Background(), "web", "alice@example.com")
		if err != nil {
			t.Fatalf("ShareAdd() error: %v", err)
		}
		assertCommand(t, m.body, "share add web alice@example.com")
	})
}

// ---------------------------------------------------------------------------
// TestShareRemove
// ---------------------------------------------------------------------------

func TestShareRemove(t *testing.T) {
	t.Run("test_share_remove", func(t *testing.T) {
		m := mockServer(200, "")
		defer m.server.Close()
		c := newTestClient(t, m)
		err := c.ShareRemove(context.Background(), "web", "alice@example.com")
		if err != nil {
			t.Fatalf("ShareRemove() error: %v", err)
		}
		assertCommand(t, m.body, "share remove web alice@example.com")
	})
}

// ---------------------------------------------------------------------------
// TestShareAddLink
// ---------------------------------------------------------------------------

func TestShareAddLink(t *testing.T) {
	m := mockServer(200, `{"status":"success","token":"GNFM5GK72LOIQ32TVZOBDPJI4I","url":"https://example-vm.exe.xyz?share=GNFM5GK72LOIQ32TVZOBDPJI4I","vm_name":"example-vm"}`)
	defer m.server.Close()
	c := newTestClient(t, m)
	result, err := c.ShareAddLink(context.Background(), "example-vm")
	if err != nil {
		t.Fatalf("ShareAddLink() error: %v", err)
	}
	assertCommand(t, m.body, "share add-link example-vm --json")
	if result.Status != "success" {
		t.Errorf("Status = %q, want %q", result.Status, "success")
	}
	if result.Token != "GNFM5GK72LOIQ32TVZOBDPJI4I" {
		t.Errorf("Token = %q, want %q", result.Token, "GNFM5GK72LOIQ32TVZOBDPJI4I")
	}
	if result.URL != "https://example-vm.exe.xyz?share=GNFM5GK72LOIQ32TVZOBDPJI4I" {
		t.Errorf("URL = %q, want %q", result.URL, "https://example-vm.exe.xyz?share=GNFM5GK72LOIQ32TVZOBDPJI4I")
	}
	if result.VMName != "example-vm" {
		t.Errorf("VMName = %q, want %q", result.VMName, "example-vm")
	}
}

// ---------------------------------------------------------------------------
// TestShareRemoveLink
// ---------------------------------------------------------------------------

func TestShareRemoveLink(t *testing.T) {
	m := mockServer(200, "")
	defer m.server.Close()
	c := newTestClient(t, m)
	err := c.ShareRemoveLink(context.Background(), "web")
	if err != nil {
		t.Fatalf("ShareRemoveLink() error: %v", err)
	}
	assertCommand(t, m.body, "share remove-link web")
}

// ---------------------------------------------------------------------------
// TestShareReceiveEmail
// ---------------------------------------------------------------------------

func TestShareReceiveEmail(t *testing.T) {
	t.Run("test_enable", func(t *testing.T) {
		m := mockServer(200, `{"email_address":"anything@example-vm.exe.xyz","email_enabled":true,"status":"success","vm_name":"example-vm"}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		result, err := c.ShareReceiveEmail(context.Background(), "example-vm", true)
		if err != nil {
			t.Fatalf("ShareReceiveEmail() error: %v", err)
		}
		assertCommand(t, m.body, "share receive-email example-vm on")
		if result.EmailEnabled != true {
			t.Errorf("EmailEnabled = %v, want true", result.EmailEnabled)
		}
		if result.Status != "success" {
			t.Errorf("Status = %q, want %q", result.Status, "success")
		}
		if result.VMName != "example-vm" {
			t.Errorf("VMName = %q, want %q", result.VMName, "example-vm")
		}
		if result.EmailAddress == nil || *result.EmailAddress != "anything@example-vm.exe.xyz" {
			t.Errorf("EmailAddress = %v, want %q", result.EmailAddress, "anything@example-vm.exe.xyz")
		}
	})

	t.Run("test_disable", func(t *testing.T) {
		m := mockServer(200, `{"email_enabled":false,"status":"success","vm_name":"example-vm"}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		result, err := c.ShareReceiveEmail(context.Background(), "example-vm", false)
		if err != nil {
			t.Fatalf("ShareReceiveEmail() error: %v", err)
		}
		assertCommand(t, m.body, "share receive-email example-vm off")
		if result.EmailEnabled != false {
			t.Errorf("EmailEnabled = %v, want false", result.EmailEnabled)
		}
		if result.Status != "success" {
			t.Errorf("Status = %q, want %q", result.Status, "success")
		}
		if result.VMName != "example-vm" {
			t.Errorf("VMName = %q, want %q", result.VMName, "example-vm")
		}
		if result.EmailAddress != nil {
			t.Errorf("EmailAddress = %v, want nil", result.EmailAddress)
		}
	})
}

// ---------------------------------------------------------------------------
// TestSSHKey
// ---------------------------------------------------------------------------

func TestSSHKey(t *testing.T) {
	t.Run("test_list", func(t *testing.T) {
		m := mockServer(200, `{"ssh_keys":[{"public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyData","fingerprint":"SHA256:ExampleFingerprint123","name":"key-1","added_at":"2026-01-01T12:58:15Z","last_used_at":"2026-03-21T11:36:27Z","current":false}]}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		keys, err := c.SSHKeyList(context.Background())
		if err != nil {
			t.Fatalf("SSHKeyList() error: %v", err)
		}
		assertCommand(t, m.body, "ssh-key list --json")
		if len(keys) != 1 {
			t.Fatalf("len(keys) = %d, want 1", len(keys))
		}
		if keys[0].Name != "key-1" {
			t.Errorf("Name = %q, want %q", keys[0].Name, "key-1")
		}
		if keys[0].Fingerprint != "SHA256:ExampleFingerprint123" {
			t.Errorf("Fingerprint = %q, want %q", keys[0].Fingerprint, "SHA256:ExampleFingerprint123")
		}
		if keys[0].PublicKey != "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyData" {
			t.Errorf("PublicKey = %q, want %q", keys[0].PublicKey, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyData")
		}
		if keys[0].AddedAt == nil || *keys[0].AddedAt != "2026-01-01T12:58:15Z" {
			t.Errorf("AddedAt = %v, want %q", keys[0].AddedAt, "2026-01-01T12:58:15Z")
		}
		if keys[0].LastUsedAt == nil || *keys[0].LastUsedAt != "2026-03-21T11:36:27Z" {
			t.Errorf("LastUsedAt = %v, want %q", keys[0].LastUsedAt, "2026-03-21T11:36:27Z")
		}
		if keys[0].Current != false {
			t.Errorf("Current = %v, want false", keys[0].Current)
		}
	})

	t.Run("test_list_empty", func(t *testing.T) {
		m := mockServer(200, `{"ssh_keys":[]}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		keys, err := c.SSHKeyList(context.Background())
		if err != nil {
			t.Fatalf("SSHKeyList() error: %v", err)
		}
		assertCommand(t, m.body, "ssh-key list --json")
		if len(keys) != 0 {
			t.Errorf("len(keys) = %d, want 0", len(keys))
		}
	})

	t.Run("test_add", func(t *testing.T) {
		m := mockServer(200, "")
		defer m.server.Close()
		c := newTestClient(t, m)
		err := c.SSHKeyAdd(context.Background(), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample laptop")
		if err != nil {
			t.Fatalf("SSHKeyAdd() error: %v", err)
		}
		assertCommand(t, m.body, "ssh-key add ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample laptop")
	})

	t.Run("test_remove", func(t *testing.T) {
		m := mockServer(200, "")
		defer m.server.Close()
		c := newTestClient(t, m)
		err := c.SSHKeyRemove(context.Background(), "SHA256:abc123")
		if err != nil {
			t.Fatalf("SSHKeyRemove() error: %v", err)
		}
		assertCommand(t, m.body, "ssh-key remove SHA256:abc123")
	})

	t.Run("test_rename", func(t *testing.T) {
		m := mockServer(200, "")
		defer m.server.Close()
		c := newTestClient(t, m)
		err := c.SSHKeyRename(context.Background(), "SHA256:abc123", "work-laptop")
		if err != nil {
			t.Fatalf("SSHKeyRename() error: %v", err)
		}
		assertCommand(t, m.body, "ssh-key rename SHA256:abc123 work-laptop")
	})
}

// ---------------------------------------------------------------------------
// TestWhoami
// ---------------------------------------------------------------------------

func TestWhoami(t *testing.T) {
	t.Run("test_basic", func(t *testing.T) {
		m := mockServer(200, `{"email":"user@example.com","ssh_keys":[{"public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyData","fingerprint":"SHA256:ExampleFingerprint123","name":"key-1","current":false}]}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		info, err := c.Whoami(context.Background())
		if err != nil {
			t.Fatalf("Whoami() error: %v", err)
		}
		assertCommand(t, m.body, "whoami --json")
		if info.Email != "user@example.com" {
			t.Errorf("Email = %q, want %q", info.Email, "user@example.com")
		}
		if len(info.SSHKeys) != 1 {
			t.Fatalf("len(SSHKeys) = %d, want 1", len(info.SSHKeys))
		}
		if info.SSHKeys[0].Name != "key-1" {
			t.Errorf("Name = %q, want %q", info.SSHKeys[0].Name, "key-1")
		}
		if info.SSHKeys[0].Fingerprint != "SHA256:ExampleFingerprint123" {
			t.Errorf("Fingerprint = %q, want %q", info.SSHKeys[0].Fingerprint, "SHA256:ExampleFingerprint123")
		}
		if info.SSHKeys[0].PublicKey != "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyData" {
			t.Errorf("PublicKey = %q, want %q", info.SSHKeys[0].PublicKey, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyData")
		}
		if info.SSHKeys[0].Current != false {
			t.Errorf("Current = %v, want false", info.SSHKeys[0].Current)
		}
	})

	t.Run("test_forbidden", func(t *testing.T) {
		m := mockServer(403, `{"error":"command not allowed"}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		_, err := c.Whoami(context.Background())
		assertExeDevError(t, err, 403, `{"error":"command not allowed"}`)
	})
}

// ---------------------------------------------------------------------------
// TestShelley
// ---------------------------------------------------------------------------

func TestShelley(t *testing.T) {
	t.Run("test_install", func(t *testing.T) {
		m := mockServer(200, "")
		defer m.server.Close()
		c := newTestClient(t, m)
		err := c.ShelleyInstall(context.Background(), "dev")
		if err != nil {
			t.Fatalf("ShelleyInstall() error: %v", err)
		}
		assertCommand(t, m.body, "shelley install dev")
	})

	t.Run("test_prompt", func(t *testing.T) {
		m := mockServer(200, "")
		defer m.server.Close()
		c := newTestClient(t, m)
		err := c.ShelleyPrompt(context.Background(), "dev", "create a hello world app")
		if err != nil {
			t.Fatalf("ShelleyPrompt() error: %v", err)
		}
		assertCommand(t, m.body, `shelley prompt dev "create a hello world app"`)
	})
}

// ---------------------------------------------------------------------------
// TestValidation
// ---------------------------------------------------------------------------

func TestValidation(t *testing.T) {
	t.Run("test_reject_spaces", func(t *testing.T) {
		m := mockServer(200, "")
		defer m.server.Close()
		c := newTestClient(t, m)
		_, err := c.Rm(context.Background(), "bad name")
		assertExeDevError(t, err, 0, "invalid characters in value")
	})

	t.Run("test_reject_semicolons", func(t *testing.T) {
		m := mockServer(200, "")
		defer m.server.Close()
		c := newTestClient(t, m)
		_, err := c.Restart(context.Background(), "vm;rm -rf /")
		assertExeDevError(t, err, 0, "invalid characters in value")
	})

	t.Run("test_reject_pipes", func(t *testing.T) {
		m := mockServer(200, "")
		defer m.server.Close()
		c := newTestClient(t, m)
		_, err := c.Restart(context.Background(), "vm|cat /etc/passwd")
		assertExeDevError(t, err, 0, "invalid characters in value")
	})

	t.Run("test_accept_hyphens", func(t *testing.T) {
		m := mockServer(200, `{"status":"restarted","vm_name":"my-cool-vm"}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		result, err := c.Restart(context.Background(), "my-cool-vm")
		if err != nil {
			t.Fatalf("Restart() error: %v", err)
		}
		assertCommand(t, m.body, "restart my-cool-vm")
		if result.Status != "restarted" {
			t.Errorf("Status = %q, want %q", result.Status, "restarted")
		}
		if result.VMName != "my-cool-vm" {
			t.Errorf("VMName = %q, want %q", result.VMName, "my-cool-vm")
		}
	})

	t.Run("test_accept_underscores", func(t *testing.T) {
		m := mockServer(200, `{"status":"restarted","vm_name":"my_vm_2"}`)
		defer m.server.Close()
		c := newTestClient(t, m)
		result, err := c.Restart(context.Background(), "my_vm_2")
		if err != nil {
			t.Fatalf("Restart() error: %v", err)
		}
		assertCommand(t, m.body, "restart my_vm_2")
		if result.Status != "restarted" {
			t.Errorf("Status = %q, want %q", result.Status, "restarted")
		}
		if result.VMName != "my_vm_2" {
			t.Errorf("VMName = %q, want %q", result.VMName, "my_vm_2")
		}
	})
}

// ---------------------------------------------------------------------------
// TestTokenGeneration
// ---------------------------------------------------------------------------

func TestTokenGeneration(t *testing.T) {
	t.Run("test_empty_permissions", func(t *testing.T) {
		c, err := NewClient(testKeyPEM)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}
		token, err := c.GenerateToken(nil)
		if err != nil {
			t.Fatalf("GenerateToken() error: %v", err)
		}
		if !strings.HasPrefix(token, "exe0.") {
			t.Errorf("token should start with 'exe0.', got %q", token)
		}
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Fatalf("token should have 3 segments, got %d", len(parts))
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("failed to decode payload: %v", err)
		}
		if string(payload) != "{}" {
			t.Errorf("payload = %q, want %q", string(payload), "{}")
		}
	})

	t.Run("test_with_expiry", func(t *testing.T) {
		c, err := NewClient(testKeyPEM)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}
		perms := &TokenPermissions{Exp: int64Ptr(1735689600)}
		token, err := c.GenerateToken(perms)
		if err != nil {
			t.Fatalf("GenerateToken() error: %v", err)
		}
		if !strings.HasPrefix(token, "exe0.") {
			t.Errorf("token should start with 'exe0.', got %q", token)
		}
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Fatalf("token should have 3 segments, got %d", len(parts))
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("failed to decode payload: %v", err)
		}
		if string(payload) != `{"exp":1735689600}` {
			t.Errorf("payload = %q, want %q", string(payload), `{"exp":1735689600}`)
		}
	})

	t.Run("test_with_cmds", func(t *testing.T) {
		c, err := NewClient(testKeyPEM)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}
		perms := &TokenPermissions{Cmds: []string{"ls", "whoami"}}
		token, err := c.GenerateToken(perms)
		if err != nil {
			t.Fatalf("GenerateToken() error: %v", err)
		}
		if !strings.HasPrefix(token, "exe0.") {
			t.Errorf("token should start with 'exe0.', got %q", token)
		}
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Fatalf("token should have 3 segments, got %d", len(parts))
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("failed to decode payload: %v", err)
		}
		if string(payload) != `{"cmds":["ls","whoami"]}` {
			t.Errorf("payload = %q, want %q", string(payload), `{"cmds":["ls","whoami"]}`)
		}
	})

	t.Run("test_all_fields", func(t *testing.T) {
		c, err := NewClient(testKeyPEM)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}
		perms := &TokenPermissions{
			Exp:  int64Ptr(1735689600),
			Nbf:  int64Ptr(1735686000),
			Cmds: []string{"ls"},
			Ctx:  map[string]interface{}{"role": "readonly"},
		}
		token, err := c.GenerateToken(perms)
		if err != nil {
			t.Fatalf("GenerateToken() error: %v", err)
		}
		if !strings.HasPrefix(token, "exe0.") {
			t.Errorf("token should start with 'exe0.', got %q", token)
		}
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Fatalf("token should have 3 segments, got %d", len(parts))
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("failed to decode payload: %v", err)
		}
		var payloadData map[string]interface{}
		if err := json.Unmarshal(payload, &payloadData); err != nil {
			t.Fatalf("failed to unmarshal payload: %v", err)
		}
		expectedKeys := []string{"exp", "nbf", "cmds", "ctx"}
		for _, key := range expectedKeys {
			if _, ok := payloadData[key]; !ok {
				t.Errorf("payload missing key %q", key)
			}
		}
		if len(payloadData) != len(expectedKeys) {
			t.Errorf("payload has %d keys, want %d", len(payloadData), len(expectedKeys))
		}
	})

	t.Run("test_vm_scoped", func(t *testing.T) {
		c, err := NewClient(testKeyPEM)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}
		token, err := c.GenerateVMToken("my-vm", nil)
		if err != nil {
			t.Fatalf("GenerateVMToken() error: %v", err)
		}
		if !strings.HasPrefix(token, "exe0.") {
			t.Errorf("token should start with 'exe0.', got %q", token)
		}
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Fatalf("token should have 3 segments, got %d", len(parts))
		}
	})
}

// ---------------------------------------------------------------------------
// TestErrorResponses
// ---------------------------------------------------------------------------

func TestErrorResponses(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		method string // "ls" or "rm"
		input  string // for rm
	}{
		{"400_bad_request", 400, `{"error":"empty request body"}`, "ls", ""},
		{"401_unauthorized", 401, `{"error":"token expired"}`, "ls", ""},
		{"403_forbidden", 403, `{"error":"command not in cmds list"}`, "ls", ""},
		{"404_not_found", 404, `{"error":"unknown command"}`, "ls", ""},
		{"413_too_large", 413, "request body too large", "ls", ""},
		{"422_command_failed", 422, `{"error":"vm not found"}`, "rm", "ghost"},
		{"429_rate_limited", 429, "too many requests", "ls", ""},
		{"500_server_error", 500, "internal server error", "ls", ""},
		{"504_timeout", 504, "command timed out", "ls", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := mockServer(tc.status, tc.body)
			defer m.server.Close()
			c := newTestClient(t, m)

			var err error
			if tc.method == "rm" {
				_, err = c.Rm(context.Background(), tc.input)
			} else {
				_, err = c.Ls(context.Background(), false, false)
			}

			assertExeDevError(t, err, tc.status, tc.body)
		})
	}
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

func strPtr(s string) *string {
	return &s
}

func int64Ptr(v int64) *int64 {
	return &v
}
