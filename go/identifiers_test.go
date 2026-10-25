package exedev

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Identifier validation regression tests, over real HTTP
// ---------------------------------------------------------------------------

// Response bodies from the verified fixtures, keyed by the command's first words.
var identifierResponses = []struct{ prefix, body string }{
	{"share receive-email", `{"email_enabled":false,"status":"success","vm_name":"example-vm"}`},
	{"share add-link", `{"status":"success","token":"GNFM5GK72LOIQ32TVZOBDPJI4I","url":"https://example-vm.exe.xyz?share=GNFM5GK72LOIQ32TVZOBDPJI4I","vm_name":"example-vm"}`},
	{"share show", `{"links":[],"port":8000,"status":"private","team_access":false,"team_shelley":false,"team_ssh":false,"teams":[],"url":"https://example-vm.exe.xyz","users":[],"vm_name":"example-vm"}`},
	{"share", `{"port":8000,"share":"public","status":"updated","team_access":false,"team_shelley":false,"team_ssh":false,"vm_name":"example-vm"}`},
	{"new", `{"vm_name":"example-vm","ssh_command":"ssh example-vm.exe.xyz","ssh_dest":"example-vm.exe.xyz","ssh_port":22,"https_url":"https://example-vm.exe.xyz","proxy_port":8000,"shelley_url":"https://example-vm.shelley.exe.xyz","vscode_url":"vscode://vscode-remote/ssh-remote+example-vm.exe.xyz/home/exedev?windowId=_blank"}`},
	{"rm", `{"deleted":["example-vm-copy"],"failed":[]}`},
	{"restart", `{"status":"restarted","vm_name":"example-vm"}`},
	{"rename", `{"new_name":"example-vm-renamed","old_name":"example-vm","status":"renamed"}`},
	{"cp", `{"elapsed":1.06002825,"name":"example-vm-copy","source":"example-vm-renamed","ssh":"example-vm-copy.exe.xyz","state":"starting"}`},
	{"tag", `{"tags":["testtag"],"vm_name":"example-vm"}`},
}

type recordedRequest struct {
	path string
	body string
}

// recordingServer is a local exe.dev stand-in that records each request.
type recordingServer struct {
	*httptest.Server
	mu       sync.Mutex
	requests []recordedRequest
}

func newRecordingServer(t *testing.T) *recordingServer {
	t.Helper()
	rs := &recordingServer{}
	rs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		cmd := string(b)
		rs.mu.Lock()
		rs.requests = append(rs.requests, recordedRequest{path: r.URL.Path, body: cmd})
		rs.mu.Unlock()
		reply := "{}"
		for _, resp := range identifierResponses {
			if strings.HasPrefix(cmd, resp.prefix) {
				reply = resp.body
				break
			}
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, reply)
	}))
	t.Cleanup(rs.Close)
	return rs
}

func (rs *recordingServer) bodies() []string {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	out := make([]string, len(rs.requests))
	for i, r := range rs.requests {
		out[i] = r.body
	}
	return out
}

func (rs *recordingServer) client(t *testing.T) *Client {
	t.Helper()
	c, err := NewClient(testKeyPEM, WithBaseURL(rs.URL))
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	return c
}

// identifierCalls calls one method with the identifier under test in one
// argument. The other arguments hold valid values.
var identifierCalls = []struct {
	name string
	call func(c *Client, v string) error
}{
	{"New(Name)", func(c *Client, v string) error { _, err := c.New(context.Background(), NewOpts{Name: &v}); return err }},
	{"Rm(first)", func(c *Client, v string) error { _, err := c.Rm(context.Background(), v); return err }},
	{"Rm(second)", func(c *Client, v string) error { _, err := c.Rm(context.Background(), "dev", v); return err }},
	{"Restart", func(c *Client, v string) error { _, err := c.Restart(context.Background(), v); return err }},
	{"Rename(vmName)", func(c *Client, v string) error { _, err := c.Rename(context.Background(), v, "dev2"); return err }},
	{"Rename(newName)", func(c *Client, v string) error { _, err := c.Rename(context.Background(), "dev", v); return err }},
	{"Cp(vmName)", func(c *Client, v string) error { _, err := c.Cp(context.Background(), v, nil); return err }},
	{"Cp(newName)", func(c *Client, v string) error { _, err := c.Cp(context.Background(), "dev", &v); return err }},
	{"Tag(vmName)", func(c *Client, v string) error { _, err := c.Tag(context.Background(), v, "t1"); return err }},
	{"Tag(tagName)", func(c *Client, v string) error { _, err := c.Tag(context.Background(), "dev", v); return err }},
	{"Untag(vmName)", func(c *Client, v string) error { _, err := c.Untag(context.Background(), v, "t1"); return err }},
	{"Untag(tagName)", func(c *Client, v string) error { _, err := c.Untag(context.Background(), "dev", v); return err }},
	{"ShareShow", func(c *Client, v string) error { _, err := c.ShareShow(context.Background(), v); return err }},
	{"ShareSetPublic", func(c *Client, v string) error { _, err := c.ShareSetPublic(context.Background(), v); return err }},
	{"ShareSetPrivate", func(c *Client, v string) error { _, err := c.ShareSetPrivate(context.Background(), v); return err }},
	{"SharePort", func(c *Client, v string) error { _, err := c.SharePort(context.Background(), v, 3000); return err }},
	{"ShareAdd", func(c *Client, v string) error { return c.ShareAdd(context.Background(), v, "user@example.com") }},
	{"ShareRemove", func(c *Client, v string) error { return c.ShareRemove(context.Background(), v, "user@example.com") }},
	{"ShareAddLink", func(c *Client, v string) error { _, err := c.ShareAddLink(context.Background(), v); return err }},
	{"ShareRemoveLink", func(c *Client, v string) error { return c.ShareRemoveLink(context.Background(), v) }},
	{"ShareReceiveEmail", func(c *Client, v string) error {
		_, err := c.ShareReceiveEmail(context.Background(), v, true)
		return err
	}},
	{"SSHKeyRename(newName)", func(c *Client, v string) error { return c.SSHKeyRename(context.Background(), "SHA256:abc123", v) }},
	{"ShelleyInstall", func(c *Client, v string) error { return c.ShelleyInstall(context.Background(), v) }},
	{"ShelleyPrompt", func(c *Client, v string) error { return c.ShelleyPrompt(context.Background(), v, "hello") }},
	{"GenerateVMToken", func(c *Client, v string) error { _, err := c.GenerateVMToken(v, nil); return err }},
}

var invalidIdentifierChars = []struct{ name, value string }{
	{"dot-dot", ".."},
	{"parent dir", "../etc"},
	{"slash", "vm/x"},
	{"absolute path", "/etc/passwd"},
	{"dot", "vm.x"},
	{"colon", "vm:x"},
	{"at", "vm@x"},
	{"space", "vm name"},
	{"semicolon", "vm;ls"},
	{"pipe", "vm|ls"},
	{"ampersand", "vm&ls"},
	{"subshell", "vm$(id)"},
	{"backtick", "vm`id`"},
	{"single quote", "vm'x"},
	{"double quote", `vm"x`},
	{"redirect", "vm>out"},
	{"glob", "vm*"},
	{"trailing newline", "vm\n"},
	{"newline", "vm\nls"},
	{"tab", "vm\tx"},
	{"nul", "vm\x00x"},
	{"invalid utf-8", "vm\xffx"},
	{"leading hyphen", "-d"},
	{"long flag", "--help"},
	{"leading underscore", "_vm"},
	{"cyrillic a", "vаm"},
	{"greek omicron", "vm-ο"},
	{"fullwidth letters", "ｖｍ"},
	{"unicode hyphen", "vm‐x"},
	{"non-breaking hyphen", "vm‑x"},
	{"fullwidth digit", "vm１"},
	{"zero-width space", "vm​x"},
	{"accented letter", "vm-é"},
}

func assertRejectedLocally(t *testing.T, rs *recordingServer, err error, wantMessage string) {
	t.Helper()
	assertExeDevError(t, err, 0, wantMessage)
	if got := rs.bodies(); len(got) != 0 {
		t.Errorf("server received %d requests, want 0: %q", len(got), got)
	}
}

func TestIdentifierInvalidCharactersNeverReachTheServer(t *testing.T) {
	for _, call := range identifierCalls {
		for _, tc := range invalidIdentifierChars {
			t.Run(call.name+"/"+tc.name, func(t *testing.T) {
				rs := newRecordingServer(t)
				err := call.call(rs.client(t), tc.value)
				assertRejectedLocally(t, rs, err, "invalid characters in value")
			})
		}
	}
}

func TestIdentifierEmptyNeverReachesTheServer(t *testing.T) {
	for _, call := range identifierCalls {
		t.Run(call.name, func(t *testing.T) {
			rs := newRecordingServer(t)
			err := call.call(rs.client(t), "")
			assertRejectedLocally(t, rs, err, "value must not be empty")
		})
	}
}

func TestIdentifierTooLongNeverReachesTheServer(t *testing.T) {
	for _, call := range identifierCalls {
		t.Run(call.name, func(t *testing.T) {
			rs := newRecordingServer(t)
			err := call.call(rs.client(t), strings.Repeat("a", 64))
			assertRejectedLocally(t, rs, err, "value exceeds 63 characters")
		})
	}
}

func TestIdentifierValidValuesAreSentUnchanged(t *testing.T) {
	ctx := context.Background()
	for _, v := range []string{"a", "0", "dev", "my-cool-vm", "my_vm_2", "9lives", "A-B_c", strings.Repeat("a", 63)} {
		t.Run(v, func(t *testing.T) {
			rs := newRecordingServer(t)
			c := rs.client(t)
			if _, err := c.Restart(ctx, v); err != nil {
				t.Fatalf("Restart: %v", err)
			}
			if _, err := c.Rename(ctx, v, v); err != nil {
				t.Fatalf("Rename: %v", err)
			}
			if _, err := c.Tag(ctx, v, v); err != nil {
				t.Fatalf("Tag: %v", err)
			}
			if _, err := c.Rm(ctx, v, v); err != nil {
				t.Fatalf("Rm: %v", err)
			}
			if _, err := c.New(ctx, NewOpts{Name: &v}); err != nil {
				t.Fatalf("New: %v", err)
			}
			want := []string{
				"restart " + v,
				"rename " + v + " " + v,
				"tag " + v + " " + v,
				"rm " + v + " " + v,
				"new --name=" + v + " --json",
			}
			got := rs.bodies()
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Errorf("bodies = %q, want %q", got, want)
			}
			for _, r := range rs.requests {
				if r.path != "/exec" {
					t.Errorf("path = %q, want /exec", r.path)
				}
			}
		})
	}
}

func TestIdentifierRestartParentDirRejectedBeforeTheRequest(t *testing.T) {
	rs := newRecordingServer(t)
	c := rs.client(t)
	_, err := c.Restart(context.Background(), "../etc")
	assertRejectedLocally(t, rs, err, "invalid characters in value")

	// The same client still works for a valid name afterwards.
	resp, err := c.Restart(context.Background(), "example-vm")
	if err != nil {
		t.Fatalf("Restart: %v", err)
	}
	if resp.Status != "restarted" {
		t.Errorf("Status = %q, want restarted", resp.Status)
	}
	if got := rs.bodies(); len(got) != 1 || got[0] != "restart example-vm" {
		t.Errorf("bodies = %q, want [restart example-vm]", got)
	}
}

func TestIdentifierOneBadNameInRmSendsNothing(t *testing.T) {
	rs := newRecordingServer(t)
	_, err := rs.client(t).Rm(context.Background(), "vm1", "vm2", "../vm3")
	assertRejectedLocally(t, rs, err, "invalid characters in value")
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"my-vm_2": "my-vm_2",
		"":        "''",
		"a b":     "'a b'",
		"it's":    `'it'"'"'s'`,
		"$(id)":   "'$(id)'",
	} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFingerprintInvalidNeverReachesTheServer(t *testing.T) {
	calls := []struct {
		name string
		call func(c *Client, v string) error
	}{
		{"SSHKeyRemove", func(c *Client, v string) error { return c.SSHKeyRemove(context.Background(), v) }},
		{"SSHKeyRename(fingerprint)", func(c *Client, v string) error {
			return c.SSHKeyRename(context.Background(), v, "work-laptop")
		}},
	}
	invalid := []struct{ name, value string }{
		{"command", "SHA256:x; rm -rf /"},
		{"parent dir", "../etc --all"},
		{"dot-dot in digest", "SHA256:../etc"},
		{"space", "SHA256:abc def"},
		{"subshell", "SHA256:$(id)"},
		{"trailing newline", "SHA256:abc123\n"},
		{"no prefix", "abc123"},
		{"md5", "MD5:aa:bb:cc"},
		{"lower-case prefix", "sha256:abc123"},
		{"empty digest", "SHA256:"},
		{"empty", ""},
		{"too long", "SHA256:" + strings.Repeat("a", 44)},
		{"double padding", "SHA256:abc=="},
		{"cyrillic a", "SHA256:аbc"},
		{"leading hyphen", "-SHA256:abc"},
	}
	for _, call := range calls {
		for _, tc := range invalid {
			t.Run(call.name+"/"+tc.name, func(t *testing.T) {
				rs := newRecordingServer(t)
				err := call.call(rs.client(t), tc.value)
				assertRejectedLocally(t, rs, err, "invalid fingerprint")
			})
		}
	}
}

func TestFingerprintValidValuesAreSentUnchanged(t *testing.T) {
	ctx := context.Background()
	for _, v := range []string{
		"SHA256:abc123",
		"SHA256:ExampleFingerprint123",
		"SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8",
		"SHA256:a+b/c=",
	} {
		t.Run(v, func(t *testing.T) {
			rs := newRecordingServer(t)
			c := rs.client(t)
			if err := c.SSHKeyRemove(ctx, v); err != nil {
				t.Fatalf("SSHKeyRemove: %v", err)
			}
			if err := c.SSHKeyRename(ctx, v, "work-laptop"); err != nil {
				t.Fatalf("SSHKeyRename: %v", err)
			}
			want := []string{"ssh-key remove " + v, "ssh-key rename " + v + " work-laptop"}
			if got := rs.bodies(); strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Errorf("bodies = %q, want %q", got, want)
			}
		})
	}
}
