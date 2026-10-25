package exedev

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Token signature tests over real HTTP, checked with ssh-keygen. Each test
// sends requests through Client to a local server and verifies the bearer
// token with `ssh-keygen -Y verify`. Many keys and payloads per key type make
// sure that a defect which fails only some signatures cannot pass by chance.

const (
	sigKeysPerType    = 30
	sigMessagesPerKey = 4
)

var sigKeyTypes = map[string]func() (crypto.Signer, error){
	"ed25519": func() (crypto.Signer, error) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	},
	"ecdsa-p256": func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) },
	"ecdsa-p384": func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P384(), rand.Reader) },
	"ecdsa-p521": func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P521(), rand.Reader) },
}

type authServer struct {
	*httptest.Server
	mu    sync.Mutex
	auths []string
}

func newAuthServer(t *testing.T) *authServer {
	t.Helper()
	s := &authServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/exec" || string(body) != "whoami --json" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.auths = append(s.auths, r.Header.Get("Authorization"))
		s.mu.Unlock()
		w.Write([]byte(`{"email":"user@example.com","ssh_keys":[]}`))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *authServer) last() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.auths[len(s.auths)-1]
}

func requireSSHKeygen(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is required")
	}
}

func splitBearer(t *testing.T, auth string) (payload, sigBlob []byte) {
	t.Helper()
	token, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok {
		t.Fatalf("authorization header %q has no bearer token", auth)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "exe0" {
		t.Fatalf("token %q is not exe0.payload.signature", token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	sigBlob, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	return payload, sigBlob
}

// sshKeygenVerify returns nil if ssh-keygen accepts the signature for the
// public key and namespace, else ssh-keygen's error output.
func sshKeygenVerify(t *testing.T, pub ssh.PublicKey, payload, sigBlob []byte, namespace string) error {
	t.Helper()
	dir := t.TempDir()
	signers := filepath.Join(dir, "allowed_signers")
	line := "signer@test " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + "\n"
	if err := os.WriteFile(signers, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	sigFile := filepath.Join(dir, "token.sig")
	armored := pem.EncodeToMemory(&pem.Block{Type: "SSH SIGNATURE", Bytes: sigBlob})
	if err := os.WriteFile(sigFile, armored, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ssh-keygen", "-Y", "verify", "-f", signers, "-I", "signer@test", "-n", namespace, "-s", sigFile)
	cmd.Stdin = strings.NewReader(string(payload))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func generateKeyPEM(t *testing.T, keyType string) ([]byte, ssh.PublicKey) {
	t.Helper()
	priv, err := sigKeyTypes[keyType]()
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block), pub
}

func randomPermissions(rng *mrand.Rand) TokenPermissions {
	words := []string{"ls", "whoami", "new", "rm", "share", "ssh-key", "restart"}
	var p TokenPermissions
	if rng.Float64() < 0.7 {
		exp := 946684800 + rng.Int64N(4102444800-946684800)
		p.Exp = &exp
	}
	if rng.Float64() < 0.3 {
		nbf := 946684800 + rng.Int64N(4102444800-946684800)
		p.Nbf = &nbf
	}
	if rng.Float64() < 0.7 {
		rng.Shuffle(len(words), func(i, j int) { words[i], words[j] = words[j], words[i] })
		p.Cmds = words[:1+rng.IntN(len(words))]
	}
	if rng.Float64() < 0.4 {
		p.Ctx = map[string]any{"n": rng.IntN(1e9), "s": strings.Repeat("x", rng.IntN(300))}
	}
	return p
}

func TestTokenSignaturesOverHTTP(t *testing.T) {
	requireSSHKeygen(t)
	srv := newAuthServer(t)
	for keyType := range sigKeyTypes {
		t.Run(keyType, func(t *testing.T) {
			rng := mrand.New(mrand.NewPCG(uint64(len(keyType)), 1))
			var failures []string
			for k := 0; k < sigKeysPerType; k++ {
				keyPEM, pub := generateKeyPEM(t, keyType)
				for m := 0; m < sigMessagesPerKey; m++ {
					perms := randomPermissions(rng)
					c, err := NewClient(keyPEM, WithBaseURL(srv.URL), WithPermissions(perms))
					if err != nil {
						t.Fatal(err)
					}
					if _, err := c.Whoami(context.Background()); err != nil {
						t.Fatal(err)
					}
					payload, sigBlob := splitBearer(t, srv.last())
					if string(payload) != perms.toJSON() {
						t.Fatalf("payload %s, want %s", payload, perms.toJSON())
					}
					if err := sshKeygenVerify(t, pub, payload, sigBlob, "v0@exe.dev"); err != nil {
						failures = append(failures, fmt.Sprintf("key %d message %d: %v", k, m, err))
					}
				}
			}
			if len(failures) > 0 {
				t.Fatalf("%d of %d tokens failed:\n%s", len(failures), sigKeysPerType*sigMessagesPerKey, strings.Join(failures, "\n"))
			}
		})
	}
}

func TestVMTokenSignaturesVerifyOnlyForTheirNamespace(t *testing.T) {
	requireSSHKeygen(t)
	for keyType := range sigKeyTypes {
		t.Run(keyType, func(t *testing.T) {
			for i := 0; i < 10; i++ {
				keyPEM, pub := generateKeyPEM(t, keyType)
				c, err := NewClient(keyPEM)
				if err != nil {
					t.Fatal(err)
				}
				token, err := c.GenerateVMToken("my-vm", &TokenPermissions{Cmds: []string{"ls"}})
				if err != nil {
					t.Fatal(err)
				}
				payload, sigBlob := splitBearer(t, "Bearer "+token)
				if err := sshKeygenVerify(t, pub, payload, sigBlob, "v0@my-vm.exe.xyz"); err != nil {
					t.Fatalf("VM namespace: %v", err)
				}
				if err := sshKeygenVerify(t, pub, payload, sigBlob, "v0@exe.dev"); err == nil {
					t.Fatal("VM token verified for v0@exe.dev")
				}
			}
		})
	}
}

func TestSSHKeygenGeneratedKeySignatures(t *testing.T) {
	requireSSHKeygen(t)
	srv := newAuthServer(t)
	for _, bits := range []string{"256", "384", "521"} {
		t.Run("ecdsa-"+bits, func(t *testing.T) {
			for i := 0; i < 5; i++ {
				keyPath := filepath.Join(t.TempDir(), "id")
				if out, err := exec.Command("ssh-keygen", "-q", "-t", "ecdsa", "-b", bits, "-N", "", "-f", keyPath).CombinedOutput(); err != nil {
					t.Fatalf("ssh-keygen: %v: %s", err, out)
				}
				keyPEM, _ := os.ReadFile(keyPath)
				pubLine, _ := os.ReadFile(keyPath + ".pub")
				pub, _, _, _, err := ssh.ParseAuthorizedKey(pubLine)
				if err != nil {
					t.Fatal(err)
				}
				exp := int64(4102444799)
				c, err := NewClient(keyPEM, WithBaseURL(srv.URL), WithPermissions(TokenPermissions{Exp: &exp, Cmds: []string{"ls"}}))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := c.Whoami(context.Background()); err != nil {
					t.Fatal(err)
				}
				payload, sigBlob := splitBearer(t, srv.last())
				if err := sshKeygenVerify(t, pub, payload, sigBlob, "v0@exe.dev"); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestAgentTokenSignaturesOverHTTP(t *testing.T) {
	requireSSHKeygen(t)
	if _, err := exec.LookPath("ssh-agent"); err != nil {
		t.Skip("ssh-agent is required")
	}
	srv := newAuthServer(t)
	for keyType := range sigKeyTypes {
		t.Run(keyType, func(t *testing.T) {
			// A Unix socket path must stay short, so do not use t.TempDir.
			sockDir, err := os.MkdirTemp("", "exa")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(sockDir)
			sock := filepath.Join(sockDir, "s")
			agentCmd := exec.Command("ssh-agent", "-D", "-a", sock)
			if err := agentCmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { agentCmd.Process.Kill(); agentCmd.Wait() }()
			for i := 0; i < 100; i++ {
				if _, err := os.Stat(sock); err == nil {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}

			keyPEM, pub := generateKeyPEM(t, keyType)
			keyPath := filepath.Join(t.TempDir(), "id")
			if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
				t.Fatal(err)
			}
			add := exec.Command("ssh-add", "-q", keyPath)
			add.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock)
			if out, err := add.CombinedOutput(); err != nil {
				t.Fatalf("ssh-add: %v: %s", err, out)
			}

			rng := mrand.New(mrand.NewPCG(uint64(len(keyType)), 2))
			for i := 0; i < 10; i++ {
				c, err := NewClient(nil, WithAgentSock(sock), WithBaseURL(srv.URL), WithPermissions(randomPermissions(rng)))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := c.Whoami(context.Background()); err != nil {
					t.Fatal(err)
				}
				payload, sigBlob := splitBearer(t, srv.last())
				if err := sshKeygenVerify(t, pub, payload, sigBlob, "v0@exe.dev"); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
