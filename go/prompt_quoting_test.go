package exedev

import (
	"context"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Prompt quoting regression tests, over real HTTP
// ---------------------------------------------------------------------------

// shWords splits body into POSIX shell words with a real shell.
func shWords(t *testing.T, body string) []string {
	t.Helper()
	out, err := exec.Command("sh", "-c", `eval "set -- $1"; printf '%s\0' "$@"`, "sh", body).Output()
	if err != nil {
		t.Fatalf("sh could not split %q: %v", body, err)
	}
	words := strings.Split(string(out), "\x00")
	return words[:len(words)-1]
}

var quotingPrompts = []struct{ name, prompt string }{
	{"plain", "create a hello world app"},
	{"double quotes", `say "hi"; echo pwned`},
	{"closing quote", `"; echo pwned; "`},
	{"single quote", "it's fine"},
	{"backslash", `a\b`},
	{"trailing backslash", `ends with \`},
	{"backslash before quote", `\"; echo pwned; \"`},
	{"command substitution", "$(echo pwned)"},
	{"backticks", "`echo pwned`"},
	{"variable", "$HOME and ${PATH}"},
	{"arithmetic", "$((1+1))"},
	{"semicolon and pipe", "a; b | c && d"},
	{"newline", "line one\nline two"},
	{"glob", "*.go ?"},
	{"history", "!! and !$"},
	{"unicode", "café — “quoted”"},
	{"empty", ""},
}

func TestShelleyPromptIsOneUnchangedWord(t *testing.T) {
	for _, tc := range quotingPrompts {
		t.Run(tc.name, func(t *testing.T) {
			rs := newRecordingServer(t)
			if err := rs.client(t).ShelleyPrompt(context.Background(), "dev", tc.prompt); err != nil {
				t.Fatalf("ShelleyPrompt: %v", err)
			}
			bodies := rs.bodies()
			if len(bodies) != 1 {
				t.Fatalf("server received %d requests, want 1", len(bodies))
			}
			want := []string{"shelley", "prompt", "dev", tc.prompt}
			if got := shWords(t, bodies[0]); !reflect.DeepEqual(got, want) {
				t.Errorf("body %q splits to %q, want %q", bodies[0], got, want)
			}
		})
	}
}

func TestNewPromptIsOneUnchangedWord(t *testing.T) {
	for _, tc := range quotingPrompts {
		t.Run(tc.name, func(t *testing.T) {
			rs := newRecordingServer(t)
			name, prompt := "dev", tc.prompt
			if _, err := rs.client(t).New(context.Background(), NewOpts{Name: &name, Prompt: &prompt}); err != nil {
				t.Fatalf("New: %v", err)
			}
			bodies := rs.bodies()
			if len(bodies) != 1 {
				t.Fatalf("server received %d requests, want 1", len(bodies))
			}
			want := []string{"new", "--name=dev", "--prompt=" + tc.prompt, "--json"}
			if got := shWords(t, bodies[0]); !reflect.DeepEqual(got, want) {
				t.Errorf("body %q splits to %q, want %q", bodies[0], got, want)
			}
		})
	}
}

func TestPromptWireFormat(t *testing.T) {
	ctx := context.Background()
	for prompt, quoted := range map[string]string{
		"create a hello world app": `"create a hello world app"`,
		`say "hi"; echo pwned`:     `"say \"hi\"; echo pwned"`,
		`a\b`:                      `"a\\b"`,
		"$(id) `id`":               "\"\\$(id) \\`id\\`\"",
	} {
		rs := newRecordingServer(t)
		c := rs.client(t)
		if err := c.ShelleyPrompt(ctx, "dev", prompt); err != nil {
			t.Fatalf("ShelleyPrompt: %v", err)
		}
		p := prompt
		if _, err := c.New(ctx, NewOpts{Prompt: &p}); err != nil {
			t.Fatalf("New: %v", err)
		}
		want := []string{"shelley prompt dev " + quoted, "new --prompt=" + quoted + " --json"}
		if got := rs.bodies(); !reflect.DeepEqual(got, want) {
			t.Errorf("bodies = %q, want %q", got, want)
		}
	}
}
