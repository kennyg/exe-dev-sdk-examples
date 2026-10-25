package exedev

import (
	"context"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// Regression tests: a prompt reaches the server as exactly one shell word.
// The client talks to a real HTTP server (httptest). Each test runs the
// request body in /bin/sh, with shelley and new defined as functions that
// print their arguments, and checks that sh gives back the exact prompt.

var quotingPrompts = []string{
	`say "hi"; echo pwned`,
	"it's here",
	`back\slash`,
	`trailing backslash\`,
	`escaped \" quote`,
	"$(echo pwned)",
	"`echo pwned`",
	"$HOME ${HOME} $1 $$",
	"line one\nline two",
	"backslash then newline\\\nnext",
	"crlf\r\nline",
	"a; b && c || d | e > f < g & h",
	"tab\there",
	"!history !! !-1",
	"*glob? [abc] ~user {a,b}",
	"非ASCII テキスト — café, emoji 🚀",
	"",
	" leading and trailing spaces ",
	"\"'\\$`;\n",
}

const newVMBody = `{"vm_name":"dev","ssh_command":"ssh dev.exe.xyz","ssh_dest":"dev.exe.xyz","ssh_port":22,"https_url":"https://dev.exe.xyz","proxy_port":8000,"shelley_url":"https://dev.shelley.exe.xyz","vscode_url":"vscode://vscode-remote/ssh-remote+dev.exe.xyz/home/exedev?windowId=_blank","xterm_url":"https://dev.xterm.exe.xyz"}`

// shWords runs body in /bin/sh and returns the words the command received.
func shWords(t *testing.T, body string) []string {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("needs /bin/sh")
	}
	script := "shelley() { printf '%s\\0' shelley \"$@\"; }\n" +
		"new() { printf '%s\\0' new \"$@\"; }\n" + body
	out, err := exec.Command("/bin/sh", "-c", script).Output()
	if err != nil {
		t.Fatalf("sh failed on body %q: %v", body, err)
	}
	words := strings.Split(string(out), "\x00")
	return words[:len(words)-1]
}

func TestShelleyPromptQuoting(t *testing.T) {
	for _, prompt := range quotingPrompts {
		t.Run(prompt, func(t *testing.T) {
			m := mockServer(200, "")
			defer m.server.Close()
			c := newTestClient(t, m)
			if err := c.ShelleyPrompt(context.Background(), "dev", prompt); err != nil {
				t.Fatalf("ShelleyPrompt() error: %v", err)
			}
			got := shWords(t, m.body())
			want := []string{"shelley", "prompt", "dev", prompt}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("body %q gives words %q, want %q", m.body(), got, want)
			}
		})
	}
}

func TestNewPromptQuoting(t *testing.T) {
	for _, prompt := range quotingPrompts {
		t.Run(prompt, func(t *testing.T) {
			m := mockServer(200, newVMBody)
			defer m.server.Close()
			c := newTestClient(t, m)
			if _, err := c.New(context.Background(), NewOpts{Name: strPtr("dev"), Prompt: strPtr(prompt)}); err != nil {
				t.Fatalf("New() error: %v", err)
			}
			got := shWords(t, m.body())
			want := []string{"new", "--name=dev", "--prompt=" + prompt, "--json"}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("body %q gives words %q, want %q", m.body(), got, want)
			}
		})
	}
}

func TestBreakoutPromptIsEscaped(t *testing.T) {
	m := mockServer(200, "")
	defer m.server.Close()
	c := newTestClient(t, m)
	if err := c.ShelleyPrompt(context.Background(), "dev", "say \"hi\"; echo $(id) `id` \\"); err != nil {
		t.Fatalf("ShelleyPrompt() error: %v", err)
	}
	assertCommand(t, m.body, `shelley prompt dev "say "'"'"hi"'"'"; echo "'$'"(id) "'`+"`"+`'"id"'`+"`"+`'" "'\'""`)
}
