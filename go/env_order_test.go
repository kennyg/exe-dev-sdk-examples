package exedev

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// --env flag order regression tests, over real HTTP
// ---------------------------------------------------------------------------

// TestNewEnvFlagsAreSorted checks that New writes --env flags sorted by key.
// Go map order is random, so a map-order loop fails here almost every run:
// 20 calls with 12 keys each leave no real chance of a sorted result.
func TestNewEnvFlagsAreSorted(t *testing.T) {
	env := map[string]string{}
	var want []string
	for i := range 12 {
		k := fmt.Sprintf("KEY_%02d", i)
		env[k] = fmt.Sprint(i)
		want = append(want, fmt.Sprintf("--env=%s=%d", k, i))
	}
	wantCmd := "new --name=dev " + strings.Join(want, " ") + " --json"

	rs := newRecordingServer(t)
	c := rs.client(t)
	name := "dev"
	for range 20 {
		if _, err := c.New(context.Background(), NewOpts{Name: &name, Env: env}); err != nil {
			t.Fatalf("New: %v", err)
		}
	}
	for i, got := range rs.bodies() {
		if got != wantCmd {
			t.Fatalf("call %d: command = %q, want %q", i, got, wantCmd)
		}
	}
}

// TestNewEnvFlagsMatchTheJourney checks the exact command of the verifier
// journey vm_lifecycle/create-vm-with-env-vars.
func TestNewEnvFlagsMatchTheJourney(t *testing.T) {
	rs := newRecordingServer(t)
	c := rs.client(t)
	name := "api-server"
	env := map[string]string{"PORT": "3000", "NODE_ENV": "production"}
	for range 20 {
		if _, err := c.New(context.Background(), NewOpts{Name: &name, Env: env}); err != nil {
			t.Fatalf("New: %v", err)
		}
	}
	want := "new --name=api-server --env=NODE_ENV=production --env=PORT=3000 --json"
	for i, got := range rs.bodies() {
		if got != want {
			t.Fatalf("call %d: command = %q, want %q", i, got, want)
		}
	}
}
