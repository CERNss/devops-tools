package docker

import (
	"strings"
	"testing"

	"opsagent/internal/api"
)

func TestComposeArgsAllowsOnlyKnownActionsAndSafeServices(t *testing.T) {
	args, err := ComposeArgs(api.ComposeRunRequest{
		Action:   "up",
		Services: []string{"api"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "compose up -d api"
	if strings.Join(args, " ") != want {
		t.Fatalf("args mismatch: want %q, got %q", want, strings.Join(args, " "))
	}

	if _, err := ComposeArgs(api.ComposeRunRequest{Action: "exec"}); err == nil {
		t.Fatal("expected unsupported action to be rejected")
	}
	if _, err := ComposeArgs(api.ComposeRunRequest{Action: "restart", Services: []string{"api;rm"}}); err == nil {
		t.Fatal("expected unsafe service name to be rejected")
	}
}
