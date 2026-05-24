package dotenv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	t.Setenv("EXISTING_KEY", "from-env")

	path := filepath.Join(t.TempDir(), ".env")
	content := strings.Join([]string{
		"# comment",
		"PLAIN=value",
		"QUOTED=\"hello world\"",
		"SINGLE='literal value'",
		"export EXPORTED=yes",
		"EXISTING_KEY=from-file",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Load(path); err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"PLAIN":        "value",
		"QUOTED":       "hello world",
		"SINGLE":       "literal value",
		"EXPORTED":     "yes",
		"EXISTING_KEY": "from-env",
	}
	for key, want := range cases {
		if got := os.Getenv(key); got != want {
			t.Fatalf("%s mismatch: want %q, got %q", key, want, got)
		}
	}
}
