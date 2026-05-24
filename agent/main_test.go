package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestValidateDeploy(t *testing.T) {
	valid := DeployRequest{
		AppName:       "demo-app",
		Domain:        "demo.example.com",
		Image:         "nginx:latest",
		HostPort:      18080,
		ContainerPort: 80,
		Env: map[string]string{
			"APP_ENV": "production",
		},
	}

	if err := validateDeploy(valid); err != nil {
		t.Fatalf("valid deploy request failed validation: %v", err)
	}

	cases := map[string]DeployRequest{
		"bad app name": {
			AppName:       "../demo",
			Domain:        valid.Domain,
			Image:         valid.Image,
			HostPort:      valid.HostPort,
			ContainerPort: valid.ContainerPort,
		},
		"bad domain": {
			AppName:       valid.AppName,
			Domain:        "demo..example.com",
			Image:         valid.Image,
			HostPort:      valid.HostPort,
			ContainerPort: valid.ContainerPort,
		},
		"bad image": {
			AppName:       valid.AppName,
			Domain:        valid.Domain,
			Image:         "nginx:latest;touch /tmp/pwned",
			HostPort:      valid.HostPort,
			ContainerPort: valid.ContainerPort,
		},
		"bad host port": {
			AppName:       valid.AppName,
			Domain:        valid.Domain,
			Image:         valid.Image,
			HostPort:      80,
			ContainerPort: valid.ContainerPort,
		},
		"bad env key": {
			AppName:       valid.AppName,
			Domain:        valid.Domain,
			Image:         valid.Image,
			HostPort:      valid.HostPort,
			ContainerPort: valid.ContainerPort,
			Env: map[string]string{
				"app-env": "production",
			},
		},
	}

	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if err := validateDeploy(req); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestReadAndVerify(t *testing.T) {
	oldSecret := secret
	secret = "test-secret"
	t.Cleanup(func() {
		secret = oldSecret
	})

	body := `{"app_name":"demo-app"}`
	ts := strconvFormat(time.Now().Unix())
	req, err := http.NewRequest(http.MethodPost, "/deploy", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Signature", sign(ts, body, secret))

	got, err := readAndVerify(req)
	if err != nil {
		t.Fatalf("readAndVerify failed: %v", err)
	}
	if string(got) != body {
		t.Fatalf("body mismatch: got %q", string(got))
	}
}

func TestReadAndVerifyRejectsBadSignature(t *testing.T) {
	oldSecret := secret
	secret = "test-secret"
	t.Cleanup(func() {
		secret = oldSecret
	})

	body := `{"app_name":"demo-app"}`
	ts := strconvFormat(time.Now().Unix())
	req, err := http.NewRequest(http.MethodPost, "/deploy", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Signature", "bad")

	if _, err := readAndVerify(req); err == nil {
		t.Fatal("expected bad signature error")
	}
}

func TestRenderComposeSortsAndQuotesEnvironment(t *testing.T) {
	req := DeployRequest{
		AppName:       "demo-app",
		Image:         "nginx:latest",
		HostPort:      18080,
		ContainerPort: 80,
		Env: map[string]string{
			"Z_VALUE": "last",
			"A_VALUE": `needs "quotes"`,
		},
	}

	compose, err := renderCompose(req)
	if err != nil {
		t.Fatal(err)
	}

	want := `services:
  app:
    image: "nginx:latest"
    container_name: "demo-app"
    restart: unless-stopped
    ports:
      - "127.0.0.1:18080:80"
    environment:
      A_VALUE: "needs \"quotes\""
      Z_VALUE: "last"
`
	if compose != want {
		t.Fatalf("compose mismatch:\nwant:\n%s\ngot:\n%s", want, compose)
	}
}

func TestLoadDotEnv(t *testing.T) {
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

	if err := loadDotEnv(path); err != nil {
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

func sign(ts, body, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(ts + "." + body))
	return hex.EncodeToString(mac.Sum(nil))
}

func strconvFormat(v int64) string {
	return strconv.FormatInt(v, 10)
}
