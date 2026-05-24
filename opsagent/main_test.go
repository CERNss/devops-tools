package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
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

func TestValidateDeployAllowsTemplateWithoutNPM(t *testing.T) {
	oldRoot := appRoot
	appRoot = t.TempDir()
	t.Cleanup(func() {
		appRoot = oldRoot
	})

	req := DeployRequest{
		AppName:         "demo-app",
		Directory:       "team/demo-app",
		ComposeTemplate: "services:\n  app:\n    image: {{IMAGE}}\n",
		Env: map[string]string{
			"IMAGE": "nginx:latest",
		},
		SkipNPM: true,
	}

	if err := validateDeploy(req); err != nil {
		t.Fatalf("template deploy failed validation: %v", err)
	}
}

func TestResolveAppDirRejectsTraversal(t *testing.T) {
	oldRoot := appRoot
	appRoot = t.TempDir()
	t.Cleanup(func() {
		appRoot = oldRoot
	})

	if _, err := resolveAppDir("demo-app", "../outside"); err == nil {
		t.Fatal("expected traversal directory to be rejected")
	}

	got, err := resolveAppDir("demo-app", "team/demo-app")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(appRoot, "team", "demo-app")
	if got != want {
		t.Fatalf("dir mismatch: want %q, got %q", want, got)
	}
}

func TestSafeRelativeFileRejectsTraversal(t *testing.T) {
	if _, err := safeRelativeFile("../compose.yml", "docker-compose.yml"); err == nil {
		t.Fatal("expected traversal file to be rejected")
	}
	if got, err := safeRelativeFile("deploy/docker-compose.yml", "docker-compose.yml"); err != nil || got != "deploy/docker-compose.yml" {
		t.Fatalf("safe file mismatch: got %q err %v", got, err)
	}
}

func TestRenderTemplateReplacesSupportedPlaceholders(t *testing.T) {
	got, err := renderTemplate("image={{IMAGE}}\nname=${APP_NAME}\n", map[string]string{
		"APP_NAME": "demo",
		"IMAGE":    "nginx:latest",
	})
	if err != nil {
		t.Fatal(err)
	}

	want := "image=nginx:latest\nname=demo\n"
	if got != want {
		t.Fatalf("template mismatch: want %q, got %q", want, got)
	}
}

func TestRenderEnvSortsAndQuotesValues(t *testing.T) {
	got, err := renderEnv("", map[string]string{
		"Z_VALUE": "plain",
		"A_VALUE": "hello world",
		"EMPTY":   "",
	})
	if err != nil {
		t.Fatal(err)
	}

	want := "A_VALUE=\"hello world\"\nEMPTY=\"\"\nZ_VALUE=plain\n"
	if got != want {
		t.Fatalf("env mismatch:\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func TestComposeArgsAllowsOnlyKnownActionsAndSafeServices(t *testing.T) {
	args, err := composeArgs(ComposeRunRequest{
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

	if _, err := composeArgs(ComposeRunRequest{Action: "exec"}); err == nil {
		t.Fatal("expected unsupported action to be rejected")
	}
	if _, err := composeArgs(ComposeRunRequest{Action: "restart", Services: []string{"api;rm"}}); err == nil {
		t.Fatal("expected unsafe service name to be rejected")
	}
}

func TestNPMProxyPayloadDefaultsAndValidation(t *testing.T) {
	disabled := false
	req := NPMProxyHostRequest{
		DomainNames:      []string{"demo.example.com"},
		ForwardHost:      "127.0.0.1",
		ForwardPort:      18080,
		BlockExploits:    &disabled,
		WebsocketUpgrade: &disabled,
		Enabled:          &disabled,
	}
	if err := validateNPMProxyHost(req); err != nil {
		t.Fatal(err)
	}

	payload := npmProxyPayload(req)
	if payload["block_exploits"] != false {
		t.Fatalf("expected block_exploits false, got %#v", payload["block_exploits"])
	}
	if payload["allow_websocket_upgrade"] != false {
		t.Fatalf("expected websocket false, got %#v", payload["allow_websocket_upgrade"])
	}
	if payload["enabled"] != false {
		t.Fatalf("expected enabled false, got %#v", payload["enabled"])
	}
}

func TestWebhookDeployRendersFiles(t *testing.T) {
	oldRoot := appRoot
	oldSecret := secret
	appRoot = t.TempDir()
	secret = "test-secret"
	t.Cleanup(func() {
		appRoot = oldRoot
		secret = oldSecret
	})

	body := `{"action":"deploy","data":{"app_name":"demo-app","compose_template":"services:\n  app:\n    image: {{IMAGE}}\n","env_file":"runtime.env","env":{"IMAGE":"nginx:latest","APP_ENV":"production"},"skip_docker":true,"skip_npm":true}}`
	ts := strconvFormat(time.Now().Unix())
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewBufferString(body))
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Signature", sign(ts, body, secret))

	rr := httptest.NewRecorder()
	handleWebhook(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	compose, err := os.ReadFile(filepath.Join(appRoot, "demo-app", "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(compose), "image: nginx:latest") {
		t.Fatalf("compose was not rendered: %s", string(compose))
	}

	envFile, err := os.ReadFile(filepath.Join(appRoot, "demo-app", "runtime.env"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(envFile), "APP_ENV=production") {
		t.Fatalf("env file was not rendered: %s", string(envFile))
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
