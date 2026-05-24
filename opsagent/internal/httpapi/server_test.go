package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"opsagent/internal/api"
	"opsagent/internal/appsvc"
	"opsagent/internal/config"
)

func TestWebhookDeployRendersFiles(t *testing.T) {
	appRoot := t.TempDir()
	secret := "test-secret"
	apps := appsvc.New(
		config.Config{
			AppRoot:          appRoot,
			ProxyForwardMode: "host-port",
			ProxyForwardHost: "127.0.0.1",
		},
		fakeDocker{},
		fakeNPM{},
	)
	server := New(secret, apps)

	body := `{"action":"deploy","data":{"app_name":"demo-app","compose_template":"services:\n  app:\n    image: {{IMAGE}}\n","env_file":"runtime.env","env":{"IMAGE":"nginx:latest","APP_ENV":"production"},"skip_docker":true,"skip_npm":true}}`
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewBufferString(body))
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Signature", sign(ts, body, secret))

	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, req)

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

type fakeDocker struct{}

func (fakeDocker) Compose(string, api.ComposeRunRequest) error {
	return nil
}

func (fakeDocker) Pull(string) error {
	return nil
}

func (fakeDocker) Up(string) error {
	return nil
}

func (fakeDocker) InspectHealth(container string) (api.ContainerHealth, error) {
	return api.ContainerHealth{Container: container, Status: "running", Health: "healthy"}, nil
}

type fakeNPM struct{}

func (fakeNPM) UpsertDeployProxyHost(api.DeployRequest) error {
	return nil
}

func (fakeNPM) ListProxyHosts() ([]api.NPMProxyHost, error) {
	return nil, nil
}

func (fakeNPM) UpsertProxyHost(api.NPMProxyHostRequest) (any, error) {
	return map[string]any{"id": 1}, nil
}

func (fakeNPM) DeleteProxyHost(int) error {
	return nil
}
