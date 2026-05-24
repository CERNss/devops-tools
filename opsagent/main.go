package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const signatureWindow = 5 * time.Minute

var (
	listenAddr = env("LISTEN_ADDR", ":9090")
	secret     = env("AGENT_SECRET", "change-me")
	appRoot    = env("APP_ROOT", "/opt/apps")

	npmBaseURL  = strings.TrimRight(env("NPM_BASE_URL", "http://127.0.0.1:81"), "/")
	npmEmail    = env("NPM_EMAIL", "admin@example.com")
	npmPassword = env("NPM_PASSWORD", "password")

	proxyForwardMode = env("PROXY_FORWARD_MODE", "host-port")
	proxyForwardHost = env("PROXY_FORWARD_HOST", "127.0.0.1")

	nameRe   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}$`)
	domainRe = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$`)
	imageRe  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9./:@_-]{0,255}$`)
	envKeyRe = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
	fileRe   = regexp.MustCompile(`^[a-zA-Z0-9._/-]{1,160}$`)

	httpClient = &http.Client{Timeout: 20 * time.Second}

	loadDotEnvOnce sync.Once
	loadDotEnvErr  error
)

type DeployRequest struct {
	AppName   string `json:"app_name"`
	Directory string `json:"directory,omitempty"`
	Domain    string `json:"domain,omitempty"`
	Image     string `json:"image"`

	HostPort      int `json:"host_port"`
	ContainerPort int `json:"container_port"`

	Env map[string]string `json:"env,omitempty"`

	ComposeFile     string `json:"compose_file,omitempty"`
	EnvFile         string `json:"env_file,omitempty"`
	ComposeTemplate string `json:"compose_template,omitempty"`
	EnvTemplate     string `json:"env_template,omitempty"`

	SkipDocker bool `json:"skip_docker,omitempty"`
	SkipNPM    bool `json:"skip_npm,omitempty"`
}

type APIResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
	AppName string `json:"app_name,omitempty"`
	Domain  string `json:"domain,omitempty"`
	Data    any    `json:"data,omitempty"`
}

type WebhookRequest struct {
	Action string          `json:"action"`
	Data   json.RawMessage `json:"data"`
}

type FileRenderRequest struct {
	AppName         string            `json:"app_name"`
	Directory       string            `json:"directory,omitempty"`
	ComposeFile     string            `json:"compose_file,omitempty"`
	EnvFile         string            `json:"env_file,omitempty"`
	ComposeTemplate string            `json:"compose_template,omitempty"`
	EnvTemplate     string            `json:"env_template,omitempty"`
	Env             map[string]string `json:"env,omitempty"`
}

type ComposeRunRequest struct {
	AppName   string   `json:"app_name"`
	Directory string   `json:"directory,omitempty"`
	Action    string   `json:"action"`
	Services  []string `json:"services,omitempty"`
}

type ContainerHealthRequest struct {
	Container string `json:"container"`
}

type ContainerHealth struct {
	Container string `json:"container"`
	Status    string `json:"status"`
	Health    string `json:"health,omitempty"`
	ExitCode  string `json:"exit_code,omitempty"`
}

type NPMProxyHostRequest struct {
	ID               int      `json:"id,omitempty"`
	DomainNames      []string `json:"domain_names,omitempty"`
	ForwardHost      string   `json:"forward_host,omitempty"`
	ForwardPort      int      `json:"forward_port,omitempty"`
	ForwardScheme    string   `json:"forward_scheme,omitempty"`
	CertificateID    int      `json:"certificate_id,omitempty"`
	SSLEnabled       bool     `json:"ssl_enabled,omitempty"`
	SSLForced        bool     `json:"ssl_forced,omitempty"`
	HTTP2Support     bool     `json:"http2_support,omitempty"`
	BlockExploits    *bool    `json:"block_exploits,omitempty"`
	WebsocketUpgrade *bool    `json:"websocket_upgrade,omitempty"`
	Enabled          *bool    `json:"enabled,omitempty"`
}

type npmTokenResp struct {
	Token string `json:"token"`
}

type npmProxyHost struct {
	ID          int      `json:"id"`
	DomainNames []string `json:"domain_names"`
}

func main() {
	if loadDotEnvErr != nil {
		log.Fatal(loadDotEnvErr)
	}
	if secret == "change-me" {
		log.Println("warning: AGENT_SECRET is using the default value")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, APIResponse{OK: true, Message: "ok"})
	})
	mux.HandleFunc("POST /deploy", handleDeploy)
	mux.HandleFunc("POST /webhook", handleWebhook)
	mux.HandleFunc("POST /api/deploy", handleDeploy)
	mux.HandleFunc("POST /api/compose/render", handleRenderFiles)
	mux.HandleFunc("POST /api/compose/run", handleComposeRun)
	mux.HandleFunc("POST /api/apps/{app}/restart", handleRestart)
	mux.HandleFunc("POST /api/containers/health", handleContainerHealth)
	mux.HandleFunc("GET /api/containers/{container}/health", handleContainerHealth)
	mux.HandleFunc("GET /api/npm/proxy-hosts", handleNPMProxyHosts)
	mux.HandleFunc("POST /api/npm/proxy-hosts", handleNPMProxyHosts)
	mux.HandleFunc("DELETE /api/npm/proxy-hosts", handleNPMProxyHosts)

	log.Println("opsagent listening on", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}

func handleDeploy(w http.ResponseWriter, r *http.Request) {
	var req DeployRequest
	if !readSignedJSON(w, r, &req) {
		return
	}

	resp, code := deployApp(req)
	writeJSON(w, code, resp)
}

func handleWebhook(w http.ResponseWriter, r *http.Request) {
	var req WebhookRequest
	if !readSignedJSON(w, r, &req) {
		return
	}

	switch req.Action {
	case "deploy":
		var deploy DeployRequest
		if !decodeRaw(w, req.Data, &deploy) {
			return
		}
		resp, code := deployApp(deploy)
		writeJSON(w, code, resp)
	case "render":
		var render FileRenderRequest
		if !decodeRaw(w, req.Data, &render) {
			return
		}
		resp, code := renderFiles(render)
		writeJSON(w, code, resp)
	case "compose":
		var compose ComposeRunRequest
		if !decodeRaw(w, req.Data, &compose) {
			return
		}
		resp, code := runComposeAction(compose)
		writeJSON(w, code, resp)
	case "restart":
		var compose ComposeRunRequest
		if !decodeRaw(w, req.Data, &compose) {
			return
		}
		compose.Action = "restart"
		resp, code := runComposeAction(compose)
		writeJSON(w, code, resp)
	case "container_health":
		var health ContainerHealthRequest
		if !decodeRaw(w, req.Data, &health) {
			return
		}
		resp, code := inspectContainerHealth(health.Container)
		writeJSON(w, code, resp)
	case "npm_proxy_host":
		var proxy NPMProxyHostRequest
		if !decodeRaw(w, req.Data, &proxy) {
			return
		}
		resp, code := upsertNPMProxyHost(proxy)
		writeJSON(w, code, resp)
	default:
		writeJSON(w, http.StatusBadRequest, APIResponse{OK: false, Message: "unsupported action"})
	}
}

func handleRenderFiles(w http.ResponseWriter, r *http.Request) {
	var req FileRenderRequest
	if !readSignedJSON(w, r, &req) {
		return
	}

	resp, code := renderFiles(req)
	writeJSON(w, code, resp)
}

func handleComposeRun(w http.ResponseWriter, r *http.Request) {
	var req ComposeRunRequest
	if !readSignedJSON(w, r, &req) {
		return
	}

	resp, code := runComposeAction(req)
	writeJSON(w, code, resp)
}

func handleRestart(w http.ResponseWriter, r *http.Request) {
	var req ComposeRunRequest
	if !readSignedJSON(w, r, &req) {
		return
	}
	req.AppName = r.PathValue("app")
	req.Action = "restart"

	resp, code := runComposeAction(req)
	writeJSON(w, code, resp)
}

func handleContainerHealth(w http.ResponseWriter, r *http.Request) {
	container := r.PathValue("container")
	if container == "" {
		var req ContainerHealthRequest
		if !readSignedJSON(w, r, &req) {
			return
		}
		container = req.Container
	} else if err := verifyRequest(r); err != nil {
		writeJSON(w, http.StatusUnauthorized, APIResponse{OK: false, Message: err.Error()})
		return
	}

	resp, code := inspectContainerHealth(container)
	writeJSON(w, code, resp)
}

func handleNPMProxyHosts(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if err := verifyRequest(r); err != nil {
			writeJSON(w, http.StatusUnauthorized, APIResponse{OK: false, Message: err.Error()})
			return
		}
		resp, code := listNPMProxyHosts()
		writeJSON(w, code, resp)
		return
	}

	var req NPMProxyHostRequest
	if !readSignedJSON(w, r, &req) {
		return
	}

	switch r.Method {
	case http.MethodPost:
		resp, code := upsertNPMProxyHost(req)
		writeJSON(w, code, resp)
	case http.MethodDelete:
		resp, code := deleteNPMProxyHost(req.ID)
		writeJSON(w, code, resp)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, APIResponse{OK: false, Message: "method not allowed"})
	}
}

func deployApp(req DeployRequest) (APIResponse, int) {
	if err := validateDeploy(req); err != nil {
		return APIResponse{OK: false, Message: err.Error()}, http.StatusBadRequest
	}

	appDir, err := resolveAppDir(req.AppName, req.Directory)
	if err != nil {
		return APIResponse{OK: false, Message: err.Error()}, http.StatusBadRequest
	}

	if err := os.MkdirAll(appDir, 0o755); err != nil {
		return APIResponse{OK: false, Message: err.Error()}, http.StatusInternalServerError
	}

	if err := writeDeployFiles(appDir, req); err != nil {
		return APIResponse{OK: false, Message: err.Error()}, http.StatusInternalServerError
	}

	if !req.SkipDocker {
		if err := run(appDir, "docker", "compose", "pull"); err != nil {
			return APIResponse{OK: false, Message: err.Error()}, http.StatusInternalServerError
		}

		if err := run(appDir, "docker", "compose", "up", "-d"); err != nil {
			return APIResponse{OK: false, Message: err.Error()}, http.StatusInternalServerError
		}
	}

	if !req.SkipNPM {
		if err := upsertProxyHost(req); err != nil {
			return APIResponse{
				OK:      false,
				Message: "docker ok, npm failed: " + err.Error(),
			}, http.StatusInternalServerError
		}
	}

	return APIResponse{
		OK:      true,
		Message: "deployed",
		AppName: req.AppName,
		Domain:  req.Domain,
		Data: map[string]string{
			"directory": appDir,
		},
	}, http.StatusOK
}

func readSignedJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	body, err := readAndVerify(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, APIResponse{OK: false, Message: err.Error()})
		return false
	}
	if err := json.Unmarshal(body, out); err != nil {
		writeJSON(w, http.StatusBadRequest, APIResponse{OK: false, Message: "invalid json"})
		return false
	}
	return true
}

func verifyRequest(r *http.Request) error {
	body, err := readAndVerify(r)
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(body))) > 0 {
		return errors.New("signed GET requests must use an empty body")
	}
	return nil
}

func decodeRaw(w http.ResponseWriter, raw json.RawMessage, out any) bool {
	if len(raw) == 0 {
		writeJSON(w, http.StatusBadRequest, APIResponse{OK: false, Message: "missing data"})
		return false
	}
	if err := json.Unmarshal(raw, out); err != nil {
		writeJSON(w, http.StatusBadRequest, APIResponse{OK: false, Message: "invalid data"})
		return false
	}
	return true
}

func readAndVerify(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	ts := r.Header.Get("X-Timestamp")
	sig := strings.TrimPrefix(r.Header.Get("X-Signature"), "sha256=")
	if ts == "" || sig == "" {
		return nil, errors.New("missing signature")
	}

	timestamp, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return nil, errors.New("invalid timestamp")
	}

	now := time.Now()
	signedAt := time.Unix(timestamp, 0)
	if signedAt.Before(now.Add(-signatureWindow)) || signedAt.After(now.Add(signatureWindow)) {
		return nil, errors.New("timestamp expired")
	}

	payload := ts + "." + string(body)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(expected), []byte(sig)) {
		return nil, errors.New("bad signature")
	}

	return body, nil
}

func validateDeploy(req DeployRequest) error {
	if !nameRe.MatchString(req.AppName) {
		return errors.New("invalid app_name")
	}
	if _, err := resolveAppDir(req.AppName, req.Directory); err != nil {
		return err
	}
	if req.Domain == "" && !req.SkipNPM {
		return errors.New("domain is required unless skip_npm is true")
	}
	if req.Domain != "" && (!domainRe.MatchString(req.Domain) || strings.Contains(req.Domain, "..")) {
		return errors.New("invalid domain")
	}
	if req.ComposeTemplate == "" && !imageRe.MatchString(req.Image) {
		return errors.New("invalid image")
	}
	if req.Image != "" && !imageRe.MatchString(req.Image) {
		return errors.New("invalid image")
	}
	if req.ComposeTemplate == "" || req.HostPort != 0 {
		if req.HostPort < 10000 || req.HostPort > 60000 {
			return errors.New("host_port must be 10000-60000")
		}
	}
	if req.ComposeTemplate == "" || req.ContainerPort != 0 {
		if req.ContainerPort < 1 || req.ContainerPort > 65535 {
			return errors.New("invalid container_port")
		}
	}
	if len(req.Env) > 128 {
		return errors.New("too many env entries")
	}
	for key, value := range req.Env {
		if !envKeyRe.MatchString(key) {
			return fmt.Errorf("invalid env key: %s", key)
		}
		if strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("invalid env value for key: %s", key)
		}
	}
	if proxyForwardMode != "host-port" && proxyForwardMode != "container" {
		return errors.New("PROXY_FORWARD_MODE must be host-port or container")
	}
	if _, err := safeRelativeFile(req.ComposeFile, "docker-compose.yml"); err != nil {
		return fmt.Errorf("invalid compose_file: %w", err)
	}
	if _, err := safeRelativeFile(req.EnvFile, ".env"); err != nil {
		return fmt.Errorf("invalid env_file: %w", err)
	}

	return nil
}

func writeCompose(appDir string, req DeployRequest) error {
	compose, err := renderCompose(req)
	if err != nil {
		return err
	}

	composeFile, err := safeRelativeFile(req.ComposeFile, "docker-compose.yml")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(appDir, composeFile), []byte(compose), 0o644)
}

func writeDeployFiles(appDir string, req DeployRequest) error {
	if err := writeCompose(appDir, req); err != nil {
		return err
	}

	if req.EnvTemplate == "" && len(req.Env) == 0 {
		return nil
	}

	envFile, err := safeRelativeFile(req.EnvFile, ".env")
	if err != nil {
		return err
	}

	envContent, err := renderEnv(req.EnvTemplate, req.Env)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(appDir, envFile), []byte(envContent), 0o600)
}

func renderCompose(req DeployRequest) (string, error) {
	if req.ComposeTemplate != "" {
		return renderTemplate(req.ComposeTemplate, req.Env)
	}

	var b strings.Builder
	b.WriteString("services:\n")
	b.WriteString("  app:\n")
	b.WriteString(fmt.Sprintf("    image: %q\n", req.Image))
	b.WriteString(fmt.Sprintf("    container_name: %q\n", req.AppName))
	b.WriteString("    restart: unless-stopped\n")
	b.WriteString("    ports:\n")
	b.WriteString(fmt.Sprintf("      - %q\n", fmt.Sprintf("127.0.0.1:%d:%d", req.HostPort, req.ContainerPort)))

	if len(req.Env) > 0 {
		b.WriteString("    environment:\n")
		keys := make([]string, 0, len(req.Env))
		for key := range req.Env {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			b.WriteString(fmt.Sprintf("      %s: %q\n", key, req.Env[key]))
		}
	}

	return b.String(), nil
}

func renderFiles(req FileRenderRequest) (APIResponse, int) {
	if !nameRe.MatchString(req.AppName) {
		return APIResponse{OK: false, Message: "invalid app_name"}, http.StatusBadRequest
	}
	if err := validateEnv(req.Env); err != nil {
		return APIResponse{OK: false, Message: err.Error()}, http.StatusBadRequest
	}

	appDir, err := resolveAppDir(req.AppName, req.Directory)
	if err != nil {
		return APIResponse{OK: false, Message: err.Error()}, http.StatusBadRequest
	}
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		return APIResponse{OK: false, Message: err.Error()}, http.StatusInternalServerError
	}

	written := []string{}
	if req.ComposeTemplate != "" {
		composeFile, err := safeRelativeFile(req.ComposeFile, "docker-compose.yml")
		if err != nil {
			return APIResponse{OK: false, Message: "invalid compose_file: " + err.Error()}, http.StatusBadRequest
		}
		compose, err := renderTemplate(req.ComposeTemplate, req.Env)
		if err != nil {
			return APIResponse{OK: false, Message: err.Error()}, http.StatusBadRequest
		}
		if err := os.WriteFile(filepath.Join(appDir, composeFile), []byte(compose), 0o644); err != nil {
			return APIResponse{OK: false, Message: err.Error()}, http.StatusInternalServerError
		}
		written = append(written, composeFile)
	}

	if req.EnvTemplate != "" || len(req.Env) > 0 {
		envFile, err := safeRelativeFile(req.EnvFile, ".env")
		if err != nil {
			return APIResponse{OK: false, Message: "invalid env_file: " + err.Error()}, http.StatusBadRequest
		}
		envContent, err := renderEnv(req.EnvTemplate, req.Env)
		if err != nil {
			return APIResponse{OK: false, Message: err.Error()}, http.StatusBadRequest
		}
		if err := os.WriteFile(filepath.Join(appDir, envFile), []byte(envContent), 0o600); err != nil {
			return APIResponse{OK: false, Message: err.Error()}, http.StatusInternalServerError
		}
		written = append(written, envFile)
	}

	if len(written) == 0 {
		return APIResponse{OK: false, Message: "nothing to render"}, http.StatusBadRequest
	}

	return APIResponse{
		OK:      true,
		Message: "rendered",
		AppName: req.AppName,
		Data: map[string]any{
			"directory": appDir,
			"files":     written,
		},
	}, http.StatusOK
}

func runComposeAction(req ComposeRunRequest) (APIResponse, int) {
	if !nameRe.MatchString(req.AppName) {
		return APIResponse{OK: false, Message: "invalid app_name"}, http.StatusBadRequest
	}
	appDir, err := resolveAppDir(req.AppName, req.Directory)
	if err != nil {
		return APIResponse{OK: false, Message: err.Error()}, http.StatusBadRequest
	}
	if _, err := os.Stat(appDir); err != nil {
		return APIResponse{OK: false, Message: err.Error()}, http.StatusBadRequest
	}

	args, err := composeArgs(req)
	if err != nil {
		return APIResponse{OK: false, Message: err.Error()}, http.StatusBadRequest
	}
	if err := run(appDir, "docker", args...); err != nil {
		return APIResponse{OK: false, Message: err.Error()}, http.StatusInternalServerError
	}

	return APIResponse{
		OK:      true,
		Message: "compose " + req.Action + " completed",
		AppName: req.AppName,
		Data: map[string]any{
			"directory": appDir,
			"args":      append([]string{"docker"}, args...),
		},
	}, http.StatusOK
}

func composeArgs(req ComposeRunRequest) ([]string, error) {
	for _, service := range req.Services {
		if !nameRe.MatchString(service) {
			return nil, fmt.Errorf("invalid service: %s", service)
		}
	}

	args := []string{"compose"}
	switch req.Action {
	case "pull":
		args = append(args, "pull")
	case "up":
		args = append(args, "up", "-d")
	case "restart":
		args = append(args, "restart")
	case "down":
		args = append(args, "down")
	case "stop":
		args = append(args, "stop")
	case "start":
		args = append(args, "start")
	default:
		return nil, errors.New("unsupported compose action")
	}

	args = append(args, req.Services...)
	return args, nil
}

func inspectContainerHealth(container string) (APIResponse, int) {
	if !nameRe.MatchString(container) {
		return APIResponse{OK: false, Message: "invalid container"}, http.StatusBadRequest
	}

	cmd := exec.Command("docker", "inspect", "--format", "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{.State.ExitCode}}", container)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return APIResponse{OK: false, Message: strings.TrimSpace(string(out))}, http.StatusInternalServerError
	}

	parts := strings.Split(strings.TrimSpace(string(out)), "|")
	for len(parts) < 3 {
		parts = append(parts, "")
	}
	health := ContainerHealth{
		Container: container,
		Status:    parts[0],
		Health:    parts[1],
		ExitCode:  parts[2],
	}

	return APIResponse{
		OK:      true,
		Message: "container inspected",
		Data:    health,
	}, http.StatusOK
}

func renderEnv(template string, values map[string]string) (string, error) {
	if template != "" {
		return renderTemplate(template, values)
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, key := range keys {
		b.WriteString(key)
		b.WriteString("=")
		b.WriteString(quoteDotEnvValue(values[key]))
		b.WriteString("\n")
	}
	return b.String(), nil
}

func renderTemplate(template string, values map[string]string) (string, error) {
	if err := validateEnv(values); err != nil {
		return "", err
	}

	rendered := template
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		rendered = strings.ReplaceAll(rendered, "{{"+key+"}}", values[key])
		rendered = strings.ReplaceAll(rendered, "${"+key+"}", values[key])
	}
	return rendered, nil
}

func quoteDotEnvValue(value string) string {
	if value == "" {
		return `""`
	}
	if strings.ContainsAny(value, " #\"'\\") {
		return strconv.Quote(value)
	}
	return value
}

func validateEnv(values map[string]string) error {
	if len(values) > 128 {
		return errors.New("too many env entries")
	}
	for key, value := range values {
		if !envKeyRe.MatchString(key) {
			return fmt.Errorf("invalid env key: %s", key)
		}
		if strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("invalid env value for key: %s", key)
		}
	}
	return nil
}

func resolveAppDir(appName, requested string) (string, error) {
	if requested == "" {
		requested = appName
	}
	if !fileRe.MatchString(requested) || filepath.IsAbs(requested) {
		return "", errors.New("invalid directory")
	}

	clean := filepath.Clean(requested)
	if clean == "." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean == ".." {
		return "", errors.New("directory must stay inside APP_ROOT")
	}

	root, err := filepath.Abs(appRoot)
	if err != nil {
		return "", err
	}
	dir, err := filepath.Abs(filepath.Join(root, clean))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errors.New("directory must stay inside APP_ROOT")
	}

	return dir, nil
}

func safeRelativeFile(value, fallback string) (string, error) {
	if value == "" {
		value = fallback
	}
	if !fileRe.MatchString(value) || filepath.IsAbs(value) {
		return "", errors.New("must be a relative file path")
	}
	clean := filepath.Clean(value)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("must stay inside the app directory")
	}
	return clean, nil
}

func run(dir string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}

	return nil
}

func npmLogin() (string, error) {
	payload := map[string]string{
		"identity": npmEmail,
		"secret":   npmPassword,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, npmBaseURL+"/api/tokens", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("npm login failed: %s", strings.TrimSpace(string(raw)))
	}

	var tokenResp npmTokenResp
	if err := json.Unmarshal(raw, &tokenResp); err != nil {
		return "", err
	}
	if tokenResp.Token == "" {
		return "", errors.New("empty npm token")
	}

	return tokenResp.Token, nil
}

func upsertProxyHost(req DeployRequest) error {
	token, err := npmLogin()
	if err != nil {
		return err
	}

	existing, err := findProxyHostByDomain(token, req.Domain)
	if err != nil {
		return err
	}

	payload := proxyPayload(req)
	if existing != nil {
		return sendNPM(token, http.MethodPut, fmt.Sprintf("/api/nginx/proxy-hosts/%d", existing.ID), payload)
	}

	return sendNPM(token, http.MethodPost, "/api/nginx/proxy-hosts", payload)
}

func listNPMProxyHosts() (APIResponse, int) {
	token, err := npmLogin()
	if err != nil {
		return APIResponse{OK: false, Message: err.Error()}, http.StatusInternalServerError
	}

	body, err := requestNPM(token, http.MethodGet, "/api/nginx/proxy-hosts", nil)
	if err != nil {
		return APIResponse{OK: false, Message: err.Error()}, http.StatusInternalServerError
	}

	var hosts []npmProxyHost
	if err := json.Unmarshal(body, &hosts); err != nil {
		return APIResponse{OK: false, Message: err.Error()}, http.StatusInternalServerError
	}

	return APIResponse{
		OK:      true,
		Message: "proxy hosts listed",
		Data:    hosts,
	}, http.StatusOK
}

func upsertNPMProxyHost(req NPMProxyHostRequest) (APIResponse, int) {
	if err := validateNPMProxyHost(req); err != nil {
		return APIResponse{OK: false, Message: err.Error()}, http.StatusBadRequest
	}

	token, err := npmLogin()
	if err != nil {
		return APIResponse{OK: false, Message: err.Error()}, http.StatusInternalServerError
	}

	existingID := req.ID
	if existingID == 0 && len(req.DomainNames) > 0 {
		existing, err := findProxyHostByDomain(token, req.DomainNames[0])
		if err != nil {
			return APIResponse{OK: false, Message: err.Error()}, http.StatusInternalServerError
		}
		if existing != nil {
			existingID = existing.ID
		}
	}

	payload := npmProxyPayload(req)
	method := http.MethodPost
	path := "/api/nginx/proxy-hosts"
	if existingID > 0 {
		method = http.MethodPut
		path = fmt.Sprintf("/api/nginx/proxy-hosts/%d", existingID)
	}

	body, err := requestNPM(token, method, path, payload)
	if err != nil {
		return APIResponse{OK: false, Message: err.Error()}, http.StatusInternalServerError
	}

	var data any
	if len(body) > 0 {
		_ = json.Unmarshal(body, &data)
	}

	return APIResponse{
		OK:      true,
		Message: "proxy host saved",
		Data:    data,
	}, http.StatusOK
}

func deleteNPMProxyHost(id int) (APIResponse, int) {
	if id <= 0 {
		return APIResponse{OK: false, Message: "id is required"}, http.StatusBadRequest
	}

	token, err := npmLogin()
	if err != nil {
		return APIResponse{OK: false, Message: err.Error()}, http.StatusInternalServerError
	}

	if _, err := requestNPM(token, http.MethodDelete, fmt.Sprintf("/api/nginx/proxy-hosts/%d", id), nil); err != nil {
		return APIResponse{OK: false, Message: err.Error()}, http.StatusInternalServerError
	}

	return APIResponse{OK: true, Message: "proxy host deleted"}, http.StatusOK
}

func findProxyHostByDomain(token, domain string) (*npmProxyHost, error) {
	req, err := http.NewRequest(http.MethodGet, npmBaseURL+"/api/nginx/proxy-hosts", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("list proxy hosts failed: %s", strings.TrimSpace(string(raw)))
	}

	var hosts []npmProxyHost
	if err := json.Unmarshal(raw, &hosts); err != nil {
		return nil, err
	}

	for i := range hosts {
		if slices.Contains(hosts[i].DomainNames, domain) {
			return &hosts[i], nil
		}
	}

	return nil, nil
}

func proxyPayload(req DeployRequest) map[string]any {
	forwardHost := proxyForwardHost
	forwardPort := req.HostPort
	if proxyForwardMode == "container" {
		forwardHost = req.AppName
		forwardPort = req.ContainerPort
	}

	return map[string]any{
		"domain_names":            []string{req.Domain},
		"forward_scheme":          "http",
		"forward_host":            forwardHost,
		"forward_port":            forwardPort,
		"certificate_id":          0,
		"ssl_forced":              false,
		"hsts_enabled":            false,
		"hsts_subdomains":         false,
		"http2_support":           false,
		"block_exploits":          true,
		"caching_enabled":         false,
		"allow_websocket_upgrade": true,
		"access_list_id":          0,
		"advanced_config":         "",
		"enabled":                 true,
		"meta":                    map[string]any{},
		"locations":               []any{},
	}
}

func sendNPM(token, method, path string, payload map[string]any) error {
	_, err := requestNPM(token, method, path, payload)
	return err
}

func requestNPM(token, method, path string, payload map[string]any) ([]byte, error) {
	var reader io.Reader
	if payload != nil {
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, npmBaseURL+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("%s %s failed: %s", method, path, strings.TrimSpace(string(raw)))
	}

	return raw, nil
}

func validateNPMProxyHost(req NPMProxyHostRequest) error {
	if len(req.DomainNames) == 0 {
		return errors.New("domain_names is required")
	}
	if len(req.DomainNames) > 16 {
		return errors.New("too many domain_names")
	}
	for _, domain := range req.DomainNames {
		if !domainRe.MatchString(domain) || strings.Contains(domain, "..") {
			return fmt.Errorf("invalid domain: %s", domain)
		}
	}
	if req.ForwardScheme == "" {
		req.ForwardScheme = "http"
	}
	if req.ForwardScheme != "http" && req.ForwardScheme != "https" {
		return errors.New("forward_scheme must be http or https")
	}
	if !nameRe.MatchString(req.ForwardHost) && !domainRe.MatchString(req.ForwardHost) && req.ForwardHost != "127.0.0.1" && req.ForwardHost != "localhost" {
		return errors.New("invalid forward_host")
	}
	if req.ForwardPort < 1 || req.ForwardPort > 65535 {
		return errors.New("invalid forward_port")
	}
	if req.CertificateID < 0 {
		return errors.New("invalid certificate_id")
	}
	return nil
}

func npmProxyPayload(req NPMProxyHostRequest) map[string]any {
	forwardScheme := req.ForwardScheme
	if forwardScheme == "" {
		forwardScheme = "http"
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	blockExploits := true
	if req.BlockExploits != nil {
		blockExploits = *req.BlockExploits
	}
	websocketUpgrade := true
	if req.WebsocketUpgrade != nil {
		websocketUpgrade = *req.WebsocketUpgrade
	}

	return map[string]any{
		"domain_names":            req.DomainNames,
		"forward_scheme":          forwardScheme,
		"forward_host":            req.ForwardHost,
		"forward_port":            req.ForwardPort,
		"certificate_id":          req.CertificateID,
		"ssl_forced":              req.SSLForced,
		"hsts_enabled":            false,
		"hsts_subdomains":         false,
		"http2_support":           req.HTTP2Support,
		"block_exploits":          blockExploits,
		"caching_enabled":         false,
		"allow_websocket_upgrade": websocketUpgrade,
		"access_list_id":          0,
		"advanced_config":         "",
		"enabled":                 enabled,
		"meta": map[string]any{
			"letsencrypt_agree": req.SSLEnabled,
		},
		"locations": []any{},
	}
}

func env(key string, fallback string) string {
	loadDotEnvOnce.Do(func() {
		loadDotEnvErr = loadDotEnv(dotEnvPath())
	})

	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}

func dotEnvPath() string {
	if path := os.Getenv("ENV_FILE"); path != "" {
		return path
	}
	if _, err := os.Stat(".env"); err == nil {
		return ".env"
	}
	if _, err := os.Stat(filepath.Join("opsagent", ".env")); err == nil {
		return filepath.Join("opsagent", ".env")
	}
	return ".env"
}

func loadDotEnv(path string) error {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("load %s: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("%s:%d: missing '='", path, lineNo)
		}

		key = strings.TrimSpace(key)
		if !validDotEnvKey(key) {
			return fmt.Errorf("%s:%d: invalid key %q", path, lineNo, key)
		}

		parsedValue, err := parseDotEnvValue(value)
		if err != nil {
			return fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		if _, exists := os.LookupEnv(key); !exists {
			if err := os.Setenv(key, parsedValue); err != nil {
				return fmt.Errorf("%s:%d: set %s: %w", path, lineNo, key, err)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	return nil
}

func validDotEnvKey(key string) bool {
	if key == "" {
		return false
	}
	for i, r := range key {
		if r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}

func parseDotEnvValue(value string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) < 2 {
		return value, nil
	}

	quote := value[0]
	if quote != '"' && quote != '\'' {
		return value, nil
	}
	if value[len(value)-1] != quote {
		return "", errors.New("unterminated quoted value")
	}
	if quote == '\'' {
		return value[1 : len(value)-1], nil
	}

	return strconv.Unquote(value)
}

func writeJSON(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(data)
}
