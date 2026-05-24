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

	httpClient = &http.Client{Timeout: 20 * time.Second}

	loadDotEnvOnce sync.Once
	loadDotEnvErr  error
)

type DeployRequest struct {
	AppName string `json:"app_name"`
	Domain  string `json:"domain"`
	Image   string `json:"image"`

	HostPort      int `json:"host_port"`
	ContainerPort int `json:"container_port"`

	Env map[string]string `json:"env"`
}

type APIResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
	AppName string `json:"app_name,omitempty"`
	Domain  string `json:"domain,omitempty"`
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

	log.Println("opshook listening on", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}

func handleDeploy(w http.ResponseWriter, r *http.Request) {
	body, err := readAndVerify(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, APIResponse{OK: false, Message: err.Error()})
		return
	}

	var req DeployRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, APIResponse{OK: false, Message: "invalid json"})
		return
	}

	if err := validateDeploy(req); err != nil {
		writeJSON(w, http.StatusBadRequest, APIResponse{OK: false, Message: err.Error()})
		return
	}

	appDir := filepath.Join(appRoot, req.AppName)
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		writeJSON(w, http.StatusInternalServerError, APIResponse{OK: false, Message: err.Error()})
		return
	}

	if err := writeCompose(appDir, req); err != nil {
		writeJSON(w, http.StatusInternalServerError, APIResponse{OK: false, Message: err.Error()})
		return
	}

	if err := run(appDir, "docker", "compose", "pull"); err != nil {
		writeJSON(w, http.StatusInternalServerError, APIResponse{OK: false, Message: err.Error()})
		return
	}

	if err := run(appDir, "docker", "compose", "up", "-d"); err != nil {
		writeJSON(w, http.StatusInternalServerError, APIResponse{OK: false, Message: err.Error()})
		return
	}

	if err := upsertProxyHost(req); err != nil {
		writeJSON(w, http.StatusInternalServerError, APIResponse{
			OK:      false,
			Message: "docker ok, npm failed: " + err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		OK:      true,
		Message: "deployed",
		AppName: req.AppName,
		Domain:  req.Domain,
	})
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
	if !domainRe.MatchString(req.Domain) || strings.Contains(req.Domain, "..") {
		return errors.New("invalid domain")
	}
	if !imageRe.MatchString(req.Image) {
		return errors.New("invalid image")
	}
	if req.HostPort < 10000 || req.HostPort > 60000 {
		return errors.New("host_port must be 10000-60000")
	}
	if req.ContainerPort < 1 || req.ContainerPort > 65535 {
		return errors.New("invalid container_port")
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

	return nil
}

func writeCompose(appDir string, req DeployRequest) error {
	compose, err := renderCompose(req)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(appDir, "docker-compose.yml"), []byte(compose), 0o644)
}

func renderCompose(req DeployRequest) (string, error) {
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
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(method, npmBaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%s %s failed: %s", method, path, strings.TrimSpace(string(raw)))
	}

	return nil
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
	if _, err := os.Stat(filepath.Join("agent", ".env")); err == nil {
		return filepath.Join("agent", ".env")
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
