package config

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"opsagent/internal/dotenv"
)

type Config struct {
	ListenAddr string
	Secret     string
	APIKey     string
	AppRoot    string

	NPMBaseURL  string
	NPMEmail    string
	NPMPassword string

	ProxyForwardMode string
	ProxyForwardHost string
}

func Load() (Config, error) {
	if err := dotenv.Load(dotEnvPath()); err != nil {
		return Config{}, err
	}

	return Config{
		ListenAddr:       env("LISTEN_ADDR", ":9090"),
		Secret:           env("AGENT_SECRET", "change-me"),
		APIKey:           env("API_KEY", ""),
		AppRoot:          env("APP_ROOT", "/opt/apps"),
		NPMBaseURL:       strings.TrimRight(env("NPM_BASE_URL", "http://127.0.0.1:81"), "/"),
		NPMEmail:         env("NPM_EMAIL", "admin@example.com"),
		NPMPassword:      env("NPM_PASSWORD", "password"),
		ProxyForwardMode: env("PROXY_FORWARD_MODE", "host-port"),
		ProxyForwardHost: env("PROXY_FORWARD_HOST", "127.0.0.1"),
	}, nil
}

func HTTPClient() *http.Client {
	return &http.Client{Timeout: 20 * time.Second}
}

func env(key string, fallback string) string {
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
