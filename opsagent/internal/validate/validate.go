package validate

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"opsagent/internal/api"
)

var (
	nameRe   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}$`)
	domainRe = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$`)
	imageRe  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9./:@_-]{0,255}$`)
	envKeyRe = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
	fileRe   = regexp.MustCompile(`^[a-zA-Z0-9._/-]{1,160}$`)
)

func Name(value string) bool {
	return nameRe.MatchString(value)
}

func Domain(value string) bool {
	return domainRe.MatchString(value) && !strings.Contains(value, "..")
}

func Env(values map[string]string) error {
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

func Deploy(req api.DeployRequest, proxyForwardMode string, appRoot string) error {
	if !Name(req.AppName) {
		return errors.New("invalid app_name")
	}
	if _, err := ResolveAppDir(appRoot, req.AppName, req.Directory); err != nil {
		return err
	}
	if req.Domain == "" && !req.SkipNPM {
		return errors.New("domain is required unless skip_npm is true")
	}
	if req.Domain != "" && !Domain(req.Domain) {
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
	if err := Env(req.Env); err != nil {
		return err
	}
	if proxyForwardMode != "host-port" && proxyForwardMode != "container" {
		return errors.New("PROXY_FORWARD_MODE must be host-port or container")
	}
	if _, err := SafeRelativeFile(req.ComposeFile, "docker-compose.yml"); err != nil {
		return fmt.Errorf("invalid compose_file: %w", err)
	}
	if _, err := SafeRelativeFile(req.EnvFile, ".env"); err != nil {
		return fmt.Errorf("invalid env_file: %w", err)
	}

	return nil
}

func ResolveAppDir(appRoot, appName, requested string) (string, error) {
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

func SafeRelativeFile(value, fallback string) (string, error) {
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
