package appsvc

import (
	"net/http"
	"os"
	"path/filepath"

	"opsagent/internal/api"
	"opsagent/internal/config"
	"opsagent/internal/docker"
	"opsagent/internal/render"
	"opsagent/internal/validate"
)

type Service struct {
	cfg    config.Config
	docker DockerClient
	npm    NPMClient
}

type DockerClient interface {
	Compose(dir string, req api.ComposeRunRequest) error
	Pull(dir string) error
	Up(dir string) error
	InspectHealth(container string) (api.ContainerHealth, error)
}

type NPMClient interface {
	UpsertDeployProxyHost(req api.DeployRequest) error
	ListProxyHosts() ([]api.NPMProxyHost, error)
	UpsertProxyHost(req api.NPMProxyHostRequest) (any, error)
	DeleteProxyHost(id int) error
}

func New(cfg config.Config, dockerClient DockerClient, npmClient NPMClient) *Service {
	return &Service{cfg: cfg, docker: dockerClient, npm: npmClient}
}

func (s *Service) Deploy(req api.DeployRequest) (api.Response, int) {
	if err := validate.Deploy(req, s.cfg.ProxyForwardMode, s.cfg.AppRoot); err != nil {
		return api.Response{OK: false, Message: err.Error()}, http.StatusBadRequest
	}

	appDir, err := validate.ResolveAppDir(s.cfg.AppRoot, req.AppName, req.Directory)
	if err != nil {
		return api.Response{OK: false, Message: err.Error()}, http.StatusBadRequest
	}

	if err := os.MkdirAll(appDir, 0o755); err != nil {
		return api.Response{OK: false, Message: err.Error()}, http.StatusInternalServerError
	}

	if err := s.writeDeployFiles(appDir, req); err != nil {
		return api.Response{OK: false, Message: err.Error()}, http.StatusInternalServerError
	}

	if !req.SkipDocker {
		if err := s.docker.Pull(appDir); err != nil {
			return api.Response{OK: false, Message: err.Error()}, http.StatusInternalServerError
		}
		if err := s.docker.Up(appDir); err != nil {
			return api.Response{OK: false, Message: err.Error()}, http.StatusInternalServerError
		}
	}

	if !req.SkipNPM {
		if err := s.npm.UpsertDeployProxyHost(req); err != nil {
			return api.Response{
				OK:      false,
				Message: "docker ok, npm failed: " + err.Error(),
			}, http.StatusInternalServerError
		}
	}

	return api.Response{
		OK:      true,
		Message: "deployed",
		AppName: req.AppName,
		Domain:  req.Domain,
		Data: map[string]string{
			"directory": appDir,
		},
	}, http.StatusOK
}

func (s *Service) RenderFiles(req api.FileRenderRequest) (api.Response, int) {
	if !validate.Name(req.AppName) {
		return api.Response{OK: false, Message: "invalid app_name"}, http.StatusBadRequest
	}
	if err := validate.Env(req.Env); err != nil {
		return api.Response{OK: false, Message: err.Error()}, http.StatusBadRequest
	}

	appDir, err := validate.ResolveAppDir(s.cfg.AppRoot, req.AppName, req.Directory)
	if err != nil {
		return api.Response{OK: false, Message: err.Error()}, http.StatusBadRequest
	}
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		return api.Response{OK: false, Message: err.Error()}, http.StatusInternalServerError
	}

	written := []string{}
	if req.ComposeTemplate != "" {
		composeFile, err := validate.SafeRelativeFile(req.ComposeFile, "docker-compose.yml")
		if err != nil {
			return api.Response{OK: false, Message: "invalid compose_file: " + err.Error()}, http.StatusBadRequest
		}
		compose, err := render.Template(req.ComposeTemplate, req.Env)
		if err != nil {
			return api.Response{OK: false, Message: err.Error()}, http.StatusBadRequest
		}
		if err := os.WriteFile(filepath.Join(appDir, composeFile), []byte(compose), 0o644); err != nil {
			return api.Response{OK: false, Message: err.Error()}, http.StatusInternalServerError
		}
		written = append(written, composeFile)
	}

	if req.EnvTemplate != "" || len(req.Env) > 0 {
		envFile, err := validate.SafeRelativeFile(req.EnvFile, ".env")
		if err != nil {
			return api.Response{OK: false, Message: "invalid env_file: " + err.Error()}, http.StatusBadRequest
		}
		envContent, err := render.Env(req.EnvTemplate, req.Env)
		if err != nil {
			return api.Response{OK: false, Message: err.Error()}, http.StatusBadRequest
		}
		if err := os.WriteFile(filepath.Join(appDir, envFile), []byte(envContent), 0o600); err != nil {
			return api.Response{OK: false, Message: err.Error()}, http.StatusInternalServerError
		}
		written = append(written, envFile)
	}

	if len(written) == 0 {
		return api.Response{OK: false, Message: "nothing to render"}, http.StatusBadRequest
	}

	return api.Response{
		OK:      true,
		Message: "rendered",
		AppName: req.AppName,
		Data: map[string]any{
			"directory": appDir,
			"files":     written,
		},
	}, http.StatusOK
}

func (s *Service) RunCompose(req api.ComposeRunRequest) (api.Response, int) {
	if !validate.Name(req.AppName) {
		return api.Response{OK: false, Message: "invalid app_name"}, http.StatusBadRequest
	}
	appDir, err := validate.ResolveAppDir(s.cfg.AppRoot, req.AppName, req.Directory)
	if err != nil {
		return api.Response{OK: false, Message: err.Error()}, http.StatusBadRequest
	}
	if _, err := os.Stat(appDir); err != nil {
		return api.Response{OK: false, Message: err.Error()}, http.StatusBadRequest
	}

	args, err := docker.ComposeArgs(req)
	if err != nil {
		return api.Response{OK: false, Message: err.Error()}, http.StatusBadRequest
	}
	if err := s.docker.Compose(appDir, req); err != nil {
		return api.Response{OK: false, Message: err.Error()}, http.StatusInternalServerError
	}

	return api.Response{
		OK:      true,
		Message: "compose " + req.Action + " completed",
		AppName: req.AppName,
		Data: map[string]any{
			"directory": appDir,
			"args":      append([]string{"docker"}, args...),
		},
	}, http.StatusOK
}

func (s *Service) ContainerHealth(container string) (api.Response, int) {
	health, err := s.docker.InspectHealth(container)
	if err != nil {
		code := http.StatusInternalServerError
		if err.Error() == "invalid container" {
			code = http.StatusBadRequest
		}
		return api.Response{OK: false, Message: err.Error()}, code
	}

	return api.Response{
		OK:      true,
		Message: "container inspected",
		Data:    health,
	}, http.StatusOK
}

func (s *Service) ListNPMProxyHosts() (api.Response, int) {
	hosts, err := s.npm.ListProxyHosts()
	if err != nil {
		return api.Response{OK: false, Message: err.Error()}, http.StatusInternalServerError
	}

	return api.Response{
		OK:      true,
		Message: "proxy hosts listed",
		Data:    hosts,
	}, http.StatusOK
}

func (s *Service) UpsertNPMProxyHost(req api.NPMProxyHostRequest) (api.Response, int) {
	data, err := s.npm.UpsertProxyHost(req)
	if err != nil {
		code := http.StatusInternalServerError
		if validationError(err.Error()) {
			code = http.StatusBadRequest
		}
		return api.Response{OK: false, Message: err.Error()}, code
	}

	return api.Response{
		OK:      true,
		Message: "proxy host saved",
		Data:    data,
	}, http.StatusOK
}

func (s *Service) DeleteNPMProxyHost(id int) (api.Response, int) {
	if err := s.npm.DeleteProxyHost(id); err != nil {
		code := http.StatusInternalServerError
		if err.Error() == "id is required" {
			code = http.StatusBadRequest
		}
		return api.Response{OK: false, Message: err.Error()}, code
	}

	return api.Response{OK: true, Message: "proxy host deleted"}, http.StatusOK
}

func (s *Service) writeDeployFiles(appDir string, req api.DeployRequest) error {
	compose, err := render.Compose(req)
	if err != nil {
		return err
	}

	composeFile, err := validate.SafeRelativeFile(req.ComposeFile, "docker-compose.yml")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(appDir, composeFile), []byte(compose), 0o644); err != nil {
		return err
	}

	if req.EnvTemplate == "" && len(req.Env) == 0 {
		return nil
	}

	envFile, err := validate.SafeRelativeFile(req.EnvFile, ".env")
	if err != nil {
		return err
	}

	envContent, err := render.Env(req.EnvTemplate, req.Env)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(appDir, envFile), []byte(envContent), 0o600)
}

func validationError(message string) bool {
	switch message {
	case "domain_names is required",
		"too many domain_names",
		"forward_scheme must be http or https",
		"invalid forward_host",
		"invalid forward_port",
		"invalid certificate_id":
		return true
	default:
		return false
	}
}
