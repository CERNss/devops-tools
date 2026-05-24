package docker

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"opsagent/internal/api"
	"opsagent/internal/validate"
)

type Client struct{}

func New() Client {
	return Client{}
}

func (Client) Compose(dir string, req api.ComposeRunRequest) error {
	args, err := ComposeArgs(req)
	if err != nil {
		return err
	}
	return run(dir, "docker", args...)
}

func (Client) Pull(dir string) error {
	return run(dir, "docker", "compose", "pull")
}

func (Client) Up(dir string) error {
	return run(dir, "docker", "compose", "up", "-d")
}

func (Client) InspectHealth(container string) (api.ContainerHealth, error) {
	if !validate.Name(container) {
		return api.ContainerHealth{}, errors.New("invalid container")
	}

	cmd := exec.Command("docker", "inspect", "--format", "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{.State.ExitCode}}", container)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return api.ContainerHealth{}, errors.New(strings.TrimSpace(string(out)))
	}

	parts := strings.Split(strings.TrimSpace(string(out)), "|")
	for len(parts) < 3 {
		parts = append(parts, "")
	}

	return api.ContainerHealth{
		Container: container,
		Status:    parts[0],
		Health:    parts[1],
		ExitCode:  parts[2],
	}, nil
}

func ComposeArgs(req api.ComposeRunRequest) ([]string, error) {
	for _, service := range req.Services {
		if !validate.Name(service) {
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

func run(dir string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}

	return nil
}
