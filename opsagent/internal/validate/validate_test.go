package validate

import (
	"path/filepath"
	"testing"

	"opsagent/internal/api"
)

func TestDeploy(t *testing.T) {
	appRoot := t.TempDir()
	valid := api.DeployRequest{
		AppName:       "demo-app",
		Domain:        "demo.example.com",
		Image:         "nginx:latest",
		HostPort:      18080,
		ContainerPort: 80,
		Env: map[string]string{
			"APP_ENV": "production",
		},
	}

	if err := Deploy(valid, "host-port", appRoot); err != nil {
		t.Fatalf("valid deploy request failed validation: %v", err)
	}

	cases := map[string]api.DeployRequest{
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
			if err := Deploy(req, "host-port", appRoot); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestDeployAllowsTemplateWithoutNPM(t *testing.T) {
	req := api.DeployRequest{
		AppName:         "demo-app",
		Directory:       "team/demo-app",
		ComposeTemplate: "services:\n  app:\n    image: {{IMAGE}}\n",
		Env: map[string]string{
			"IMAGE": "nginx:latest",
		},
		SkipNPM: true,
	}

	if err := Deploy(req, "host-port", t.TempDir()); err != nil {
		t.Fatalf("template deploy failed validation: %v", err)
	}
}

func TestResolveAppDirRejectsTraversal(t *testing.T) {
	appRoot := t.TempDir()

	if _, err := ResolveAppDir(appRoot, "demo-app", "../outside"); err == nil {
		t.Fatal("expected traversal directory to be rejected")
	}

	got, err := ResolveAppDir(appRoot, "demo-app", "team/demo-app")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(appRoot, "team", "demo-app")
	if got != want {
		t.Fatalf("dir mismatch: want %q, got %q", want, got)
	}
}

func TestSafeRelativeFileRejectsTraversal(t *testing.T) {
	if _, err := SafeRelativeFile("../compose.yml", "docker-compose.yml"); err == nil {
		t.Fatal("expected traversal file to be rejected")
	}
	if got, err := SafeRelativeFile("deploy/docker-compose.yml", "docker-compose.yml"); err != nil || got != "deploy/docker-compose.yml" {
		t.Fatalf("safe file mismatch: got %q err %v", got, err)
	}
}
