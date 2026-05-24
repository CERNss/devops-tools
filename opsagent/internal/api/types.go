package api

import "encoding/json"

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

type Response struct {
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

type NPMProxyHost struct {
	ID          int      `json:"id"`
	DomainNames []string `json:"domain_names"`
}
