package render

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"opsagent/internal/api"
	"opsagent/internal/validate"
)

func Compose(req api.DeployRequest) (string, error) {
	if req.ComposeTemplate != "" {
		return Template(req.ComposeTemplate, req.Env)
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

func Env(template string, values map[string]string) (string, error) {
	if template != "" {
		return Template(template, values)
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
		b.WriteString(QuoteDotEnvValue(values[key]))
		b.WriteString("\n")
	}
	return b.String(), nil
}

func Template(template string, values map[string]string) (string, error) {
	if err := validate.Env(values); err != nil {
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

func QuoteDotEnvValue(value string) string {
	if value == "" {
		return `""`
	}
	if strings.ContainsAny(value, " #\"'\\") {
		return strconv.Quote(value)
	}
	return value
}
