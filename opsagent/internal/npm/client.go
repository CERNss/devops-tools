package npm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"opsagent/internal/api"
	"opsagent/internal/validate"
)

type Config struct {
	BaseURL          string
	Email            string
	Password         string
	ProxyForwardMode string
	ProxyForwardHost string
}

type Client struct {
	cfg        Config
	httpClient *http.Client
}

type tokenResp struct {
	Token string `json:"token"`
}

func New(cfg Config, httpClient *http.Client) *Client {
	return &Client{cfg: cfg, httpClient: httpClient}
}

func (c *Client) UpsertDeployProxyHost(req api.DeployRequest) error {
	token, err := c.login()
	if err != nil {
		return err
	}

	existing, err := c.findProxyHostByDomain(token, req.Domain)
	if err != nil {
		return err
	}

	payload := c.deployProxyPayload(req)
	if existing != nil {
		_, err = c.request(token, http.MethodPut, fmt.Sprintf("/api/nginx/proxy-hosts/%d", existing.ID), payload)
		return err
	}

	_, err = c.request(token, http.MethodPost, "/api/nginx/proxy-hosts", payload)
	return err
}

func (c *Client) ListProxyHosts() ([]api.NPMProxyHost, error) {
	token, err := c.login()
	if err != nil {
		return nil, err
	}

	body, err := c.request(token, http.MethodGet, "/api/nginx/proxy-hosts", nil)
	if err != nil {
		return nil, err
	}

	var hosts []api.NPMProxyHost
	if err := json.Unmarshal(body, &hosts); err != nil {
		return nil, err
	}

	return hosts, nil
}

func (c *Client) UpsertProxyHost(req api.NPMProxyHostRequest) (any, error) {
	if err := ValidateProxyHost(req); err != nil {
		return nil, err
	}

	token, err := c.login()
	if err != nil {
		return nil, err
	}

	existingID := req.ID
	if existingID == 0 && len(req.DomainNames) > 0 {
		existing, err := c.findProxyHostByDomain(token, req.DomainNames[0])
		if err != nil {
			return nil, err
		}
		if existing != nil {
			existingID = existing.ID
		}
	}

	payload := ProxyPayload(req)
	method := http.MethodPost
	path := "/api/nginx/proxy-hosts"
	if existingID > 0 {
		method = http.MethodPut
		path = fmt.Sprintf("/api/nginx/proxy-hosts/%d", existingID)
	}

	body, err := c.request(token, method, path, payload)
	if err != nil {
		return nil, err
	}

	var data any
	if len(body) > 0 {
		_ = json.Unmarshal(body, &data)
	}
	return data, nil
}

func (c *Client) DeleteProxyHost(id int) error {
	if id <= 0 {
		return errors.New("id is required")
	}

	token, err := c.login()
	if err != nil {
		return err
	}

	_, err = c.request(token, http.MethodDelete, fmt.Sprintf("/api/nginx/proxy-hosts/%d", id), nil)
	return err
}

func (c *Client) login() (string, error) {
	payload := map[string]string{
		"identity": c.cfg.Email,
		"secret":   c.cfg.Password,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, c.cfg.BaseURL+"/api/tokens", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("npm login failed: %s", strings.TrimSpace(string(raw)))
	}

	var token tokenResp
	if err := json.Unmarshal(raw, &token); err != nil {
		return "", err
	}
	if token.Token == "" {
		return "", errors.New("empty npm token")
	}

	return token.Token, nil
}

func (c *Client) findProxyHostByDomain(token, domain string) (*api.NPMProxyHost, error) {
	body, err := c.request(token, http.MethodGet, "/api/nginx/proxy-hosts", nil)
	if err != nil {
		return nil, err
	}

	var hosts []api.NPMProxyHost
	if err := json.Unmarshal(body, &hosts); err != nil {
		return nil, err
	}

	for i := range hosts {
		if slices.Contains(hosts[i].DomainNames, domain) {
			return &hosts[i], nil
		}
	}

	return nil, nil
}

func (c *Client) request(token, method, path string, payload map[string]any) ([]byte, error) {
	var reader io.Reader
	if payload != nil {
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, c.cfg.BaseURL+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
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

func (c *Client) deployProxyPayload(req api.DeployRequest) map[string]any {
	forwardHost := c.cfg.ProxyForwardHost
	forwardPort := req.HostPort
	if c.cfg.ProxyForwardMode == "container" {
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

func ValidateProxyHost(req api.NPMProxyHostRequest) error {
	if len(req.DomainNames) == 0 {
		return errors.New("domain_names is required")
	}
	if len(req.DomainNames) > 16 {
		return errors.New("too many domain_names")
	}
	for _, domain := range req.DomainNames {
		if !validate.Domain(domain) {
			return fmt.Errorf("invalid domain: %s", domain)
		}
	}
	if req.ForwardScheme == "" {
		req.ForwardScheme = "http"
	}
	if req.ForwardScheme != "http" && req.ForwardScheme != "https" {
		return errors.New("forward_scheme must be http or https")
	}
	if !validate.Name(req.ForwardHost) && !validate.Domain(req.ForwardHost) && req.ForwardHost != "127.0.0.1" && req.ForwardHost != "localhost" {
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

func ProxyPayload(req api.NPMProxyHostRequest) map[string]any {
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
