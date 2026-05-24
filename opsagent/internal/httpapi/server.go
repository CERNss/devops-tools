package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"opsagent/internal/api"
	"opsagent/internal/appsvc"
)

type Server struct {
	secret string
	apps   *appsvc.Service
	mux    *http.ServeMux
}

func New(secret string, apps *appsvc.Service) *Server {
	s := &Server{
		secret: secret,
		apps:   apps,
		mux:    http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, api.Response{OK: true, Message: "ok"})
	})
	s.mux.HandleFunc("POST /deploy", s.handleDeploy)
	s.mux.HandleFunc("POST /webhook", s.handleWebhook)
	s.mux.HandleFunc("POST /api/deploy", s.handleDeploy)
	s.mux.HandleFunc("POST /api/compose/render", s.handleRenderFiles)
	s.mux.HandleFunc("POST /api/compose/run", s.handleComposeRun)
	s.mux.HandleFunc("POST /api/apps/{app}/restart", s.handleRestart)
	s.mux.HandleFunc("POST /api/containers/health", s.handleContainerHealth)
	s.mux.HandleFunc("GET /api/containers/{container}/health", s.handleContainerHealth)
	s.mux.HandleFunc("GET /api/npm/proxy-hosts", s.handleNPMProxyHosts)
	s.mux.HandleFunc("POST /api/npm/proxy-hosts", s.handleNPMProxyHosts)
	s.mux.HandleFunc("DELETE /api/npm/proxy-hosts", s.handleNPMProxyHosts)
}

func (s *Server) handleDeploy(w http.ResponseWriter, r *http.Request) {
	var req api.DeployRequest
	if !s.readSignedJSON(w, r, &req) {
		return
	}

	resp, code := s.apps.Deploy(req)
	writeJSON(w, code, resp)
}

func (s *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	var req api.WebhookRequest
	if !s.readSignedJSON(w, r, &req) {
		return
	}

	switch req.Action {
	case "deploy":
		var deploy api.DeployRequest
		if !decodeRaw(w, req.Data, &deploy) {
			return
		}
		resp, code := s.apps.Deploy(deploy)
		writeJSON(w, code, resp)
	case "render":
		var render api.FileRenderRequest
		if !decodeRaw(w, req.Data, &render) {
			return
		}
		resp, code := s.apps.RenderFiles(render)
		writeJSON(w, code, resp)
	case "compose":
		var compose api.ComposeRunRequest
		if !decodeRaw(w, req.Data, &compose) {
			return
		}
		resp, code := s.apps.RunCompose(compose)
		writeJSON(w, code, resp)
	case "restart":
		var compose api.ComposeRunRequest
		if !decodeRaw(w, req.Data, &compose) {
			return
		}
		compose.Action = "restart"
		resp, code := s.apps.RunCompose(compose)
		writeJSON(w, code, resp)
	case "container_health":
		var health api.ContainerHealthRequest
		if !decodeRaw(w, req.Data, &health) {
			return
		}
		resp, code := s.apps.ContainerHealth(health.Container)
		writeJSON(w, code, resp)
	case "npm_proxy_host":
		var proxy api.NPMProxyHostRequest
		if !decodeRaw(w, req.Data, &proxy) {
			return
		}
		resp, code := s.apps.UpsertNPMProxyHost(proxy)
		writeJSON(w, code, resp)
	default:
		writeJSON(w, http.StatusBadRequest, api.Response{OK: false, Message: "unsupported action"})
	}
}

func (s *Server) handleRenderFiles(w http.ResponseWriter, r *http.Request) {
	var req api.FileRenderRequest
	if !s.readSignedJSON(w, r, &req) {
		return
	}

	resp, code := s.apps.RenderFiles(req)
	writeJSON(w, code, resp)
}

func (s *Server) handleComposeRun(w http.ResponseWriter, r *http.Request) {
	var req api.ComposeRunRequest
	if !s.readSignedJSON(w, r, &req) {
		return
	}

	resp, code := s.apps.RunCompose(req)
	writeJSON(w, code, resp)
}

func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	var req api.ComposeRunRequest
	if !s.readSignedJSON(w, r, &req) {
		return
	}
	req.AppName = r.PathValue("app")
	req.Action = "restart"

	resp, code := s.apps.RunCompose(req)
	writeJSON(w, code, resp)
}

func (s *Server) handleContainerHealth(w http.ResponseWriter, r *http.Request) {
	container := r.PathValue("container")
	if container == "" {
		var req api.ContainerHealthRequest
		if !s.readSignedJSON(w, r, &req) {
			return
		}
		container = req.Container
	} else if err := s.verifyRequest(r); err != nil {
		writeJSON(w, http.StatusUnauthorized, api.Response{OK: false, Message: err.Error()})
		return
	}

	resp, code := s.apps.ContainerHealth(container)
	writeJSON(w, code, resp)
}

func (s *Server) handleNPMProxyHosts(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if err := s.verifyRequest(r); err != nil {
			writeJSON(w, http.StatusUnauthorized, api.Response{OK: false, Message: err.Error()})
			return
		}
		resp, code := s.apps.ListNPMProxyHosts()
		writeJSON(w, code, resp)
		return
	}

	var req api.NPMProxyHostRequest
	if !s.readSignedJSON(w, r, &req) {
		return
	}

	switch r.Method {
	case http.MethodPost:
		resp, code := s.apps.UpsertNPMProxyHost(req)
		writeJSON(w, code, resp)
	case http.MethodDelete:
		resp, code := s.apps.DeleteNPMProxyHost(req.ID)
		writeJSON(w, code, resp)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, api.Response{OK: false, Message: "method not allowed"})
	}
}

func (s *Server) readSignedJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	body, err := readAndVerify(r, s.secret)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, api.Response{OK: false, Message: err.Error()})
		return false
	}
	if err := json.Unmarshal(body, out); err != nil {
		writeJSON(w, http.StatusBadRequest, api.Response{OK: false, Message: "invalid json"})
		return false
	}
	return true
}

func (s *Server) verifyRequest(r *http.Request) error {
	body, err := readAndVerify(r, s.secret)
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
		writeJSON(w, http.StatusBadRequest, api.Response{OK: false, Message: "missing data"})
		return false
	}
	if err := json.Unmarshal(raw, out); err != nil {
		writeJSON(w, http.StatusBadRequest, api.Response{OK: false, Message: "invalid data"})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(data)
}
