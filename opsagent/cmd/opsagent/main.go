package main

import (
	"log"
	"net/http"

	"opsagent/internal/appsvc"
	"opsagent/internal/config"
	"opsagent/internal/docker"
	"opsagent/internal/httpapi"
	"opsagent/internal/npm"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	if cfg.Secret == "change-me" {
		log.Println("warning: AGENT_SECRET is using the default value")
	}

	httpClient := config.HTTPClient()
	npmClient := npm.New(npm.Config{
		BaseURL:          cfg.NPMBaseURL,
		Email:            cfg.NPMEmail,
		Password:         cfg.NPMPassword,
		ProxyForwardMode: cfg.ProxyForwardMode,
		ProxyForwardHost: cfg.ProxyForwardHost,
	}, httpClient)

	apps := appsvc.New(cfg, docker.New(), npmClient)
	server := httpapi.New(httpapi.AuthConfig{
		WebhookSecret: cfg.Secret,
		APIKey:        cfg.APIKey,
	}, apps)

	log.Println("opsagent listening on", cfg.ListenAddr)
	log.Fatal(http.ListenAndServe(cfg.ListenAddr, server.Handler()))
}
