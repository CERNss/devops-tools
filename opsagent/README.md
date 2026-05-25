# opsagent

`opsagent` exposes signed HTTP APIs for webhook-driven Docker Compose deployment,
file rendering, container health checks, and Nginx Proxy Manager proxy host
operations.

## OpenAPI

The OpenAPI 3 document is [openapi.yaml](./openapi.yaml).

## Authentication

Protected endpoints accept either API key auth or webhook HMAC auth.

For API key auth, set `API_KEY` and send:

- `X-API-Key`: API key value.

For webhook HMAC auth, send:

- `X-Timestamp`: Unix seconds.
- `X-Signature`: `sha256=<hex hmac>`.

The HMAC payload is:

```text
<X-Timestamp>.<raw request body>
```

Use `AGENT_SECRET` as the HMAC-SHA256 key. Signed timestamps are accepted within
a five minute window.

API key example:

```bash
curl -s http://localhost:9090/api/compose/render \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"app_name":"demo-app","compose_template":"services:\n  app:\n    image: {{IMAGE}}\n","env":{"IMAGE":"nginx:latest"}}'
```

## Endpoints

- `GET /health`: local process health.
- `POST /webhook`: action-based webhook entrypoint.
- `POST /api/deploy`: render compose/env files, run `docker compose pull`, run
  `docker compose up -d`, and optionally upsert an NPM proxy host.
- `POST /api/compose/render`: render a compose template and/or `.env` file
  under `APP_ROOT`.
- `POST /api/compose/run`: run an allowed compose action: `pull`, `up`,
  `restart`, `down`, `stop`, or `start`.
- `POST /api/apps/{app}/restart`: restart an app's compose project.
- `POST /api/containers/health`: inspect a container's Docker status and health.
- `GET /api/containers/{container}/health`: inspect a container with a signed
  empty body.
- `GET /api/npm/proxy-hosts`: list NPM proxy hosts with a signed empty body.
- `POST /api/npm/proxy-hosts`: create or update an NPM proxy host.
- `DELETE /api/npm/proxy-hosts`: delete an NPM proxy host by signed JSON body
  containing `id`.

All app directories and rendered files are constrained to `APP_ROOT`.

## Webhook Actions

`POST /webhook` accepts:

```json
{
  "action": "deploy",
  "data": {
    "app_name": "demo-app",
    "domain": "demo.example.com",
    "image": "nginx:latest",
    "host_port": 18080,
    "container_port": 80,
    "env": {
      "APP_ENV": "production"
    }
  }
}
```

Supported actions are `deploy`, `render`, `compose`, `restart`,
`container_health`, and `npm_proxy_host`.

## Background Run

Build the binary from the module root:

```bash
go build -o opsagent ./cmd/opsagent
```

For a server, prefer `systemd` so the process restarts after failure or reboot:

```ini
[Unit]
Description=opsagent
After=network-online.target docker.service
Wants=network-online.target

[Service]
WorkingDirectory=/opt/opsagent
EnvironmentFile=/opt/opsagent/.env
ExecStart=/opt/opsagent/opsagent
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

Install and start it:

```bash
sudo install -m 0755 opsagent /opt/opsagent/opsagent
sudo install -m 0600 .env /opt/opsagent/.env
sudo cp opsagent.service /etc/systemd/system/opsagent.service
sudo systemctl daemon-reload
sudo systemctl enable --now opsagent
sudo systemctl status opsagent
```

If the host already manages opsagent with Docker Compose, mount the Docker
socket and app root, then run the binary inside a small container. This is
convenient, but remember that mounting `/var/run/docker.sock` gives the
container host-level Docker control.

For temporary debugging only:

```bash
nohup ./opsagent > opsagent.log 2>&1 &
```
