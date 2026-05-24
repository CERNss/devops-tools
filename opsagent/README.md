# opsagent

`opsagent` exposes signed HTTP APIs for webhook-driven Docker Compose deployment,
file rendering, container health checks, and Nginx Proxy Manager proxy host
operations.

## Authentication

Every mutating API request must include:

- `X-Timestamp`: Unix seconds.
- `X-Signature`: `sha256=<hex hmac>`.

The HMAC payload is:

```text
<X-Timestamp>.<raw request body>
```

Use `AGENT_SECRET` as the HMAC-SHA256 key. Signed timestamps are accepted within
a five minute window.

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
