# Gatepass LLM Proxy

A lightweight, high-performance, rate-limiting, and header-spoofing reverse proxy designed for LLM APIs. 

If your LLM gateway enforces strict rate limits (e.g., `429 Too Many Requests`) or restricts API access to specific developer clients, this proxy lets you **queue incoming requests** in memory and **inject required spoofed headers** (such as specific `User-Agent` or custom authentication metadata) before forwarding them upstream.

---

## Features

- **Token Bucket Rate Limiting with Reservation:** Smooths out incoming request spikes. If you hit your rate limit, the proxy buffers and queues the request in memory rather than returning a `429` error.
- **Client Disconnection Support:** Automatically detects if a client aborts or times out while waiting in the queue. It cancels the queue slot and refunds the reserved token so it isn't wasted on upstream calls.
- **Dynamic Header Injection:** Inject any HTTP headers (such as `User-Agent` or custom API keys/metadata) dynamically using simple environment variables.
- **Zero Dependencies:** Written in standard Go, compiling down to a single self-contained binary.

---

## Potential Use Cases

This proxy acts as a centralized middleware layer between your downline services and upstream LLM providers, unlocking several key architectural patterns:

* **Centralized API Key Management & Decoupling:** Instead of distributing and rotating secret upstream provider keys across all downline applications, configure downline apps to use virtual/internal keys and let the proxy swap them centrally at the edge with `API_KEY_REPLACE`.
* **Dynamic Routing & Model Version Upgrades:** Avoid deploying configuration changes to multiple client apps when upgrading models. By configuring `MODEL_REPLACE` (e.g. mapping `gpt-3.5-turbo` to `gpt-4o-mini`), all downline requests are centrally and transparently mapped to the new model (updating request bodies and URL paths).
* **Client Identification & Header Spoofing:** Some LLM gateways require specific HTTP headers (like a specific `User-Agent`). The proxy lets you spoof these credentials centrally to bypass access restrictions.
* **Resiliency Against Hard Rate Limits (429s):** The token-bucket rate limiter intercepts client requests and buffers/queues them in memory when limits are reached, gradually releasing them to fit upstream quotas instead of failing downstream calls with `429 Too Many Requests`.
* **Central Audits & Cost Analysis:** With all transaction details, response statuses, and raw bodies saved to a local SQLite database, you can centrally audit all LLM traffic, debug payloads, and compute usage costs.

---

## Configuration

Configure the proxy at runtime using the following environment variables:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `PROXY_TARGET_URL` | **Required.** The upstream LLM API base URL to proxy requests to (e.g., `https://api.openai.com` or any custom gateway). | *None* |
| `PROXY_PORT` | The port the proxy server will listen on. | `8318` |
| `RATE_LIMIT_RPM` | Requests per minute to allow. | `20` |
| `RATE_LIMIT_BURST` | The maximum burst capacity (tokens) allowed before queuing kicks in. | `5` |
| `HEADER_<NAME>` | Injects an HTTP header named `NAME` with the specified value. Single underscores are replaced with hyphens (e.g., `HEADER_User_Agent` maps to `User-Agent`). | *None* |
| `INJECT_HEADERS_JSON` | A JSON-formatted string representing a key-value map of headers to inject (useful for complex headers). | *None* |
| `API_KEY_REPLACE` | Maps client API keys to upstream API keys. Replaces keys in standard headers (`Authorization`, `api-key`, `x-api-key`) and query parameters (`key`, `api_key`, `api-key`). Supports comma-separated format (e.g. `client-key-1:upstream-key-1`) or JSON format. | *None* |

---

## How to Run

### Native Go
Build and run the proxy locally:
```bash
# Set configuration env variables and run
export PROXY_TARGET_URL="https://your-upstream-api.com"
export RATE_LIMIT_RPM=20
export RATE_LIMIT_BURST=5
export HEADER_User_Agent="my-custom-client/1.0"

go run main.go
```

### Docker / Podman
Build a minimal, multi-stage Docker container:
```bash
# Build the container
docker build -t gatepass .

# Run the container
docker run -d \
  -p 8318:8318 \
  -e PROXY_TARGET_URL="https://your-upstream-api.com" \
  -e RATE_LIMIT_RPM=20 \
  -e RATE_LIMIT_BURST=5 \
  -e HEADER_User_Agent="my-custom-client/1.0" \
  --name gatepass \
  gatepass
```

---

## Example: Bypassing Client Restrictions

Some API gateways restrict access to official developer command-line tools by matching on specific headers (like `User-Agent` or version keys). You can bypass these restrictions by running this proxy to inject the expected headers.

### 1. Run the Proxy
```bash
export PROXY_TARGET_URL="https://api.upstream-service.com"
export PROXY_PORT="8318"
export RATE_LIMIT_RPM=20
export RATE_LIMIT_BURST=5

# Inject official client spoofing headers
export HEADER_User_Agent="official-cli-client/1.0.0"
export HEADER_X_Client_Version="1.0.0"

go run main.go
```

### 2. Configure Your Client
Point your client tool's base URL to the local proxy:
```bash
export UPSTREAM_BASE_URL="http://localhost:8318"
export UPSTREAM_API_KEY="your-api-key"
cli-tool-run
```

---

## Deployment Options

### 1. Systemd Service (Native Binary)

To run the compiled proxy binary as a background systemd service:

Create `/etc/systemd/system/gatepass.service`:

```ini
[Unit]
Description=Gatepass LLM Proxy
After=network.target

[Service]
ExecStart=/usr/local/bin/gatepass
Restart=always
RestartSec=3
Environment=PROXY_TARGET_URL=https://agentrouter.org
Environment=PROXY_PORT=8318
#Environment=RATE_LIMIT_RPM=20
#Environment=RATE_LIMIT_BURST=5
Environment=HEADER_Originator=codex_cli_rs
Environment="HEADER_User_Agent=codex_cli_rs/0.138.0 (Mac OS 26.0.1; arm64) Apple_Terminal/464"
Environment=HEADER_Version=0.138.0
# Environment=API_KEY_REPLACE="client-key:upstream-key"

[Install]
WantedBy=default.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now gatepass
```

### 2. Podman Quadlet (Containerized)

If you are using Podman, you can manage the container lifecycle through systemd using a Quadlet file.

Create `/etc/containers/systemd/gatepass.container` (or `~/.config/containers/systemd/gatepass.container` for rootless setup):

```ini
[Unit]
Description=Gatepass LLM Proxy Container
After=network.target

[Container]
Image=ghcr.io/rat-s/gatepass:latest
PublishPort=8318:8318
# For system-wide (runs as root, Podman will auto-create the directory):
Volume=/srv/gatepass/data:/data:Z
# For rootless (runs as user, use this instead so Podman can auto-create it in home):
# Volume=%h/.local/share/gatepass/data:/data:Z
Environment=PROXY_TARGET_URL=https://agentrouter.org
Environment=PROXY_PORT=8318
#Environment=RATE_LIMIT_RPM=20
#Environment=RATE_LIMIT_BURST=5
Environment=HEADER_Originator=codex_cli_rs
Environment="HEADER_User_Agent=codex_cli_rs/0.138.0 (Mac OS 26.0.1; arm64) Apple_Terminal/464"
Environment=HEADER_Version=0.138.0
# Environment=API_KEY_REPLACE="client-key:upstream-key"

[Service]
Restart=always

[Install]
WantedBy=default.target
```

Reload systemd to generate the service unit and start it:
```bash
# For system-wide:
sudo systemctl daemon-reload
sudo systemctl enable --now gatepass

# For rootless (run without sudo):
systemctl --user daemon-reload
systemctl --user enable --now gatepass
```

---

## License

This project is open-source and available under the [GNU Affero General Public License v3.0 (AGPLv3)](LICENSE).
