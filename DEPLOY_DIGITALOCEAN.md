# Deploying to a DigitalOcean Droplet

This guide brings the Composio Toolkit Ops control plane up on a single Ubuntu
Droplet using Docker Compose and Caddy.

```
Internet ──▶ Caddy (:80 / :443, automatic HTTPS)
               ├─ /api/ops/* ─▶ web  (Next.js route handlers)
               ├─ /api/*     ─▶ api  (FastAPI control plane)
               └─ everything ─▶ web  (Next.js UI)

web ⇄ api communicate only on the private "opsnet" Docker network.
Persistent SQLite state lives in the ops_data volume, mounted at /data.
```

Only the reverse proxy is published. Ports **8000** (api) and **3000** (web) are
never exposed publicly.

> Security note: this control plane has no built-in user authentication (it is
> designed as an owner-operated tool). Anything reachable on the public domain is
> reachable by anyone who finds it. Restrict access with the Cloud Firewall,
> keep the domain private, and consider adding proxy-level access control before
> exposing it broadly. The browser never calls the API directly — Next.js proxies
> server-side — so you may also choose to drop the public `/api/*` route in
> `deploy/Caddyfile` and expose only the UI.

Do not commit `.env.production`, real domains, IPs, or provider keys anywhere.

---

## 1. Create the Droplet

1. In the DigitalOcean control panel: **Create → Droplets**.
2. Choose **Ubuntu 24.04 LTS**.
3. Size: a 2 GB / 1 vCPU basic Droplet is a reasonable starting point (the
   Next.js production build benefits from >= 2 GB RAM).
4. **Authentication → SSH keys**: add your public SSH key. Avoid password login.
5. (Optional) Enable **Backups** for automated Droplet-level snapshots.
6. Create the Droplet.

### Reserved (static) IP

If you want a stable address that survives Droplet rebuilds, go to
**Networking → Reserved IPs** and assign one to the Droplet. Use this IP for the
DNS record below.

---

## 2. Cloud Firewall

Create a firewall under **Networking → Firewalls** and attach it to the Droplet.

Inbound rules:

| Type  | Protocol | Port | Sources                    |
| ----- | -------- | ---- | -------------------------- |
| SSH   | TCP      | 22   | Your admin IP only         |
| HTTP  | TCP      | 80   | All IPv4 / All IPv6        |
| HTTPS | TCP      | 443  | All IPv4 / All IPv6        |

- Do **not** open 8000 or 3000.
- Restrict SSH (22) to your own IP address.
- Leave all other inbound ports denied (default).
- Outbound: leave the default allow-all so the Droplet can fetch packages,
  certificates, and reach configured providers.

---

## 3. Install Docker Engine + Compose plugin

SSH into the Droplet, then install Docker using the current official steps at
<https://docs.docker.com/engine/install/ubuntu/>. Summary (verify against the
official page, as it changes over time):

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

Verify:

```bash
docker --version
docker compose version
```

(Optional) allow your user to run Docker without sudo:

```bash
sudo usermod -aG docker "$USER"   # log out / back in for this to take effect
```

---

## 4. Clone the repository securely

Use SSH deploy keys or a short-lived token; do not embed long-lived credentials
in the Droplet.

```bash
git clone git@github.com:<owner>/<repo>.git composio-toolkit-ops-agent
cd composio-toolkit-ops-agent
```

---

## 5. Create `.env.production`

```bash
cp .env.production.example .env.production
```

Edit `.env.production` and set:

- `DOMAIN` — your real hostname (e.g. the record you create in step 6).
- `OPS_CORS_ORIGINS` — `https://<your-domain>`.
- Encryption keys — generate each **independently**:

  ```bash
  # SECRET_VAULT_KEY (Fernet, url-safe base64, 32 bytes):
  python -c "import base64,os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"

  # LANGGRAPH_AES_KEY (32-byte hex):
  python -c "import os; print(os.urandom(32).hex())"
  ```

- Provider keys (`PERPLEXITY_API_KEY`, `GOOGLE_GENAI_API_KEY`, `COMPOSIO_API_KEY`,
  `COMPOSIO_GMAIL_CONNECTED_ACCOUNT_ID`, `BROWSER_USE_API_KEY`) — only if you
  intend to run live provider work. Leave blank otherwise.

Keep the safety defaults: `OPS_ENABLE_API_DOCS=false`, `ALLOW_LIVE_VENDOR_EMAIL=false`,
`RUN_LIVE_TESTS=0`.

> Keep `SECRET_VAULT_KEY` and `LANGGRAPH_AES_KEY` stable across redeployments. If
> they change, previously stored secrets and checkpoints become unreadable.

---

## 6. Point DNS at the Droplet

At your DNS provider, create an **A record** for your hostname pointing at the
Droplet's (reserved) IPv4 address. Wait for it to resolve before deploying so
Caddy can complete the HTTPS certificate challenge:

```bash
dig +short <your-domain>
```

---

## 7. Deploy

```bash
./scripts/deploy-droplet.sh
```

The script verifies Docker, validates the Compose file, builds images, starts
services, and waits for health checks. It prints sanitized status only.

---

## 8. Verify

```bash
# Frontend (through the proxy):
curl -fsS https://<your-domain>/ -o /dev/null -w '%{http_code}\n'

# API health (through the proxy):
curl -fsS https://<your-domain>/api/system/health

# Container health:
docker compose -f compose.prod.yaml ps

# Logs (no secrets are logged):
docker compose -f compose.prod.yaml logs --tail=100 caddy
docker compose -f compose.prod.yaml logs --tail=100 web
docker compose -f compose.prod.yaml logs --tail=100 api
```

All three containers should report `healthy`.

### HTTP / IP-only fallback (no domain yet)

Set `DOMAIN=:80` in `.env.production` and redeploy. Caddy then serves plain HTTP
on port 80 with no certificate. Reach the app at `http://<droplet-ip>/`. This is
for bring-up only — there is no transport encryption, so do not enter real
credentials or run provider work in this mode.

---

## 9. Update an existing deployment

```bash
./scripts/update-droplet.sh main      # or another branch
```

This pulls the branch, rebuilds, and rolls out without deleting volumes.

### Rollback

Persistent volumes are never touched by updates, so rolling back is a code-only
operation:

```bash
git fetch --tags origin
git checkout <previous-good-tag-or-commit>
docker compose -f compose.prod.yaml --env-file .env.production up -d --build
```

---

## 10. Backup and restore persistent data

Backup (optionally quiesce the API for an application-consistent snapshot):

```bash
./scripts/backup-production-data.sh --quiesce
# archive written to ./backups/ops-data-<timestamp>.tar.gz
```

Restore into the volume (stop the API first so nothing is writing):

```bash
docker compose -f compose.prod.yaml stop api
docker run --rm \
  -v composio-ops-prod_ops_data:/data \
  -v "$(pwd)/backups:/backup:ro" \
  busybox sh -c "rm -rf /data/* && tar xzf /backup/ops-data-<timestamp>.tar.gz -C /data"
docker compose -f compose.prod.yaml start api
```

> Application-consistent SQLite backups may require briefly stopping writers or
> checkpointing the WAL. The `--quiesce` flag stops the `api` service for the
> duration of the archive.

---

## 11. Rotate secrets

- **Provider keys** (Perplexity, Google/Gemini, Composio, Browser Use): update
  the value in `.env.production`, then `docker compose -f compose.prod.yaml up -d`
  to recreate the `api` container with the new environment.
- **`LANGGRAPH_AES_KEY` / `SECRET_VAULT_KEY`**: rotating these invalidates any
  data encrypted with the old key. Only rotate as part of a deliberate migration
  where existing vault entries and checkpoints are re-created; otherwise keep
  them stable. Back up first.
- After rotating, confirm health per step 8 and remove any old key material from
  shell history and local copies.

---

## Operational reminders

- Never expose ports 8000 or 3000 publicly.
- Never commit `.env.production` or place provider keys in `NEXT_PUBLIC_` vars.
- Keep the SSH firewall rule scoped to your admin IP.
- Renewals are automatic; keep the `caddy_data` volume intact to avoid
  re-issuing certificates.
