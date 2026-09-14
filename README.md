# axum-template

!<img width="500" height="281" alt="Image" src="https://github.com/user-attachments/assets/9ec00ca7-aa4b-485d-b67b-7db736179b90" />

Axum Template - Portfolio/blog website template

### Overview
Portfolio/blog website template for a company that does software/games projects

This README is the canonical docs — `src/lib.rs` pulls it in with `#![doc = include_str!("../README.md")]`.

This template provides:
- [x] Axum server with middleware
- [x] Askama templates
- [x] Containerization (with compose)
- [x] Portfolio projects management
- [x] Blog with markdown support
- [x] Admin panel with authentication
- [x] SQLite backend (default)
- [x] SurrealDB backend (optional, behind feature flag)
- [x] RBAC (User/Editor/Admin)
- [x] HttpOnly cookie support
- [x] Rate limiting on login
- [x] Enable HTTPS
- [x] Add login page template
- [x] Audit logging
- [x] Secure cookie flag
- [x] Password reset flow
- [x] Remember me checkbox with longer token TTL
- [x] Simple footer with socials

### Quick start
Install [cargo-generate] and run:
```bash
cargo generate olekspickle/axum-template -n my-project
```

## Running
```bash
# SQLite3 backend:
just run

# SurrealDB backend
just run-surreal
```
You can peek into justfile for build details

The compiled Tailwind stylesheet (`static/css/tailwind.css`) is committed, so the site works out of the box.
After editing classes in `templates/` or `static/js/`, rebuild it with `just css` (requires node).

### Configuration
Edit `config.toml` to configure:
- Server host/port
- Database path
- Admin credentials (password is argon2 hashed)
- Site name and tagline

#### Security checklist before exposing the server
- **Set `ADMIN_PASSWORD`** and delete `admin_password` from `config.toml`. The value in
  the file is a dev convenience; the server logs a warning whenever it falls back to it.
  With the SurrealDB backend, set `SURREAL_PASSWORD` the same way.
- **Set `server.trusted_proxy = true` only behind a proxy you control** (nginx, cloudflared).
  It makes login rate limiting trust `X-Real-IP`/`X-Forwarded-For`; with it on and nothing
  in front, clients can pick their own rate limit bucket.
- **Keep `posts.db`, `cert.pem` and `key.pem` out of git.** The database holds password
  hashes and session records.
- **Provide `cert.pem`/`key.pem`** to serve HTTPS. Their presence also flips the auth cookie
  to `Secure` and enables HSTS.
- Password reset tokens are never returned in the HTTP response. Wire an email sender into
  `forgot_password`; debug builds log the reset link to the server console for local testing.

#### Authorization
Routes resolve against the role in the session token:
- `User` (any authenticated team member) - read-only API endpoints.
- `Editor` - the mutating API endpoints as well.
- `Admin` - the admin panel, uploads and the Swagger UI / OpenAPI schema.

A team member's role comes from their `role` field; anything that isn't `Editor` or `Admin`
is treated as `User`.

#### Uploads
`POST /admin/upload` accepts image and video files only (no SVG or HTML, both of which can
execute script from this origin), and the `slug` field is reduced to a safe filename token,
so uploads cannot escape `static/media/`.

### Testing
```bash
just test          # sqlite backend + unit tests
just test-surreal  # starts a throwaway SurrealDB in docker and runs the backend round-trips
```
The SurrealDB tests skip themselves when no server is reachable; point them elsewhere with
`SURREAL_TEST_URL`.

#### Afterthoughts and issues
I found axum to be the most ergonomic web framework out there, and while there might be not
enough examples at the moment, it is quite a breeze to use
- static files was sure one noticeable pain in the rear to figure out
- surrealdb sure adds complexity, I'm adding it under a feature because sqlite integration is
  so much less crates to compile(190+ vs 500+)

### Deploy on Raspberry Pi via Cloudflare Tunnel (dockerless)

1. **Cross-compile for Pi (aarch64):**

   Option A — native toolchain:
   ```bash
   rustup target add aarch64-unknown-linux-gnu
   sudo apt install gcc-aarch64-linux-gnu   # Debian/Ubuntu
   just build-pi
   ```

   Option B — Docker-based (no toolchain to install):
   ```bash
   cargo install cross
   just cross-build-pi
   ```

2. **Copy to Pi:**
   ```bash
   rsync -avz target/aarch64-unknown-linux-gnu/release/axum-template \
              config.toml static/ templates/ systemd/ \
              pi@raspberrypi:~/deploy/
   ```

3. **Run automated setup on Pi:**
   ```bash
   ssh pi@raspberrypi
   cd ~/deploy
   bash systemd/setup.sh
   ```
   The script creates a system user, downloads cloudflared to
   `/opt/axum-template/cf/`, creates symlinks at `/usr/local/bin/cloudflared`
   and `/usr/local/bin/cf`, and installs the app, config and systemd services.
   Then it handles the Cloudflare Tunnel itself: browser login (once), tunnel
   create-or-reuse (idempotent — name collisions between duplicate tunnels are
   detected and cleaned up by ID), credentials install, and DNS routing.
   Set `ADMIN_PASSWORD` in `/etc/axum-template.env` before starting the service.
   Undo everything with `bash systemd/cleanup.sh`.

4. **Tunnel knobs** (all optional, sane defaults):
   ```bash
   # Route DNS to a specific hostname (asked interactively if unset on a tty)
   CF_HOSTNAME=www.example.com bash systemd/setup.sh
   # Custom tunnel name / skip tunnel setup entirely
   CF_TUNNEL_NAME=mysite CF_SKIP_TUNNEL=1 bash systemd/setup.sh
   ```
   If DNS routing fails with code 1003, a stale A/AAAA/CNAME record for that
   hostname already exists — delete it in the dashboard (DNS → Records) and
   re-run, or use an unused subdomain. `re-running the script` is safe: it
   reuses the existing tunnel and patches `config.yml` + the service file to
   match.

Systemd service files are in [`systemd/`](https://github.com/olekspickle/axum-template/tree/main/systemd)

[cargo-generate]: https://github.com/cargo-generate/cargo-generate


License: MIT OR Apache-2.0
