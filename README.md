# axum-template

!<img width="500" height="281" alt="Image" src="https://github.com/user-attachments/assets/9ec00ca7-aa4b-485d-b67b-7db736179b90" />

Axum Template - Portfolio/blog website template

### Overview
Portfolio/blog website template for a company that does software/games projects

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

### Configuration
Edit `config.toml` to configure:
- Server host/port
- Database path
- Admin credentials (password is argon2 hashed)
- Site name and tagline

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
   bash setup-pi.sh
   ```
   The script downloads cloudflared to `/opt/axum-template/cf/`, creates
   symlinks at `/usr/local/bin/cloudflared` and `/usr/local/bin/cf`, sets
   up config directories, installs systemd services, and prompts for ADMIN_PASSWORD.

4. **Configure Cloudflare Tunnel (one-time):**
   ```bash
   # Authenticate cloudflared as the dedicated user
   sudo -u cloudflared /opt/axum-template/cf/cloudflared tunnel login

   # Create tunnel and DNS route
   sudo -u cloudflared /opt/axum-template/cf/cloudflared tunnel create axum-template
   sudo -u cloudflared /opt/axum-template/cf/cloudflared tunnel route dns axum-template your-domain.com

   # Edit config with actual tunnel name and domain
   sudo $EDITOR /opt/axum-template/cf/config.yml

   # Start services
   sudo systemctl start axum-template.service
   sudo systemctl start cloudflared.service
   ```

Systemd service files are in [`systemd/`](https://github.com/olekspickle/axum-template/tree/main/systemd)

[cargo-generate]: https://github.com/cargo-generate/cargo-generate


License: MIT OR Apache-2.0
