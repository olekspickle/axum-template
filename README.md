# axum-template

![axum-template demo](https://github.com/user-attachments/assets/9ec00ca7-aa4b-485d-b67b-7db736179b90)

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

[cargo-generate]: https://github.com/cargo-generate/cargo-generate


License: MIT OR Apache-2.0
