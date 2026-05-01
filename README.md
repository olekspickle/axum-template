# axum-template

![axum-template demo](https://github.com/user-attachments/assets/a16843e7-7537-4c73-a550-52a37b6fbf73)
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


## Running
```bash
# SQLite3 backend:
make run

# SurrealDB backend
make surreal
```
You can peek into Makefile for build details

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


License: MIT OR Apache-2.0
