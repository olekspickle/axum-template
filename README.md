# axum-template

![axum-template](https://github.com/user-attachments/assets/a16843e7-7537-4c73-a550-52a37b6fbf73)

### Overview
Template to have something to get-go in some situations

This template provides:
- [x] Axum server(with middleware)
- [x] Askama templates
- [x] Containerization(with compose)
- [x] Greeter page with query param name
- [x] Sqlite backend
- [ ] SurrealDB backend

## Running
```bash
# Sqlite3 backend:
make run

# surrealdb backend
make surreal

```

You can peek into Makefile for build details

### Afterthoughts and issues
I found axum to be the most ergonomic web framework out there, and while there might be not
enough examples at the moment, it is quite a breeze to use
- static files was sure one noticeable pain in the rear to figure out
- surrealdb sure adds complexity, I'm adding it under a feature because sqlite integration is
    so much less crates to compile(190+ vs 500+)

