# axum-template

![axum-template](https://private-user-images.githubusercontent.com/22867443/395807393-714f8d47-1e8e-4544-8516-67270985d916.gif?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MzQxOTc1MzcsIm5iZiI6MTczNDE5NzIzNywicGF0aCI6Ii8yMjg2NzQ0My8zOTU4MDczOTMtNzE0ZjhkNDctMWU4ZS00NTQ0LTg1MTYtNjcyNzA5ODVkOTE2LmdpZj9YLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPUFLSUFWQ09EWUxTQTUzUFFLNFpBJTJGMjAyNDEyMTQlMkZ1cy1lYXN0LTElMkZzMyUyRmF3czRfcmVxdWVzdCZYLUFtei1EYXRlPTIwMjQxMjE0VDE3MjcxN1omWC1BbXotRXhwaXJlcz0zMDAmWC1BbXotU2lnbmF0dXJlPTc4MzhmOWQ4YWNlMGExZTliYmFjODMxNGQ1MWE1M2IyNWU0OGUzODVhNjY2MzJiY2JmM2FlNDU5YzE5OTc0ZjgmWC1BbXotU2lnbmVkSGVhZGVycz1ob3N0In0.I16zH9fwBo7N99jlqEtMzHl0ZjFOGrWX0UlXZs0xNFc)

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

