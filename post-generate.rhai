// Copy template files to root, stripping .template extension
file::rename(".template/Cargo.toml.template", "Cargo.toml");
file::rename(".template/README.md.template", "README.md");
file::rename(".template/justfile.template", "justfile");
file::rename(".template/src/lib.rs.template", "src/lib.rs");
file::rename(".template/src/main.rs.template", "src/main.rs");
file::rename(".template/.github/workflows/release.yaml.template", ".github/workflows/release.yaml");
file::rename(".template/templates/head.html.template", "templates/head.html");
file::rename(".template/Dockerfile.template", "docker/Dockerfile.run");

// Copy systemd files (dir already exists from template root)
file::rename(".template/systemd/axum-template.service.template", "systemd/axum-template.service");

// Only copy Cloudflare Tunnel files if domain was provided
let domain = variable::get("domain");
if domain != "" {
    file::rename(".template/systemd/cloudflared.service.template", "systemd/cloudflared.service");
    file::rename(".template/systemd/cloudflared-config.yml.template", "systemd/cloudflared-config.yml");
    file::rename(".template/systemd/setup-pi.sh.template", "systemd/setup-pi.sh");
}

// Clean up .template directory
file::delete(".template");
