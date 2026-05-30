// Copy template files to root, stripping .template extension
file::rename(".generate/Cargo.toml.template", "Cargo.toml");
file::rename(".generate/README.md.template", "README.md");
file::rename(".generate/justfile.template", "justfile");
file::rename(".generate/src/lib.rs.template", "src/lib.rs");
file::rename(".generate/src/main.rs.template", "src/main.rs");
file::rename(".generate/.github/workflows/release.yaml.template", ".github/workflows/release.yaml");
file::rename(".generate/templates/head.html.template", "templates/head.html");
file::rename(".generate/Dockerfile.template", "docker/Dockerfile.run");

// Copy systemd files (dir already exists from template root)
file::rename(".generate/systemd/axum-template.service.template", "systemd/" + variable::get("project-name") + ".service");

// Only copy Cloudflare Tunnel files if domain was provided
let domain = variable::get("domain");
if domain != "" {
    file::rename(".generate/systemd/cloudflared.service.template", "systemd/cloudflared.service");
    file::rename(".generate/systemd/cloudflared-config.yml.template", "systemd/cloudflared-config.yml");
    file::rename(".generate/systemd/setup.sh.template", "systemd/setup.sh");
}

// Clean up .generate directory
file::delete(".generate");
