// Move rendered template files into place, stripping .template extension
file::rename(".generate/Cargo.toml.template", "Cargo.toml");
file::rename(".generate/README.md.template", "README.md");
file::rename(".generate/justfile.template", "justfile");
file::rename(".generate/src/main.rs.template", "src/main.rs");
file::rename(".generate/.github/workflows/release.yaml.template", ".github/workflows/release.yaml");
file::rename(".generate/templates/head.html.template", "templates/head.html");
file::rename(".generate/Dockerfile.template", "docker/Dockerfile.run");
file::rename(".generate/compose.yml.template", "docker/compose.yml");

// systemd: root unit was copied verbatim; replace it with the project-named one
file::delete("systemd/axum-template.service");
file::rename(".generate/systemd/axum-template.service.template", "systemd/" + variable::get("project-name") + ".service");

// Keep Cloudflare Tunnel files only if domain was provided
let domain = variable::get("domain");
if domain != "" {
    file::rename(".generate/systemd/cloudflared.service.template", "systemd/cloudflared.service");
    file::rename(".generate/systemd/cloudflared-config.yml.template", "systemd/cloudflared-config.yml");
    file::rename(".generate/systemd/setup.sh.template", "systemd/setup.sh");
    file::rename(".generate/systemd/cleanup.sh.template", "systemd/cleanup.sh");
} else {
    file::delete("systemd/cloudflared.service");
    file::delete("systemd/cloudflared-config.yml");
    file::delete("systemd/setup.sh");
    file::delete("systemd/cleanup.sh");
}

// Clean up .generate directory
file::delete(".generate");
