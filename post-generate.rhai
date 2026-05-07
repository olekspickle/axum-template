// Copy template files to root, stripping .template extension
file::rename(".template/Cargo.toml.template", "Cargo.toml");
file::rename(".template/README.md.template", "README.md");
file::rename(".template/justfile.template", "justfile");
file::rename(".template/src/lib.rs.template", "src/lib.rs");
file::rename(".template/.github/workflows/release.yaml.template", ".github/workflows/release.yaml");
file::rename(".template/templates/head.html.template", "templates/head.html");
file::rename(".template/Dockerfile.template", "Dockerfile");

// Clean up .template directory
dir::remove_tree(".template");
