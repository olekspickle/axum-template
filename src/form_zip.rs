use std::{env, fs, io::Write, process::Command};

use crate::error::Result;

use tracing::{trace, warn};
use zip::{write::SimpleFileOptions, AesMode};

pub(crate) const FILE: &str = "my.txt";
pub(crate) const ZIP: &str = "my.zip";

pub fn create_zip() -> Result<()> {
    let Ok(file) = fs::File::create(ZIP).inspect_err(|e| warn!("create file {e}")) else {
        return Err(crate::error::Error::CreateFile);
    };
    let mut zip = zip::ZipWriter::new(file);
    let secret = env::var("SECRET").unwrap_or_else(|_| "test".into());
    let opts = SimpleFileOptions::default().with_aes_encryption(AesMode::Aes256, &secret);

    zip.start_file(FILE, opts)
        .inspect_err(|e| warn!("create file in zip {e}"))?;
    zip.write_all(b"============MACHINE INFO==============")?;
    // will fail in docker
    match Command::new("docker").args(["system", "df", "-v"]).output() {
        Ok(info) => {
            trace!("writing docker info to the zip");
            zip.write_all(&info.stdout)?;
        }
        Err(e) => warn!(err=%e.to_string(), "Failed to query docker info"),
    }

    Ok(())
}
