use displaydoc::Display;
use thiserror::Error;

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Display, Error, Debug)]
pub(crate) enum Error {
    /// IO: {0}
    IO(#[from] std::io::Error),
    /// Could not create file
    CreateFile,
    /// Failed to form encrypted zip file
    Zip(#[from] zip::result::ZipError),
    /// Failed to execute sqlite query
    #[cfg(feature = "sqlite")]
    Sqlite(#[from] rusqlite::Error),
    /// Failed to execute surrealdb query
    #[cfg(feature = "surreal")]
    #[error(transparent)]
    Surreal(#[from] surrealdb::error::Error),
}
