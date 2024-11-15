use thiserror::Error;

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub(crate) enum Error {
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error("Could not create file")]
    CreateFile,
    #[error(transparent)]
    Zip(#[from] zip::result::ZipError),
    #[cfg(feature = "sqlite")]
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[cfg(feature = "surreal")]
    #[error(transparent)]
    Surreal(#[from] surrealdb::error::Error),
}
