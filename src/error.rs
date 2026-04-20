use axum::{body::Body, http::StatusCode, response::Response};
use displaydoc::Display;
use sqlx::Error as SqlxError;
#[cfg(feature = "surreal")]
use surrealdb::Error as SurrealError;
#[cfg(feature = "surreal")]
use surrealdb::error::{Api as SurrealApiError, Db as SurrealDbError};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Display, Error, Debug)]
pub enum AppError {
    /// IO: {0}
    IO(#[from] std::io::Error),
    /// Could not create file
    CreateFile,
    /// Failed to form encrypted zip file
    Zip(#[from] zip::result::ZipError),
    /// Failed to serialize/deserialize JSON
    Json(#[from] serde_json::Error),
    /// Failed to execute sqlite query
    #[cfg(feature = "sqlite")]
    Sqlite(#[from] SqlxError),
    /// Failed to execute surrealdb query
    #[cfg(feature = "surreal")]
    #[error(transparent)]
    SurrealDb(#[from] SurrealDbError),
    /// Invalid surrealdb api
    #[cfg(feature = "surreal")]
    #[error(transparent)]
    SurrealApi(#[from] Box<SurrealApiError>),
    /// Surreal connection error
    #[cfg(feature = "surreal")]
    #[error(transparent)]
    Surreal(#[from] SurrealError),
    /// Failed to create project
    CreateProject,
    /// Failed to create post
    CreatePost,
    /// Failed to create team member
    CreateTeamMember,
    /// Entity not found
    NotFound,
}

pub(crate) fn response(status: StatusCode, body_str: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(body_str.to_string().into())
        .expect("Unable to create `hyper::Response`")
}

impl From<AppError> for Response<Body> {
    fn from(val: AppError) -> Self {
        let status_code = match &val {
            #[cfg(feature = "sqlite")]
            AppError::Sqlite(sqlx_err) => match sqlx_err {
                SqlxError::Database(_)
                | SqlxError::InvalidArgument(_)
                | SqlxError::ColumnIndexOutOfBounds { .. } => StatusCode::BAD_REQUEST,
                SqlxError::RowNotFound
                | SqlxError::ColumnNotFound(_)
                | SqlxError::TypeNotFound { .. } => StatusCode::NOT_FOUND,
                err => {
                    tracing::error!(err=?err, "SqlxError");
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            },
            #[cfg(feature = "surreal")]
            AppError::SurrealDb(db_err) => match db_err {
                SurrealDbError::InvalidArguments { .. } => StatusCode::BAD_REQUEST,
                SurrealDbError::TbNotFound { .. }
                | SurrealDbError::IdNotFound { .. }
                | SurrealDbError::PaNotFound { .. } => StatusCode::NOT_FOUND,
                err => {
                    tracing::error!(err=?err, "SurrealDbError");
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            },
            #[cfg(feature = "surreal")]
            AppError::SurrealApi(api_err) => {
                let err = api_err;
                tracing::error!(err=?err, "SurrealApiError");
                StatusCode::INTERNAL_SERVER_ERROR
            }
            AppError::NotFound => StatusCode::NOT_FOUND,
            err => {
                tracing::error!(err=?err, "AppError");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        response(status_code, &val.to_string())
    }
}
