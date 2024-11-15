use serde::{Deserialize, Serialize};

#[cfg(feature = "sqlite")]
mod sqlite;
#[cfg(feature = "surreal")]
mod surreal;

#[cfg(feature = "sqlite")]
pub use sqlite::{};
#[cfg(feature = "surreal")]
pub use surreal::{};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(crate) struct NewPost {
    user: String,
    content: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(crate) struct Post {
    pub id: u32,
    pub user: String,
    pub created_at: String,
    pub content: String,
}
