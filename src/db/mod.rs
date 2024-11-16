use serde::{Deserialize, Serialize};

#[cfg(feature = "sqlite")]
mod sqlite;
#[cfg(feature = "surreal")]
mod surreal;

#[cfg(feature = "sqlite")]
pub(crate) use sqlite::{add_post, delete_post, get_all_posts, init, update_post, DB};
#[cfg(feature = "surreal")]
pub(crate) use surreal::{add_post, delete_post, get_all_posts, init, update_post, DB};

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
