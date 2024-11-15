//! ## surrealDB api wrappers
//!
//! [Rust SDK reference](https://surrealdb.com/docs/sdk/rust)
use crate::handlers::{NewPost, Post};
use std::{env, sync::LazyLock};
use surrealdb::{
    engine::remote::ws::{Client, Ws},
    opt::auth::Root,
    RecordId, Surreal,
};

/// SurrealDB connection singleton
/// TODO: should be possible to marry the deadpool with it in the future
/// There IS a crate for it: https://docs.rs/deadpool-surrealdb/latest/deadpool_surrealdb/
/// but one guy wrote it, the other has published, it is a mess
pub static DB: LazyLock<Surreal<Client>> = LazyLock::new(|| {
    tracing::debug!(endpoint=%SURREAL_URL.clone(), "trying to connect to DB");
    let db = Surreal::init();
    // Connect to the server
    db.connect::<Ws>(SURREAL_URL.clone()).await?;

    // Signin as a namespace, database, or root user
    db.signin(Root {
        username: &SURREAL_USER,
        password: &SURREAL_PASS,
    })
    .await?;
    db.use_ns("test").use_db("actix-template").await?;

    db
});

/// Fetch SURREAL_URL var or substitute with local
static SURREAL_URL: LazyLock<String> =
    LazyLock::new(|| env::var("SURREALDB_URL").unwrap_or("localhost:8000".into()));
static SURREAL_USER: LazyLock<String> =
    LazyLock::new(|| env::var("SURREALDB_USER").unwrap_or("root".into()));
static SURREAL_PASS: LazyLock<String> =
    LazyLock::new(|| env::var("SURREALDB_PASS").unwrap_or("root".into()));

pub async fn init() -> anyhow::Result<()> {
    // some more fields to experiment with
    //DEFINE FIELD likes       ON TABLE posts TYPE int;       -- Number of likes
    //DEFINE FIELD comments    ON TABLE posts TYPE array;     -- Comments on the post
    //DEFINE FIELD image_url   ON TABLE posts TYPE string;    -- Image URL, if any
    //DEFINE FIELD tags        ON TABLE posts TYPE array;     -- Tags or hashtags
    DB.query(
        "
        DEFINE TABLE IF NOT EXISTS posts SCHEMAFULL
        // create/select only when authorized and update/delete only
        // the records authenticated connection created
        PERMISSIONS FOR
        CREATE, SELECT WHERE $auth,
        FOR UPDATE, DELETE WHERE created_by = $auth;
        // username
        DEFINE FIELD IF NOT EXISTS user        ON TABLE posts TYPE string;
        // post content
        DEFINE FIELD IF NOT EXISTS content     ON TABLE posts TYPE string;
        // timestamp post was created at
        DEFINE FIELD IF NOT EXISTS created_at  ON TABLE posts TYPE datetime;
        // authenticated connection id
        DEFINE FIELD IF NOT EXISTS created_by ON TABLE person VALUE $auth READONLY;
    ",
    )
    .await?;
    Ok(())
}

pub async fn get_all_posts() -> anyhow::Result<Vec<Post>> {
    let posts: Vec<Post> = DB.select("post").await?;
    dbg!(&posts);
    Ok(posts)
}

pub async fn add_post(post: NewPost) -> anyhow::Result<()> {
    // some more fields to experiment with
    // "likes": 0,
    // "comments": [],
    // "image_url": "https://example.com/image.jpg",
    // "tags": ["food", "lunch", "amazing"]
    let created: Option<RecordId> = DB.create("post").content(post).await?;
    let id = created.unwrap_or_default();
    tracing::debug!(id, "Inserted new post");
    Ok(())
}
