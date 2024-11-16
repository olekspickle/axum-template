use std::{env, sync::LazyLock};

use surrealdb::{
    engine::remote::ws::{Client, Ws},
    opt::auth::Root,
    RecordId, Surreal,
};

use crate::handlers::{NewPost, Post};

/// SurrealDB connection singleton
//static DB: LazyLock<Surreal<Client>> = LazyLock::new(Surreal::init);

/// SQlite connection pool singleton
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

pub async fn connect() -> anyhow::Result<()> {
    Ok(())
}

pub async fn init_db() -> anyhow::Result<()> {
    // some more fields to experiment with
    //DEFINE FIELD likes       ON TABLE posts TYPE int;       -- Number of likes
    //DEFINE FIELD comments    ON TABLE posts TYPE array;     -- Comments on the post
    //DEFINE FIELD image_url   ON TABLE posts TYPE string;    -- Image URL, if any
    //DEFINE FIELD tags        ON TABLE posts TYPE array;     -- Tags or hashtags
    DB.query(
        "
    DEFINE TABLE post SCHEMAFULL
    PERMISSIONS FOR select, create, update, delete ON TABLE;
    DEFINE FIELD user        ON TABLE posts TYPE string;    -- User handle
    DEFINE FIELD content     ON TABLE posts TYPE string;    -- Post content
    DEFINE FIELD created_at  ON TABLE posts TYPE datetime;  -- Timestamp of post creation
    ",
    )
    .await
    .expect("Surrealdb: failed to init DB");
    Ok(())
}

pub async fn get_all_posts() -> anyhow::Result<Vec<Post>> {
    let posts: Vec<Post> = DB.select("post").await?;
    dbg!(&posts);
    Ok(posts)
}

//Select (Retrieve) all posts
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
//Select (Retrieve) all posts
//SELECT * FROM posts;
// Update a post (e.g., increase the number of likes)
//UPDATE posts SET likes = likes + 1 WHERE id = "post_id123";
// Delete a post
//DELETE FROM posts WHERE id = "post_id123";
// Select posts by a specific user
// SELECT * FROM posts WHERE user_id = "user123";
// Select posts with specific tags (hashtags)
//SELECT * FROM posts WHERE "food" IN tags;
