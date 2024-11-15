use std::sync::LazyLock;

use anyhow::Result;
use deadpool_sqlite::{Config, Pool, Runtime};
use serde::{Deserialize, Serialize};
use serde_rusqlite::*;

/// SQlite connection pool singleton
pub static DB: LazyLock<Pool> = LazyLock::new(|| {
    let cfg = Config::new("posts.sqlite3");
    cfg.create_pool(Runtime::Tokio1)
        .expect("failed to initialize pool")
});

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

pub async fn init() -> Result<()> {
    let conn = DB.get().await?;
    if let Ok(conn) = conn.try_lock() {
        let _ = conn.execute(
            "CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY,
                user TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );",
            (),
        );
    }

    Ok(())
}

pub(crate) async fn get_all_posts() -> anyhow::Result<Vec<Post>> {
    let conn = DB.get().await?;
    if let Ok(conn) = conn.try_lock() {
        let mut stmt = conn
            .prepare_cached("SELECT * FROM posts")
            .expect("failed to cache statement");
        let rows = stmt
            .query_and_then([], from_row::<Post>)
            .expect("failed to query posts");
        //.expect("failed to serialize post records");

        // TODO: I have no idea why this repack is needed to be honest
        // I'm sure it should be possible to just deserialize rows query using serde_rusqlite
        let mut posts = Vec::new();
        for post_result in rows {
            posts.push(post_result?);
        }

        return Ok(posts);
    }

    Ok(Default::default())
}

pub(crate) async fn delete_post(id: u32) -> anyhow::Result<()> {
    let conn = DB.get().await?;
    if let Ok(conn) = conn.try_lock() {
        let mut stmt = conn
            .prepare_cached("DELETE FROM posts WHERE id=(?1)")
            .expect("failed to cache statement");
        let _ = stmt.execute([id]).expect("failed to add post");
        return Ok(());
    }

    Err(anyhow::format_err!(
        "Could not lock on pool for some reason"
    ))
}

pub(crate) async fn add_post(post: NewPost) -> anyhow::Result<()> {
    let conn = DB.get().await?;
    if let Ok(conn) = conn.try_lock() {
        let mut stmt = conn
            .prepare_cached(
                r#"
                INSERT INTO posts (user, content) VALUES (?1, ?2)"#,
            )
            .expect("failed to cache statement");
        let _ = stmt
            .execute([post.user, post.content])
            .expect("failed to add post");
        return Ok(());
    }

    Err(anyhow::format_err!(
        "Could not lock on pool for some reason"
    ))
}

pub(crate) async fn update_post(id: u32, post: NewPost) -> anyhow::Result<()> {
    let conn = DB.get().await?;
    if let Ok(conn) = conn.try_lock() {
        let mut stmt = conn
            .prepare_cached("UPDATE posts SET user=(?2), content=(?3) WHERE id=(?1)")
            .expect("failed to cache statement");
        let _ = stmt
            .execute([id.to_string(), post.user, post.content])
            .expect("failed to add post");
        return Ok(());
    }

    Err(anyhow::format_err!(
        "Could not lock on pool for some reason"
    ))
}

// Update a post (e.g., increase the number of likes)
// Delete a post
//DELETE FROM posts WHERE id = "post_id123";
// Select posts by a specific user
// SELECT * FROM posts WHERE user_id = "user123";
// Select posts with specific tags (hashtags)
//SELECT * FROM posts WHERE "food" IN tags;
