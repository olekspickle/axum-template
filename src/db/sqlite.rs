use super::{NewPost, Post};
use anyhow::Result;
use deadpool_sqlite::{Config, Pool, Runtime};
use serde_rusqlite::*;
use std::sync::LazyLock;
use tracing::debug;

/// SQlite connection pool singleton
pub static DB: LazyLock<Pool> = LazyLock::new(|| {
    let cfg = Config::new("posts.sqlite3");
    debug!("Initializing sqlite connection pool...");
    cfg.create_pool(Runtime::Tokio1)
        .expect("failed to initialize pool")
});

/// Init DB: create posts table
pub async fn init() -> Result<()> {
    let conn = DB.get().await?;
    debug!("Creating posts table...");
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

pub(crate) async fn get_all_posts() -> Result<Vec<Post>> {
    let conn = DB.get().await?;
    if let Ok(conn) = conn.try_lock() {
        let mut stmt = conn.prepare_cached("SELECT * FROM posts LIMIT 100")?;
        let rows = stmt.query_and_then([], from_row::<Post>)?;

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

pub(crate) async fn delete_post(id: u32) -> Result<()> {
    let conn = DB.get().await?;
    if let Ok(conn) = conn.try_lock() {
        let mut stmt = conn.prepare_cached("DELETE FROM posts WHERE id=(?1)")?;
        let _ = stmt.execute([id])?;
        return Ok(());
    }

    Err(anyhow::format_err!(
        "Could not lock on pool for some reason"
    ))
}

pub(crate) async fn add_post(post: NewPost) -> Result<()> {
    let conn = DB.get().await?;
    if let Ok(conn) = conn.try_lock() {
        let mut stmt = conn.prepare_cached(
            r#"
                INSERT INTO posts (user, content) VALUES (?1, ?2)"#,
        )?;
        let _ = stmt.execute([post.user, post.content])?;
        return Ok(());
    }

    Err(anyhow::format_err!(
        "Could not lock on pool for some reason"
    ))
}

pub(crate) async fn update_post(id: u32, post: NewPost) -> Result<()> {
    let conn = DB.get().await?;
    if let Ok(conn) = conn.try_lock() {
        let mut stmt =
            conn.prepare_cached("UPDATE posts SET user=(?2), content=(?3) WHERE id=(?1)")?;
        let _ = stmt.execute([id.to_string(), post.user, post.content])?;
        return Ok(());
    }

    Err(anyhow::format_err!(
        "Could not lock on pool for some reason"
    ))
}
