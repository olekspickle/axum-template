//! Round-trip tests for the SurrealDB backend.
//!
//! Needs a server: `docker run --rm -p 8000:8000 surrealdb/surrealdb:v3 start --user root --pass root memory`
//! Point it elsewhere with SURREAL_TEST_URL. Skipped when nothing is listening.
#![cfg(feature = "surreal")]

use axum_template::config::Config;
use axum_template::db::{Db, NewPost, NewProject, NewTeamMember, create_db};

async fn connect() -> Option<Box<dyn Db>> {
    let mut config = Config::load("config.toml").expect("config");
    config.db.surreal.url =
        std::env::var("SURREAL_TEST_URL").unwrap_or_else(|_| "ws://localhost:8000".into());
    // Isolate each run so repeated tests don't collide on unique indexes.
    config.db.surreal.namespace = format!("test_{}", uuid::Uuid::new_v4().simple());

    match create_db(&config).await {
        Ok(db) => {
            db.init().await.expect("init");
            Some(db)
        }
        Err(e) => {
            eprintln!("skipping surreal tests, no server reachable: {e:?}");
            None
        }
    }
}

fn new_post(slug: &str, published: bool) -> NewPost {
    NewPost {
        title: "Title".into(),
        slug: slug.into(),
        content: "content".into(),
        excerpt: "excerpt".into(),
        cover_image: "cover.png".into(),
        tags: vec!["rust".into()],
        author: "author".into(),
        published,
    }
}

#[tokio::test]
async fn post_round_trip() {
    let Some(db) = connect().await else { return };

    let created = db
        .create_post(new_post("hello", true))
        .await
        .expect("create");
    assert!(!created.id.is_empty());

    let fetched = db.get_post(&created.id).await.expect("get").expect("some");
    assert_eq!(fetched.title, "Title");

    let by_slug = db.get_post_by_slug("hello").await.expect("by slug");
    assert!(by_slug.is_some());

    let mut update = new_post("hello", true);
    update.title = "Updated".into();
    db.update_post(&created.id, update).await.expect("update");
    let fetched = db.get_post(&created.id).await.expect("get").expect("some");
    assert_eq!(fetched.title, "Updated", "update must actually persist");
    assert_eq!(
        fetched.created_at, created.created_at,
        "update must preserve created_at"
    );

    db.delete_post(&created.id).await.expect("delete");
    assert!(db.get_post(&created.id).await.expect("get").is_none());
}

#[tokio::test]
async fn drafts_are_not_published() {
    let Some(db) = connect().await else { return };

    db.create_post(new_post("draft", false))
        .await
        .expect("create");

    assert!(
        db.get_post_by_slug("draft")
            .await
            .expect("admin lookup")
            .is_some(),
        "admin lookup sees drafts"
    );
    assert!(
        db.get_published_post_by_slug("draft")
            .await
            .expect("public lookup")
            .is_none(),
        "public lookup must not serve drafts"
    );
    assert!(db.get_published_posts().await.expect("list").is_empty());
}

#[tokio::test]
async fn project_round_trip() {
    let Some(db) = connect().await else { return };

    let created = db
        .create_project(NewProject {
            title: "Proj".into(),
            slug: "proj".into(),
            description: "desc".into(),
            category: "web".into(),
            thumbnail_url: "t.png".into(),
            images: vec![],
            tech_stack: vec!["rust".into()],
            demo_url: None,
            repo_url: None,
            featured: true,
        })
        .await
        .expect("create");

    assert!(db.get_project(&created.id).await.expect("get").is_some());
    assert_eq!(db.get_featured_projects().await.expect("featured").len(), 1);

    let mut update = NewProject {
        title: "Renamed".into(),
        ..Default::default()
    };
    update.slug = "proj".into();
    db.update_project(&created.id, update)
        .await
        .expect("update");
    let fetched = db
        .get_project(&created.id)
        .await
        .expect("get")
        .expect("some");
    assert_eq!(fetched.title, "Renamed");

    db.delete_project(&created.id).await.expect("delete");
    assert!(db.get_project(&created.id).await.expect("get").is_none());
}

#[tokio::test]
async fn token_round_trip() {
    let Some(db) = connect().await else { return };

    db.save_token(
        "digest-1",
        "alice",
        "Admin",
        "2026-01-01T00:00:00Z",
        "2030-01-01T00:00:00Z",
    )
    .await
    .expect("save");

    let found = db.get_token("digest-1").await.expect("get").expect("some");
    assert_eq!(found.0, "alice");
    assert_eq!(found.1, "Admin");

    // Re-saving the same digest must not blow up on the unique index.
    db.save_token(
        "digest-1",
        "alice",
        "Admin",
        "2026-01-01T00:00:00Z",
        "2031-01-01T00:00:00Z",
    )
    .await
    .expect("resave");

    db.save_token(
        "digest-2",
        "bob",
        "Editor",
        "2026-01-01T00:00:00Z",
        "2026-01-02T00:00:00Z",
    )
    .await
    .expect("save expired");
    db.cleanup_expired_tokens("2027-01-01T00:00:00Z")
        .await
        .expect("cleanup");
    assert!(db.get_token("digest-2").await.expect("get").is_none());

    db.delete_token("digest-1").await.expect("delete");
    assert!(db.get_token("digest-1").await.expect("get").is_none());
}

#[tokio::test]
async fn team_member_password_update() {
    let Some(db) = connect().await else { return };

    db.create_team_member(NewTeamMember {
        name: "carol".into(),
        role: "Editor".into(),
        bio: "bio".into(),
        password: Some("initial-password".into()),
        ..Default::default()
    })
    .await
    .expect("create");

    let member = db
        .get_team_member("carol")
        .await
        .expect("get")
        .expect("some");
    let original = member.password_hash.clone().expect("hash stored");

    db.update_team_member_password("carol", "new-hash")
        .await
        .expect("update");

    let member = db
        .get_team_member("carol")
        .await
        .expect("get")
        .expect("some");
    assert_eq!(member.password_hash.as_deref(), Some("new-hash"));
    assert_ne!(member.password_hash, Some(original));
}
