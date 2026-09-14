use std::sync::Arc;

use argon2::{Argon2, PasswordHasher};
use surrealdb::types::{RecordId, RecordIdKey, SurrealValue};
use surrealdb::{
    Surreal,
    engine::remote::ws::{Client, Ws, Wss},
    opt::auth::Root,
};
use uuid::Uuid;

use crate::config::{Config, SurrealParams};
use crate::db::{Db, NewPost, NewProject, NewTeamMember, Post, Project, TeamMember};
use crate::error::{AppError, Result};

pub struct SurrealDb {
    db: Arc<Surreal<Client>>,
}

/// Records come back with a real record id (`post:abc`) while the rest of the app
/// works with plain string ids, so rows are mapped on the way in and out.
fn record_key(id: &RecordId) -> String {
    match &id.key {
        RecordIdKey::String(key) => key.clone(),
        RecordIdKey::Uuid(key) => key.to_string(),
        RecordIdKey::Number(key) => key.to_string(),
        // Array/object/range keys aren't used by this app.
        other => format!("{other:?}"),
    }
}

#[derive(SurrealValue)]
struct ProjectRow {
    id: RecordId,
    title: String,
    slug: String,
    description: String,
    category: String,
    thumbnail_url: String,
    images: Vec<String>,
    tech_stack: Vec<String>,
    demo_url: Option<String>,
    repo_url: Option<String>,
    featured: bool,
    created_at: String,
    updated_at: String,
}

/// The same fields minus `id`: the record id is addressed separately and must not
/// be written as a field.
#[derive(SurrealValue)]
struct ProjectContent {
    title: String,
    slug: String,
    description: String,
    category: String,
    thumbnail_url: String,
    images: Vec<String>,
    tech_stack: Vec<String>,
    demo_url: Option<String>,
    repo_url: Option<String>,
    featured: bool,
    created_at: String,
    updated_at: String,
}

impl From<ProjectRow> for Project {
    fn from(r: ProjectRow) -> Self {
        Project {
            id: record_key(&r.id),
            title: r.title,
            slug: r.slug,
            description: r.description,
            category: r.category,
            thumbnail_url: r.thumbnail_url,
            images: r.images,
            tech_stack: r.tech_stack,
            demo_url: r.demo_url,
            repo_url: r.repo_url,
            featured: r.featured,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

impl ProjectContent {
    fn new(p: NewProject, created_at: String, updated_at: String) -> Self {
        Self {
            title: p.title,
            slug: p.slug,
            description: p.description,
            category: p.category,
            thumbnail_url: p.thumbnail_url,
            images: p.images,
            tech_stack: p.tech_stack,
            demo_url: p.demo_url,
            repo_url: p.repo_url,
            featured: p.featured,
            created_at,
            updated_at,
        }
    }
}

#[derive(SurrealValue)]
struct PostRow {
    id: RecordId,
    title: String,
    slug: String,
    content: String,
    excerpt: String,
    cover_image: String,
    tags: Vec<String>,
    author: String,
    published: bool,
    created_at: String,
    updated_at: String,
}

#[derive(SurrealValue)]
struct PostContent {
    title: String,
    slug: String,
    content: String,
    excerpt: String,
    cover_image: String,
    tags: Vec<String>,
    author: String,
    published: bool,
    created_at: String,
    updated_at: String,
}

impl From<PostRow> for Post {
    fn from(r: PostRow) -> Self {
        Post {
            id: record_key(&r.id),
            title: r.title,
            slug: r.slug,
            content: r.content,
            excerpt: r.excerpt,
            cover_image: r.cover_image,
            tags: r.tags,
            author: r.author,
            published: r.published,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

impl PostContent {
    fn new(p: NewPost, created_at: String, updated_at: String) -> Self {
        Self {
            title: p.title,
            slug: p.slug,
            content: p.content,
            excerpt: p.excerpt,
            cover_image: p.cover_image,
            tags: p.tags,
            author: p.author,
            published: p.published,
            created_at,
            updated_at,
        }
    }
}

#[derive(SurrealValue)]
struct TeamMemberRow {
    id: RecordId,
    name: String,
    role: String,
    bio: String,
    photo_url: Option<String>,
    github_url: Option<String>,
    twitter_url: Option<String>,
    linkedin_url: Option<String>,
    password_hash: Option<String>,
    created_at: String,
}

#[derive(SurrealValue)]
struct TeamMemberContent {
    name: String,
    role: String,
    bio: String,
    photo_url: Option<String>,
    github_url: Option<String>,
    twitter_url: Option<String>,
    linkedin_url: Option<String>,
    password_hash: Option<String>,
    created_at: String,
}

impl From<TeamMemberRow> for TeamMember {
    fn from(r: TeamMemberRow) -> Self {
        TeamMember {
            id: record_key(&r.id),
            name: r.name,
            role: r.role,
            bio: r.bio,
            photo_url: r.photo_url,
            github_url: r.github_url,
            twitter_url: r.twitter_url,
            linkedin_url: r.linkedin_url,
            password_hash: r.password_hash,
            created_at: r.created_at,
        }
    }
}

/// Stored under the token digest as record key - the raw token is never persisted.
#[derive(SurrealValue)]
struct TokenRow {
    username: String,
    role: String,
    created_at: String,
    expiry: String,
}

impl SurrealDb {
    pub async fn connect(cfg: &Config) -> Result<Self> {
        let SurrealParams {
            url,
            name,
            username,
            password,
            namespace,
        } = &cfg.db.surreal;
        let db: Surreal<Client> = Surreal::init();

        // The Ws/Wss engines take a bare `host:port`; handing them a full URL makes
        // them resolve "ws://host:port" as a hostname and fail.
        let (secure, endpoint) = match url.split_once("://") {
            Some(("wss" | "https", rest)) => (true, rest),
            Some((_, rest)) => (false, rest),
            None => (false, url.as_str()),
        };
        let endpoint = endpoint.trim_end_matches('/');

        if secure {
            db.connect::<Wss>(endpoint).await?;
        } else {
            db.connect::<Ws>(endpoint).await?;
        }

        db.signin(Root {
            username: username.clone(),
            password: password.clone(),
        })
        .await?;
        db.use_ns(namespace).use_db(name).await?;

        tracing::info!(db=%url, "Database initialized");
        Ok(Self { db: Arc::new(db) })
    }
}

#[async_trait::async_trait]
impl Db for SurrealDb {
    async fn init(&self) -> Result<()> {
        self.db
            .query(
                r#"
                DEFINE TABLE IF NOT EXISTS project SCHEMAFULL;
                DEFINE FIELD IF NOT EXISTS title ON TABLE project TYPE string;
                DEFINE FIELD IF NOT EXISTS slug ON TABLE project TYPE string;
                DEFINE FIELD IF NOT EXISTS description ON TABLE project TYPE string;
                DEFINE FIELD IF NOT EXISTS category ON TABLE project TYPE string;
                DEFINE FIELD IF NOT EXISTS thumbnail_url ON TABLE project TYPE string;
                DEFINE FIELD IF NOT EXISTS images ON TABLE project TYPE array<string>;
                DEFINE FIELD IF NOT EXISTS tech_stack ON TABLE project TYPE array<string>;
                DEFINE FIELD IF NOT EXISTS demo_url ON TABLE project TYPE option<string>;
                DEFINE FIELD IF NOT EXISTS repo_url ON TABLE project TYPE option<string>;
                DEFINE FIELD IF NOT EXISTS featured ON TABLE project TYPE bool;
                DEFINE FIELD IF NOT EXISTS created_at ON TABLE project TYPE string;
                DEFINE FIELD IF NOT EXISTS updated_at ON TABLE project TYPE string;
                DEFINE INDEX IF NOT EXISTS project_slug ON TABLE project COLUMNS slug UNIQUE;
                "#,
            )
            .await?
            .check()?;

        self.db
            .query(
                r#"
                DEFINE TABLE IF NOT EXISTS post SCHEMAFULL;
                DEFINE FIELD IF NOT EXISTS title ON TABLE post TYPE string;
                DEFINE FIELD IF NOT EXISTS slug ON TABLE post TYPE string;
                DEFINE FIELD IF NOT EXISTS content ON TABLE post TYPE string;
                DEFINE FIELD IF NOT EXISTS excerpt ON TABLE post TYPE string;
                DEFINE FIELD IF NOT EXISTS cover_image ON TABLE post TYPE string;
                DEFINE FIELD IF NOT EXISTS tags ON TABLE post TYPE array<string>;
                DEFINE FIELD IF NOT EXISTS author ON TABLE post TYPE string;
                DEFINE FIELD IF NOT EXISTS published ON TABLE post TYPE bool;
                DEFINE FIELD IF NOT EXISTS created_at ON TABLE post TYPE string;
                DEFINE FIELD IF NOT EXISTS updated_at ON TABLE post TYPE string;
                DEFINE INDEX IF NOT EXISTS post_slug ON TABLE post COLUMNS slug UNIQUE;
                "#,
            )
            .await?
            .check()?;

        self.db
            .query(
                r#"
                DEFINE TABLE IF NOT EXISTS team_member SCHEMAFULL;
                DEFINE FIELD IF NOT EXISTS name ON TABLE team_member TYPE string;
                DEFINE FIELD IF NOT EXISTS role ON TABLE team_member TYPE string;
                DEFINE FIELD IF NOT EXISTS bio ON TABLE team_member TYPE string;
                DEFINE FIELD IF NOT EXISTS photo_url ON TABLE team_member TYPE option<string>;
                DEFINE FIELD IF NOT EXISTS github_url ON TABLE team_member TYPE option<string>;
                DEFINE FIELD IF NOT EXISTS twitter_url ON TABLE team_member TYPE option<string>;
                DEFINE FIELD IF NOT EXISTS linkedin_url ON TABLE team_member TYPE option<string>;
                DEFINE FIELD IF NOT EXISTS password_hash ON TABLE team_member TYPE option<string>;
                DEFINE FIELD IF NOT EXISTS created_at ON TABLE team_member TYPE string;
                DEFINE INDEX IF NOT EXISTS team_member_name ON TABLE team_member COLUMNS name UNIQUE;
                "#,
            )
            .await?
            .check()?;

        // Keyed by token digest - TokenManager never persists the raw token.
        self.db
            .query(
                r#"
                DEFINE TABLE IF NOT EXISTS token SCHEMAFULL;
                DEFINE FIELD IF NOT EXISTS username ON TABLE token TYPE string;
                DEFINE FIELD IF NOT EXISTS role ON TABLE token TYPE string;
                DEFINE FIELD IF NOT EXISTS created_at ON TABLE token TYPE string;
                DEFINE FIELD IF NOT EXISTS expiry ON TABLE token TYPE string;
                DEFINE INDEX IF NOT EXISTS token_expiry ON TABLE token COLUMNS expiry;
                "#,
            )
            .await?
            .check()?;

        Ok(())
    }

    async fn create_project(&self, p: NewProject) -> Result<Project> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();

        let created: Option<ProjectRow> = self
            .db
            .create(("project", id.as_str()))
            .content(ProjectContent::new(p, now.clone(), now))
            .await?;

        created.map(Into::into).ok_or(AppError::CreateProject)
    }

    async fn get_projects(&self) -> Result<Vec<Project>> {
        let rows: Vec<ProjectRow> = self
            .db
            .query("SELECT * FROM project ORDER BY created_at DESC LIMIT 100")
            .await?
            .take(0)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn get_project(&self, id: &str) -> Result<Option<Project>> {
        let row: Option<ProjectRow> = self.db.select(("project", id)).await?;
        Ok(row.map(Into::into))
    }

    async fn get_project_by_slug(&self, slug: &str) -> Result<Option<Project>> {
        let rows: Vec<ProjectRow> = self
            .db
            .query("SELECT * FROM project WHERE slug = $slug LIMIT 1")
            .bind(("slug", slug.to_owned()))
            .await?
            .take(0)?;
        Ok(rows.into_iter().next().map(Into::into))
    }

    async fn get_featured_projects(&self) -> Result<Vec<Project>> {
        let rows: Vec<ProjectRow> = self
            .db
            .query("SELECT * FROM project WHERE featured = true ORDER BY created_at DESC LIMIT 10")
            .await?
            .take(0)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn update_project(&self, id: &str, p: NewProject) -> Result<()> {
        let existing: Option<ProjectRow> = self.db.select(("project", id)).await?;
        let created_at = existing.map(|r| r.created_at).ok_or(AppError::NotFound)?;
        let now = chrono::Utc::now().to_rfc3339();

        let _updated: Option<ProjectRow> = self
            .db
            .update(("project", id))
            .content(ProjectContent::new(p, created_at, now))
            .await?;
        Ok(())
    }

    async fn delete_project(&self, id: &str) -> Result<()> {
        let _deleted: Option<ProjectRow> = self.db.delete(("project", id)).await?;
        Ok(())
    }

    async fn create_post(&self, p: NewPost) -> Result<Post> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();

        let created: Option<PostRow> = self
            .db
            .create(("post", id.as_str()))
            .content(PostContent::new(p, now.clone(), now))
            .await?;

        created.map(Into::into).ok_or(AppError::CreatePost)
    }

    async fn get_posts(&self) -> Result<Vec<Post>> {
        let rows: Vec<PostRow> = self
            .db
            .query("SELECT * FROM post ORDER BY created_at DESC LIMIT 100")
            .await?
            .take(0)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn get_published_posts(&self) -> Result<Vec<Post>> {
        let rows: Vec<PostRow> = self
            .db
            .query("SELECT * FROM post WHERE published = true ORDER BY created_at DESC LIMIT 100")
            .await?
            .take(0)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn get_post(&self, id: &str) -> Result<Option<Post>> {
        let row: Option<PostRow> = self.db.select(("post", id)).await?;
        Ok(row.map(Into::into))
    }

    async fn get_post_by_slug(&self, slug: &str) -> Result<Option<Post>> {
        let rows: Vec<PostRow> = self
            .db
            .query("SELECT * FROM post WHERE slug = $slug LIMIT 1")
            .bind(("slug", slug.to_owned()))
            .await?
            .take(0)?;
        Ok(rows.into_iter().next().map(Into::into))
    }

    async fn get_published_post_by_slug(&self, slug: &str) -> Result<Option<Post>> {
        let rows: Vec<PostRow> = self
            .db
            .query("SELECT * FROM post WHERE slug = $slug AND published = true LIMIT 1")
            .bind(("slug", slug.to_owned()))
            .await?
            .take(0)?;
        Ok(rows.into_iter().next().map(Into::into))
    }

    async fn update_post(&self, id: &str, p: NewPost) -> Result<()> {
        let existing: Option<PostRow> = self.db.select(("post", id)).await?;
        let created_at = existing.map(|r| r.created_at).ok_or(AppError::NotFound)?;
        let now = chrono::Utc::now().to_rfc3339();

        let _updated: Option<PostRow> = self
            .db
            .update(("post", id))
            .content(PostContent::new(p, created_at, now))
            .await?;
        Ok(())
    }

    async fn delete_post(&self, id: &str) -> Result<()> {
        let _deleted: Option<PostRow> = self.db.delete(("post", id)).await?;
        Ok(())
    }

    async fn create_team_member(&self, m: NewTeamMember) -> Result<TeamMember> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();

        let password_hash = m.password.as_ref().and_then(|password| {
            Argon2::default()
                .hash_password(password.as_bytes())
                .map(|h| h.to_string())
                .ok()
        });

        let created: Option<TeamMemberRow> = self
            .db
            .create(("team_member", id.as_str()))
            .content(TeamMemberContent {
                name: m.name,
                role: m.role,
                bio: m.bio,
                photo_url: m.photo_url,
                github_url: m.github_url,
                twitter_url: m.twitter_url,
                linkedin_url: m.linkedin_url,
                password_hash,
                created_at: now,
            })
            .await?;

        created.map(Into::into).ok_or(AppError::CreateTeamMember)
    }

    async fn get_team_members(&self) -> Result<Vec<TeamMember>> {
        let rows: Vec<TeamMemberRow> = self
            .db
            .query("SELECT * FROM team_member ORDER BY created_at DESC")
            .await?
            .take(0)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn get_team_member(&self, name: &str) -> Result<Option<TeamMember>> {
        let rows: Vec<TeamMemberRow> = self
            .db
            .query("SELECT * FROM team_member WHERE name = $name LIMIT 1")
            .bind(("name", name.to_owned()))
            .await?
            .take(0)?;
        Ok(rows.into_iter().next().map(Into::into))
    }

    async fn delete_team_member(&self, id: &str) -> Result<()> {
        let _deleted: Option<TeamMemberRow> = self.db.delete(("team_member", id)).await?;
        Ok(())
    }

    async fn update_team_member_password(&self, username: &str, password_hash: &str) -> Result<()> {
        self.db
            .query("UPDATE team_member SET password_hash = $hash WHERE name = $name")
            .bind(("hash", password_hash.to_owned()))
            .bind(("name", username.to_owned()))
            .await?
            .check()?;
        Ok(())
    }

    async fn save_token(
        &self,
        token: &str,
        username: &str,
        role: &str,
        created_at: &str,
        expiry: &str,
    ) -> Result<()> {
        let _saved: Option<TokenRow> = self
            .db
            .upsert(("token", token))
            .content(TokenRow {
                username: username.to_owned(),
                role: role.to_owned(),
                created_at: created_at.to_owned(),
                expiry: expiry.to_owned(),
            })
            .await?;
        Ok(())
    }

    async fn get_token(&self, token: &str) -> Result<Option<(String, String, String, String)>> {
        let row: Option<TokenRow> = self.db.select(("token", token)).await?;
        Ok(row.map(|r| (r.username, r.role, r.created_at, r.expiry)))
    }

    async fn delete_token(&self, token: &str) -> Result<()> {
        let _deleted: Option<TokenRow> = self.db.delete(("token", token)).await?;
        Ok(())
    }

    async fn cleanup_expired_tokens(&self, now: &str) -> Result<()> {
        self.db
            .query("DELETE token WHERE expiry < $now")
            .bind(("now", now.to_owned()))
            .await?
            .check()?;
        Ok(())
    }
}
