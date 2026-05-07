use std::sync::Arc;

use argon2::{Argon2, PasswordHasher};
use sqlx::Row;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions, SqliteRow};
use uuid::Uuid;

use crate::db::{Db, NewPost, NewProject, NewTeamMember, Post, Project, TeamMember};
use crate::error::Result;

pub struct SqliteDb {
    pool: Arc<SqlitePool>,
}

impl SqliteDb {
    pub async fn new(path: &str) -> Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_lazy_with(
                SqliteConnectOptions::new()
                    .filename(path)
                    .create_if_missing(true),
            );
        let pool = Arc::new(pool);

        tracing::info!(db=%path, "Database initialized");
        Ok(Self { pool })
    }

    fn project_row_to_project(row: SqliteRow) -> Project {
        let images_str: String = row.get("images");
        let tech_stack_str: String = row.get("tech_stack");
        let featured_int: i32 = row.get("featured");
        let demo_url: Option<String> = row.get("demo_url");
        let repo_url: Option<String> = row.get("repo_url");

        Project {
            demo_url,
            repo_url,
            id: row.get("id"),
            slug: row.get("slug"),
            title: row.get("title"),
            featured: featured_int != 0,
            category: row.get("category"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
            description: row.get("description"),
            thumbnail_url: row.get("thumbnail_url"),
            images: serde_json::from_str(&images_str).unwrap_or_default(),
            tech_stack: serde_json::from_str(&tech_stack_str).unwrap_or_default(),
        }
    }

    fn post_row_to_post(row: SqliteRow) -> Post {
        let tags_str: String = row.get("tags");
        let published_int: i32 = row.get("published");
        let cover_image: String = row.get("cover_image");

        Post {
            cover_image,
            id: row.get("id"),
            title: row.get("title"),
            slug: row.get("slug"),
            author: row.get("author"),
            content: row.get("content"),
            excerpt: row.get("excerpt"),
            published: published_int != 0,
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
            tags: serde_json::from_str(&tags_str).unwrap_or_default(),
        }
    }

    fn team_member_row_to_member(row: SqliteRow) -> TeamMember {
        let github_url: Option<String> = row.get("github_url");
        let twitter_url: Option<String> = row.get("twitter_url");
        let linkedin_url: Option<String> = row.get("linkedin_url");
        let password_hash: Option<String> = row.get("password_hash");
        let photo_url: Option<String> = row.get("photo_url");

        TeamMember {
            github_url,
            twitter_url,
            linkedin_url,
            password_hash,
            photo_url,
            id: row.get("id"),
            bio: row.get("bio"),
            name: row.get("name"),
            role: row.get("role"),
            created_at: row.get("created_at"),
        }
    }
}

#[async_trait::async_trait]
impl Db for SqliteDb {
    async fn init(&self) -> Result<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                slug TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL,
                category TEXT NOT NULL,
                thumbnail_url TEXT NOT NULL,
                images TEXT NOT NULL,
                tech_stack TEXT NOT NULL,
                demo_url TEXT,
                repo_url TEXT,
                featured INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )",
        )
        .execute(&*self.pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS posts (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                slug TEXT NOT NULL UNIQUE,
                content TEXT NOT NULL,
                excerpt TEXT NOT NULL,
                cover_image TEXT NOT NULL,
                tags TEXT NOT NULL,
                author TEXT NOT NULL,
                published INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )",
        )
        .execute(&*self.pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS team_members (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                role TEXT NOT NULL,
                bio TEXT NOT NULL,
                photo_url TEXT,
                github_url TEXT,
                twitter_url TEXT,
                linkedin_url TEXT,
                password_hash TEXT,
                created_at TEXT NOT NULL
            )",
        )
        .execute(&*self.pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS tokens (
                token TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expiry TEXT NOT NULL
            )",
        )
        .execute(&*self.pool)
        .await?;

        Ok(())
    }

    async fn create_project(&self, p: NewProject) -> Result<Project> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let images = serde_json::to_string(&p.images)?;
        let tech_stack = serde_json::to_string(&p.tech_stack)?;
        let featured = if p.featured { 1 } else { 0 };

        sqlx::query(
            "INSERT INTO projects (id, title, slug, description, category, thumbnail_url, images, tech_stack, demo_url, repo_url, featured, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        )
        .bind(&id)
        .bind(&p.title)
        .bind(&p.slug)
        .bind(&p.description)
        .bind(&p.category)
        .bind(&p.thumbnail_url)
        .bind(&images)
        .bind(&tech_stack)
        .bind(p.demo_url.as_deref())
        .bind(p.repo_url.as_deref())
        .bind(featured)
        .bind(&now)
        .bind(&now)
        .execute(&*self.pool)
        .await?;

        Ok(Project {
            id,
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
            created_at: now.clone(),
            updated_at: now,
        })
    }

    async fn get_projects(&self) -> Result<Vec<Project>> {
        let rows = sqlx::query(
            "SELECT id, title, slug, description, category, thumbnail_url, images, tech_stack, demo_url, repo_url, featured, created_at, updated_at FROM projects ORDER BY created_at DESC LIMIT 100",
        )
        .fetch_all(&*self.pool)
        .await?;

        let projects = rows.into_iter().map(Self::project_row_to_project).collect();

        Ok(projects)
    }

    async fn get_project(&self, id: &str) -> Result<Option<Project>> {
        let row = sqlx::query(
            "SELECT id, title, slug, description, category, thumbnail_url, images, tech_stack, demo_url, repo_url, featured, created_at, updated_at FROM projects WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(row.map(Self::project_row_to_project))
    }

    async fn get_project_by_slug(&self, slug: &str) -> Result<Option<Project>> {
        let row = sqlx::query(
            "SELECT id, title, slug, description, category, thumbnail_url, images, tech_stack, demo_url, repo_url, featured, created_at, updated_at FROM projects WHERE slug = ?1",
        )
        .bind(slug)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(row.map(Self::project_row_to_project))
    }

    async fn get_featured_projects(&self) -> Result<Vec<Project>> {
        let rows = sqlx::query(
            "SELECT id, title, slug, description, category, thumbnail_url, images, tech_stack, demo_url, repo_url, featured, created_at, updated_at FROM projects WHERE featured = 1 ORDER BY created_at DESC LIMIT 10",
        )
        .fetch_all(&*self.pool)
        .await?;

        let projects = rows.into_iter().map(Self::project_row_to_project).collect();

        Ok(projects)
    }

    async fn update_project(&self, id: &str, p: NewProject) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let images = serde_json::to_string(&p.images)?;
        let tech_stack = serde_json::to_string(&p.tech_stack)?;
        let featured = if p.featured { 1 } else { 0 };

        sqlx::query(
            "UPDATE projects SET title=?2, slug=?3, description=?4, category=?5, thumbnail_url=?6, images=?7, tech_stack=?8, demo_url=?9, repo_url=?10, featured=?11, updated_at=?12 WHERE id=?1",
        )
        .bind(id)
        .bind(&p.title)
        .bind(&p.slug)
        .bind(&p.description)
        .bind(&p.category)
        .bind(&p.thumbnail_url)
        .bind(&images)
        .bind(&tech_stack)
        .bind(p.demo_url.as_deref())
        .bind(p.repo_url.as_deref())
        .bind(featured)
        .bind(&now)
        .execute(&*self.pool)
        .await?;

        Ok(())
    }

    async fn delete_project(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM projects WHERE id = ?1")
            .bind(id)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    async fn create_post(&self, p: NewPost) -> Result<Post> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let tags = serde_json::to_string(&p.tags)?;
        let published = if p.published { 1 } else { 0 };

        sqlx::query(
            "INSERT INTO posts (id, title, slug, content, excerpt, cover_image, tags, author, published, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        )
        .bind(&id)
        .bind(&p.title)
        .bind(&p.slug)
        .bind(&p.content)
        .bind(&p.excerpt)
        .bind(&p.cover_image)
        .bind(&tags)
        .bind(&p.author)
        .bind(published)
        .bind(&now)
        .bind(&now)
        .execute(&*self.pool)
        .await?;

        Ok(Post {
            id,
            title: p.title,
            slug: p.slug,
            content: p.content,
            excerpt: p.excerpt,
            cover_image: p.cover_image,
            tags: p.tags,
            author: p.author,
            published: p.published,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    async fn get_posts(&self) -> Result<Vec<Post>> {
        let rows = sqlx::query(
            "SELECT id, title, slug, content, excerpt, cover_image, tags, author, published, created_at, updated_at FROM posts ORDER BY created_at DESC LIMIT 100",
        )
        .fetch_all(&*self.pool)
        .await?;

        let posts = rows.into_iter().map(Self::post_row_to_post).collect();

        Ok(posts)
    }

    async fn get_published_posts(&self) -> Result<Vec<Post>> {
        let rows = sqlx::query(
            "SELECT id, title, slug, content, excerpt, cover_image, tags, author, published, created_at, updated_at FROM posts WHERE published = 1 ORDER BY created_at DESC LIMIT 100",
        )
        .fetch_all(&*self.pool)
        .await?;

        let posts = rows.into_iter().map(Self::post_row_to_post).collect();

        Ok(posts)
    }

    async fn get_post(&self, id: &str) -> Result<Option<Post>> {
        let row = sqlx::query(
            "SELECT id, title, slug, content, excerpt, cover_image, tags, author, published, created_at, updated_at FROM posts WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(row.map(Self::post_row_to_post))
    }

    async fn get_post_by_slug(&self, slug: &str) -> Result<Option<Post>> {
        let row = sqlx::query(
            "SELECT id, title, slug, content, excerpt, cover_image, tags, author, published, created_at, updated_at FROM posts WHERE slug = ?1",
        )
        .bind(slug)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(row.map(Self::post_row_to_post))
    }

    async fn update_post(&self, id: &str, p: NewPost) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let tags = serde_json::to_string(&p.tags)?;
        let published = if p.published { 1 } else { 0 };

        sqlx::query(
            "UPDATE posts SET title=?2, slug=?3, content=?4, excerpt=?5, cover_image=?6, tags=?7, author=?8, published=?9, updated_at=?10 WHERE id=?1",
        )
        .bind(id)
        .bind(&p.title)
        .bind(&p.slug)
        .bind(&p.content)
        .bind(&p.excerpt)
        .bind(&p.cover_image)
        .bind(&tags)
        .bind(&p.author)
        .bind(published)
        .bind(&now)
        .execute(&*self.pool)
        .await?;

        Ok(())
    }

    async fn delete_post(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM posts WHERE id = ?1")
            .bind(id)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    async fn create_team_member(&self, m: NewTeamMember) -> Result<TeamMember> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();

        let password_hash = if let Some(password) = &m.password {
            let argon2 = Argon2::default();
            argon2
                .hash_password(password.as_bytes())
                .map(|h| h.to_string())
                .ok()
        } else {
            None
        };

        sqlx::query(
            "INSERT INTO team_members (id, name, role, bio, photo_url, github_url, twitter_url, linkedin_url, password_hash, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )
        .bind(&id)
        .bind(&m.name)
        .bind(&m.role)
        .bind(&m.bio)
        .bind(m.photo_url.as_deref())
        .bind(m.github_url.as_deref())
        .bind(m.twitter_url.as_deref())
        .bind(m.linkedin_url.as_deref())
        .bind(password_hash.as_deref())
        .bind(&now)
        .execute(&*self.pool)
        .await?;

        Ok(TeamMember {
            id,
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
    }

    async fn get_team_members(&self) -> Result<Vec<TeamMember>> {
        let rows = sqlx::query(
            "SELECT id, name, role, bio, photo_url, github_url, twitter_url, linkedin_url, password_hash, created_at FROM team_members ORDER BY created_at DESC",
        )
        .fetch_all(&*self.pool)
        .await?;

        let members = rows
            .into_iter()
            .map(Self::team_member_row_to_member)
            .collect();

        Ok(members)
    }

    async fn get_team_member(&self, name: &str) -> Result<Option<TeamMember>> {
        let row = sqlx::query(
            "SELECT id, name, role, bio, photo_url, github_url, twitter_url, linkedin_url, password_hash, created_at FROM team_members WHERE name = ?1",
        )
        .bind(name)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(row.map(Self::team_member_row_to_member))
    }

    async fn delete_team_member(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM team_members WHERE id = ?1")
            .bind(id)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    async fn update_team_member_password(&self, username: &str, password_hash: &str) -> Result<()> {
        sqlx::query("UPDATE team_members SET password_hash = ?1 WHERE name = ?2")
            .bind(password_hash)
            .bind(username)
            .execute(&*self.pool)
            .await?;
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
        sqlx::query(
            "INSERT OR REPLACE INTO tokens (token, username, role, created_at, expiry) VALUES (?1, ?2, ?3, ?4, ?5)"
        )
        .bind(token)
        .bind(username)
        .bind(role)
        .bind(created_at)
        .bind(expiry)
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    async fn get_token(&self, token: &str) -> Result<Option<(String, String, String, String)>> {
        let row =
            sqlx::query("SELECT username, role, created_at, expiry FROM tokens WHERE token = ?1")
                .bind(token)
                .fetch_optional(&*self.pool)
                .await?;
        Ok(row.map(|r| (r.get(0), r.get(1), r.get(2), r.get(3))))
    }

    async fn delete_token(&self, token: &str) -> Result<()> {
        sqlx::query("DELETE FROM tokens WHERE token = ?1")
            .bind(token)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    async fn cleanup_expired_tokens(&self, now: &str) -> Result<()> {
        sqlx::query("DELETE FROM tokens WHERE expiry < ?1")
            .bind(now)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }
}
