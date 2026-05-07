use std::sync::Arc;

use argon2::{Argon2, PasswordHasher};
use surrealdb::{
    Surreal,
    engine::remote::ws::{Client, Ws},
    opt::auth::Root,
};
use uuid::Uuid;

use crate::config::{Config, SurrealParams};
use crate::db::{Db, NewPost, NewProject, NewTeamMember, Post, Project, TeamMember};
use crate::error::{AppError, Result};

pub struct SurrealDb {
    db: Arc<Surreal<Client>>,
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

        db.connect::<Ws>(url).await?;
        db.signin(Root { username, password }).await?;
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
                DEFINE TABLE IF NOT EXISTS projects SCHEMAFULL;
                DEFINE FIELD IF NOT EXISTS title ON TABLE projects TYPE string;
                DEFINE FIELD IF NOT EXISTS slug ON TABLE projects TYPE string;
                DEFINE FIELD IF NOT EXISTS description ON TABLE projects TYPE string;
                DEFINE FIELD IF NOT EXISTS category ON TABLE projects TYPE string;
                DEFINE FIELD IF NOT EXISTS thumbnail_url ON TABLE projects TYPE string;
                DEFINE FIELD IF NOT EXISTS images ON TABLE projects TYPE array;
                DEFINE FIELD IF NOT EXISTS tech_stack ON TABLE projects TYPE array;
                DEFINE FIELD IF NOT EXISTS demo_url ON TABLE projects TYPE option<string>;
                DEFINE FIELD IF NOT EXISTS repo_url ON TABLE projects TYPE option<string>;
                DEFINE FIELD IF NOT EXISTS featured ON TABLE projects TYPE bool;
                DEFINE FIELD IF NOT EXISTS created_at ON TABLE projects TYPE datetime;
                DEFINE FIELD IF NOT EXISTS updated_at ON TABLE projects TYPE datetime;
                "#,
            )
            .await?;

        self.db
            .query(
                r#"
                DEFINE TABLE IF NOT EXISTS posts SCHEMAFULL;
                DEFINE FIELD IF NOT EXISTS title ON TABLE posts TYPE string;
                DEFINE FIELD IF NOT EXISTS slug ON TABLE posts TYPE string;
                DEFINE FIELD IF NOT EXISTS content ON TABLE posts TYPE string;
                DEFINE FIELD IF NOT EXISTS excerpt ON TABLE posts TYPE string;
                DEFINE FIELD IF NOT EXISTS cover_image ON TABLE posts TYPE string;
                DEFINE FIELD IF NOT EXISTS tags ON TABLE posts TYPE array;
                DEFINE FIELD IF NOT EXISTS author ON TABLE posts TYPE string;
                DEFINE FIELD IF NOT EXISTS published ON TABLE posts TYPE bool;
                DEFINE FIELD IF NOT EXISTS created_at ON TABLE posts TYPE datetime;
                DEFINE FIELD IF NOT EXISTS updated_at ON TABLE posts TYPE datetime;
                "#,
            )
            .await?;

        self.db
            .query(
                r#"
                DEFINE TABLE IF NOT EXISTS team_members SCHEMAFULL;
                DEFINE FIELD IF NOT EXISTS name ON TABLE team_members TYPE string;
                DEFINE FIELD IF NOT EXISTS role ON TABLE team_members TYPE string;
                DEFINE FIELD IF NOT EXISTS bio ON TABLE team_members TYPE string;
                DEFINE FIELD IF NOT EXISTS photo_url ON TABLE team_members TYPE option<string>;
                DEFINE FIELD IF NOT EXISTS github_url ON TABLE team_members TYPE option<string>;
                DEFINE FIELD IF NOT EXISTS twitter_url ON TABLE team_members TYPE option<string>;
                DEFINE FIELD IF NOT EXISTS linkedin_url ON TABLE team_members TYPE option<string>;
                DEFINE FIELD IF NOT EXISTS password_hash ON TABLE team_members TYPE option<string>;
                DEFINE FIELD IF NOT EXISTS created_at ON TABLE team_members TYPE datetime;
                "#,
            )
            .await?;

        self.db
            .query(
                r#"
                DEFINE TABLE IF NOT EXISTS tokens SCHEMAFULL;
                DEFINE FIELD IF NOT EXISTS username ON TABLE tokens TYPE string;
                DEFINE FIELD IF NOT EXISTS role ON TABLE tokens TYPE string;
                DEFINE FIELD IF NOT EXISTS created_at ON TABLE tokens TYPE datetime;
                DEFINE FIELD IF NOT EXISTS expiry ON TABLE tokens TYPE datetime;
                "#,
            )
            .await?;

        Ok(())
    }

    async fn create_project(&self, p: NewProject) -> Result<Project> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        let created: Option<Project> = self
            .db
            .create(("project", &id))
            .content(Project {
                id: id.clone(),
                title: p.title.clone(),
                slug: p.slug.clone(),
                description: p.description.clone(),
                category: p.category.clone(),
                thumbnail_url: p.thumbnail_url.clone(),
                images: p.images.clone(),
                tech_stack: p.tech_stack.clone(),
                demo_url: p.demo_url.clone(),
                repo_url: p.repo_url.clone(),
                featured: p.featured,
                created_at: now.to_rfc3339(),
                updated_at: now.to_rfc3339(),
            })
            .await?;

        created.ok_or(AppError::CreateProject)
    }

    async fn get_projects(&self) -> Result<Vec<Project>> {
        let projects: Vec<Project> = self.db.select("project").await?;
        Ok(projects)
    }

    async fn get_project(&self, id: &str) -> Result<Option<Project>> {
        let id = id.to_owned();
        let projects: Vec<Project> = self
            .db
            .query("SELECT * FROM project WHERE id = $id")
            .bind(("id", id))
            .await?
            .take(0)?;

        Ok(projects.into_iter().next())
    }

    async fn get_project_by_slug(&self, slug: &str) -> Result<Option<Project>> {
        let slug = slug.to_owned();
        let projects: Vec<Project> = self
            .db
            .query("SELECT * FROM project WHERE slug = $slug")
            .bind(("slug", slug))
            .await?
            .take(0)?;

        Ok(projects.into_iter().next())
    }

    async fn get_featured_projects(&self) -> Result<Vec<Project>> {
        let projects: Vec<Project> = self
            .db
            .query("SELECT * FROM project WHERE featured = true ORDER BY created_at DESC LIMIT 10")
            .await?
            .take(0)?;
        Ok(projects)
    }

    async fn update_project(&self, id: &str, p: NewProject) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.db
            .query(
                "UPDATE project SET title=$title, slug=$slug, description=$description, category=$category, thumbnail_url=$thumbnail_url, images=$images, tech_stack=$tech_stack, demo_url=$demo_url, repo_url=$repo_url, featured=$featured, updated_at=$updated_at WHERE id=$id",
            )
            .bind(("id", format!("project:{}", id)))
            .bind(("title", p.title))
            .bind(("slug", p.slug))
            .bind(("description", p.description))
            .bind(("category", p.category))
            .bind(("thumbnail_url", p.thumbnail_url))
            .bind(("images", p.images))
            .bind(("tech_stack", p.tech_stack))
            .bind(("demo_url", p.demo_url))
            .bind(("repo_url", p.repo_url))
            .bind(("featured", p.featured))
            .bind(("updated_at", now))
            .await?;
        Ok(())
    }

    async fn delete_project(&self, id: &str) -> Result<()> {
        let _project: Option<Project> = self.db.delete(("project", id)).await?;
        Ok(())
    }

    async fn create_post(&self, p: NewPost) -> Result<Post> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        let created: Option<Post> = self
            .db
            .create(("post", &id))
            .content(Post {
                id: id.clone(),
                title: p.title.clone(),
                slug: p.slug.clone(),
                content: p.content.clone(),
                excerpt: p.excerpt.clone(),
                cover_image: p.cover_image.clone(),
                tags: p.tags.clone(),
                author: p.author.clone(),
                published: p.published,
                created_at: now.to_rfc3339(),
                updated_at: now.to_rfc3339(),
            })
            .await?;

        created.ok_or(AppError::CreatePost)
    }

    async fn get_posts(&self) -> Result<Vec<Post>> {
        let posts: Vec<Post> = self.db.select("post").await?;
        Ok(posts)
    }

    async fn get_published_posts(&self) -> Result<Vec<Post>> {
        let posts: Vec<Post> = self
            .db
            .query("SELECT * FROM post WHERE published = true ORDER BY created_at DESC")
            .await?
            .take(0)?;
        Ok(posts)
    }

    async fn get_post(&self, id: &str) -> Result<Option<Post>> {
        let id = id.to_owned();
        let posts: Vec<Post> = self
            .db
            .clone()
            .query("SELECT * FROM post WHERE id = $id")
            .bind(("id", id))
            .await?
            .take(0)?;

        Ok(posts.into_iter().next())
    }

    async fn get_post_by_slug(&self, slug: &str) -> Result<Option<Post>> {
        let slug = slug.to_owned();
        let posts: Vec<Post> = self
            .db
            .clone()
            .query("SELECT * FROM post WHERE slug = $slug")
            .bind(("slug", slug))
            .await?
            .take(0)?;

        Ok(posts.into_iter().next())
    }

    async fn update_post(&self, id: &str, p: NewPost) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.db
            .query(
                "UPDATE post SET title=$title, slug=$slug, content=$content, excerpt=$excerpt, cover_image=$cover_image, tags=$tags, author=$author, published=$published, updated_at=$updated_at WHERE id=$id",
            )
            .bind(("id", format!("post:{}", id)))
            .bind(("title", p.title))
            .bind(("slug", p.slug))
            .bind(("content", p.content))
            .bind(("excerpt", p.excerpt))
            .bind(("cover_image", p.cover_image))
            .bind(("tags", p.tags))
            .bind(("author", p.author))
            .bind(("published", p.published))
            .bind(("updated_at", now))
            .await?;
        Ok(())
    }

    async fn delete_post(&self, id: &str) -> Result<()> {
        let _post: Option<Post> = self.db.delete(("post", id)).await?;
        Ok(())
    }

    async fn create_team_member(&self, m: NewTeamMember) -> Result<TeamMember> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();

        let password_hash = if let Some(password) = &m.password {
            let argon2 = Argon2::default();
            let hash = argon2
                .hash_password(password.as_bytes())
                .map(|h| h.to_string())
                .ok();
            hash
        } else {
            None
        };

        let created: Option<TeamMember> = self
            .db
            .create(("team_member", &id))
            .content(TeamMember {
                id: id.clone(),
                name: m.name.clone(),
                role: m.role.clone(),
                bio: m.bio.clone(),
                photo_url: m.photo_url.clone(),
                github_url: m.github_url.clone(),
                twitter_url: m.twitter_url.clone(),
                linkedin_url: m.linkedin_url.clone(),
                password_hash,
                created_at: now,
            })
            .await?;

        created.ok_or(AppError::CreateTeamMember)
    }

    async fn get_team_members(&self) -> Result<Vec<TeamMember>> {
        let members: Vec<TeamMember> = self.db.select("team_member").await?;
        Ok(members)
    }

    async fn get_team_member(&self, name: &str) -> Result<Option<TeamMember>> {
        let name = name.to_owned();
        let members: Vec<TeamMember> = self
            .db
            .query("SELECT * FROM team_member WHERE name = $name")
            .bind(("name", name))
            .await?
            .take(0)?;
        Ok(members.into_iter().next())
    }

    async fn delete_team_member(&self, id: &str) -> Result<()> {
        let _member: Option<TeamMember> = self.db.delete(("team_member", id)).await?;
        Ok(())
    }

    async fn update_team_member_password(&self, username: &str, password_hash: &str) -> Result<()> {
        let _: Option<TeamMember> = self
            .db
            .query("UPDATE team_member SET password_hash = $hash WHERE name = $name")
            .bind(("hash", password_hash))
            .bind(("name", username))
            .await?
            .take(0)?;
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
        let _: Option<()> = self
            .db
            .query("CREATE tokens SET username = $username, role = $role, created_at = $created_at, expiry = $expiry WHERE token = $token")
            .bind(("token", token))
            .bind(("username", username))
            .bind(("role", role))
            .bind(("created_at", created_at))
            .bind(("expiry", expiry))
            .await?
            .take(0)?;
        Ok(())
    }

    async fn get_token(&self, token: &str) -> Result<Option<(String, String, String, String)>> {
        let mut result: Vec<(String, String, String, String)> = self
            .db
            .query("SELECT username, role, created_at, expiry FROM tokens WHERE token = $token")
            .bind(("token", token))
            .await?
            .take(0)?;
        Ok(result.pop())
    }

    async fn delete_token(&self, token: &str) -> Result<()> {
        let _: Option<()> = self
            .db
            .query("DELETE FROM tokens WHERE token = $token")
            .bind(("token", token))
            .await?
            .take(0)?;
        Ok(())
    }

    async fn cleanup_expired_tokens(&self, now: &str) -> Result<()> {
        let _: Vec<()> = self
            .db
            .query("DELETE FROM tokens WHERE expiry < $now")
            .bind(("now", now))
            .await?
            .take(0)?;
        Ok(())
    }
}
