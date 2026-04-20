use async_trait::async_trait;

mod models;
#[cfg(feature = "sqlite")]
mod sqlite;
#[cfg(feature = "surreal")]
mod surreal;

pub use models::*;

use crate::error::Result;

pub async fn create_db(cfg: &crate::config::Config) -> Result<Box<dyn Db>> {
    #[cfg(all(not(feature = "surreal"), feature = "sqlite"))]
    {
        let db = sqlite::SqliteDb::new(&cfg.db.path).await?;
        Ok(Box::new(db))
    }
    #[cfg(feature = "surreal")]
    {
        let db = surreal::SurrealDb::connect(cfg).await?;
        Ok(Box::new(db))
    }
}

#[async_trait]
pub trait Db: Send + Sync {
    async fn init(&self) -> Result<()>;

    async fn create_project(&self, project: NewProject) -> Result<Project>;
    async fn get_projects(&self) -> Result<Vec<Project>>;
    async fn get_project(&self, slug: &str) -> Result<Option<Project>>;
    async fn get_featured_projects(&self) -> Result<Vec<Project>>;
    async fn update_project(&self, id: &str, project: NewProject) -> Result<()>;
    async fn delete_project(&self, id: &str) -> Result<()>;

    async fn create_post(&self, post: NewPost) -> Result<Post>;
    async fn get_posts(&self) -> Result<Vec<Post>>;
    async fn get_published_posts(&self) -> Result<Vec<Post>>;
    async fn get_post(&self, slug: &str) -> Result<Option<Post>>;
    async fn update_post(&self, id: &str, post: NewPost) -> Result<()>;
    async fn delete_post(&self, id: &str) -> Result<()>;

    async fn create_team_member(&self, member: NewTeamMember) -> Result<TeamMember>;
    async fn get_team_members(&self) -> Result<Vec<TeamMember>>;
    async fn get_team_member(&self, name: &str) -> Result<Option<TeamMember>>;
    async fn delete_team_member(&self, id: &str) -> Result<()>;
}
