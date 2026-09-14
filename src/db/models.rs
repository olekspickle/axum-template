use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, Default, Deserialize, Serialize, ToSchema)]
pub struct NewProject {
    pub title: String,
    pub slug: String,
    pub description: String,
    pub category: String,
    pub thumbnail_url: String,
    pub images: Vec<String>,
    pub tech_stack: Vec<String>,
    pub demo_url: Option<String>,
    pub repo_url: Option<String>,
    pub featured: bool,
}
#[derive(Debug, Clone, Default, Deserialize, Serialize, ToSchema)]

pub struct Project {
    pub id: String,
    pub title: String,
    pub slug: String,
    pub description: String,
    pub category: String,
    pub thumbnail_url: String,
    pub images: Vec<String>,
    pub tech_stack: Vec<String>,
    pub demo_url: Option<String>,
    pub repo_url: Option<String>,
    pub featured: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl Project {
    pub fn created_at_formatted(&self) -> String {
        format_rfc3339_date(&self.created_at)
    }
}
#[derive(Debug, Clone, Default, Deserialize, Serialize, ToSchema)]
pub struct NewPost {
    pub title: String,
    pub slug: String,
    pub content: String,
    pub excerpt: String,
    pub cover_image: String,
    pub tags: Vec<String>,
    pub author: String,
    pub published: bool,
}
#[derive(Debug, Clone, Default, Deserialize, Serialize, ToSchema)]

pub struct Post {
    pub id: String,
    pub title: String,
    pub slug: String,
    pub content: String,
    pub excerpt: String,
    pub cover_image: String,
    pub tags: Vec<String>,
    pub author: String,
    pub published: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl Post {
    pub fn format_date(&self) -> String {
        format_rfc3339_date(&self.created_at)
    }
}
/// `YYYY-MM-DD...` -> `DD-MM-YYYY`. Parsed rather than byte-sliced, so a value that
/// isn't a timestamp is passed through instead of panicking on a char boundary.
fn format_rfc3339_date(value: &str) -> String {
    match chrono::DateTime::parse_from_rfc3339(value) {
        Ok(dt) => dt.format("%d-%m-%Y").to_string(),
        Err(_) => value.to_string(),
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct NewTeamMember {
    pub name: String,
    pub role: String,
    pub bio: String,
    pub photo_url: Option<String>,
    pub github_url: Option<String>,
    pub twitter_url: Option<String>,
    pub linkedin_url: Option<String>,
    pub password: Option<String>,
}
#[derive(Debug, Clone, Default, Deserialize, Serialize)]

pub struct TeamMember {
    pub id: String,
    pub name: String,
    pub role: String,
    pub bio: String,
    pub photo_url: Option<String>,
    pub github_url: Option<String>,
    pub twitter_url: Option<String>,
    pub linkedin_url: Option<String>,
    pub password_hash: Option<String>,
    pub created_at: String,
}
