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
        if self.created_at.len() >= 10 {
            return format!(
                "{}-{}-{}",
                &self.created_at[8..10],
                &self.created_at[5..7],
                &self.created_at[0..4]
            );
        }
        self.created_at.clone()
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
        if self.created_at.len() >= 10 {
            format!(
                "{}-{}-{}",
                &self.created_at[8..10],
                &self.created_at[5..7],
                &self.created_at[0..4]
            )
        } else {
            self.created_at.clone()
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct NewTeamMember {
    pub name: String,
    pub role: String,
    pub bio: String,
    pub photo_url: String,
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
    pub photo_url: String,
    pub github_url: Option<String>,
    pub twitter_url: Option<String>,
    pub linkedin_url: Option<String>,
    pub password_hash: Option<String>,
    pub created_at: String,
}
