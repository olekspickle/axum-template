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
    pub photo: PhotoPos,
    pub links: Vec<SocialLink>,
    pub password: Option<String>,
}
#[derive(Debug, Clone, Default, Deserialize, Serialize)]

pub struct TeamMember {
    pub id: String,
    pub name: String,
    pub role: String,
    pub bio: String,
    pub photo_url: Option<String>,
    pub photo: PhotoPos,
    pub links: Vec<SocialLink>,
    pub password_hash: Option<String>,
    pub created_at: String,
}

impl TeamMember {
    pub fn photo_style(&self) -> String {
        self.photo.style()
    }

    /// Feeds the admin links editor's hidden input.
    pub fn links_json(&self) -> String {
        serde_json::to_string(&self.links).unwrap_or_else(|_| "[]".into())
    }
}

/// How an avatar sits in its round frame, in percent of the frame: `w` is the image
/// width (`None` = default centred cover), `l`/`t` its left/top offset. Percentages
/// keep it identical at every rendered size.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq)]
pub struct PhotoPos {
    pub w: Option<f64>,
    pub l: f64,
    pub t: f64,
}

impl PhotoPos {
    /// Parses the admin form's hidden inputs; anything unusable falls back to the default.
    pub fn from_form(w: &str, l: &str, t: &str) -> Self {
        let num = |s: &str| s.trim().parse::<f64>().ok().filter(|v| v.is_finite());
        match num(w) {
            Some(w) if (100.0..=1200.0).contains(&w) => Self {
                w: Some(w),
                l: num(l).unwrap_or(0.0).clamp(-1200.0, 0.0),
                t: num(t).unwrap_or(0.0).clamp(-1200.0, 0.0),
            },
            _ => Self::default(),
        }
    }

    /// Inline style for the `<img>` inside an `.avatar` frame; empty means default cover.
    pub fn style(&self) -> String {
        match self.w {
            Some(w) => format!(
                "position:absolute;max-width:none;height:auto;width:{w:.2}%;left:{:.2}%;top:{:.2}%",
                self.l, self.t
            ),
            None => String::new(),
        }
    }
}

/// `(value, label, Font Awesome classes)`. Single source of truth for the admin
/// dropdown, the public icons, and which platforms are accepted.
pub const PLATFORMS: [(&str, &str, &str); 10] = [
    ("github", "GitHub", "fa-brands fa-github"),
    ("x", "X / Twitter", "fa-brands fa-x-twitter"),
    ("bluesky", "Bluesky", "fa-brands fa-bluesky"),
    ("mastodon", "Mastodon", "fa-brands fa-mastodon"),
    ("linkedin", "LinkedIn", "fa-brands fa-linkedin"),
    ("instagram", "Instagram", "fa-brands fa-instagram"),
    ("youtube", "YouTube", "fa-brands fa-youtube"),
    ("itch", "itch.io", "fa-brands fa-itch-io"),
    ("email", "Email", "fa-solid fa-envelope"),
    ("website", "Website", "fa-solid fa-globe"),
];

const MAX_LINKS: usize = 12;
const MAX_URL_LEN: usize = 500;

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct SocialLink {
    pub platform: String,
    pub url: String,
}

impl SocialLink {
    fn entry(&self) -> Option<&'static (&'static str, &'static str, &'static str)> {
        PLATFORMS.iter().find(|(value, ..)| *value == self.platform)
    }

    pub fn label(&self) -> &'static str {
        self.entry().map_or("Link", |(_, label, _)| label)
    }

    pub fn icon_class(&self) -> &'static str {
        self.entry()
            .map_or("fa-solid fa-link", |(.., icon)| icon)
    }

    /// Only http(s) and mailto survive: these URLs land in `href`, so `javascript:`
    /// and friends must never be stored. A bare address on an email link gets `mailto:`.
    fn normalized(self) -> Option<Self> {
        let url = self.url.trim();
        if url.is_empty() || url.len() > MAX_URL_LEN {
            return None;
        }
        let platform = if PLATFORMS.iter().any(|(value, ..)| *value == self.platform) {
            self.platform
        } else {
            "website".to_string()
        };
        let lower = url.to_ascii_lowercase();
        let url = if lower.starts_with("http://")
            || lower.starts_with("https://")
            || lower.starts_with("mailto:")
        {
            url.to_string()
        } else if platform == "email" && url.contains('@') && !url.contains(':') {
            format!("mailto:{url}")
        } else if !url.contains(':') && !url.starts_with('/') && url.contains('.') {
            format!("https://{url}")
        } else {
            return None;
        };
        Some(Self { platform, url })
    }
}

/// Parses the admin form's JSON `links` field, dropping anything unusable.
pub fn parse_links(json: &str) -> Vec<SocialLink> {
    serde_json::from_str::<Vec<SocialLink>>(json)
        .unwrap_or_default()
        .into_iter()
        .filter_map(SocialLink::normalized)
        .take(MAX_LINKS)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_drop_unsafe_and_empty_urls() {
        let links = parse_links(
            r#"[{"platform":"github","url":"https://github.com/a"},
                {"platform":"x","url":"javascript:alert(1)"},
                {"platform":"x","url":"data:text/html,hi"},
                {"platform":"website","url":"   "}]"#,
        );
        assert_eq!(
            links,
            vec![SocialLink {
                platform: "github".into(),
                url: "https://github.com/a".into()
            }]
        );
    }

    #[test]
    fn links_fill_in_scheme_and_unknown_platforms() {
        let links = parse_links(
            r#"[{"platform":"email","url":"me@example.com"},
                {"platform":"nope","url":"example.com/x"}]"#,
        );
        assert_eq!(links[0].url, "mailto:me@example.com");
        assert_eq!(links[1].platform, "website");
        assert_eq!(links[1].url, "https://example.com/x");
    }

    #[test]
    fn photo_position_rejects_junk_and_clamps() {
        assert_eq!(PhotoPos::from_form("", "0", "0"), PhotoPos::default());
        assert_eq!(PhotoPos::from_form("NaN", "1", "1"), PhotoPos::default());
        assert_eq!(PhotoPos::from_form("50", "0", "0"), PhotoPos::default());
        let p = PhotoPos::from_form("250.5", "-40", "9999");
        assert_eq!(p, PhotoPos { w: Some(250.5), l: -40.0, t: 0.0 });
        assert_eq!(
            p.style(),
            "position:absolute;max-width:none;height:auto;width:250.50%;left:-40.00%;top:0.00%"
        );
        assert!(PhotoPos::default().style().is_empty());
    }

    #[test]
    fn malformed_links_json_is_empty() {
        assert!(parse_links("not json").is_empty());
        assert!(parse_links("").is_empty());
    }

    #[test]
    fn icons_and_labels_come_from_the_platform_table() {
        let link = SocialLink {
            platform: "itch".into(),
            url: "https://x.itch.io".into(),
        };
        assert_eq!(link.label(), "itch.io");
        assert_eq!(link.icon_class(), "fa-brands fa-itch-io");
    }
}
