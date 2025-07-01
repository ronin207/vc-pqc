use anyhow::{Result, Context};
use reqwest::Client;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn, error, debug};
use url::Url;

use crate::database::Database;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Paper {
    pub id: String,
    pub title: String,
    pub authors: Vec<String>,
    pub abstract_text: String,
    pub categories: Vec<String>,
    pub publication_date: String,
    pub url: String,
    pub pdf_url: Option<String>,
    pub citations: Vec<String>,
    pub references: Vec<String>,
    pub keywords: Vec<String>,
}

pub struct EprintScraper {
    client: Client,
    base_url: String,
    rate_limit_ms: u64,
}

impl EprintScraper {
    pub fn new() -> Self {
        let client = Client::builder()
            .user_agent("Research-Agent/1.0 (Educational Purpose)")
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            base_url: "https://eprint.iacr.org".to_string(),
            rate_limit_ms: 1000, // 1 second between requests
        }
    }

    pub async fn scrape_papers(
        &self,
        count: usize,
        start_year: u32,
        category: Option<String>,
        db: &Database,
    ) -> Result<Vec<Paper>> {
        info!("Starting to scrape {} papers from year {}", count, start_year);
        
        let mut papers = Vec::new();
        let mut current_year = start_year;
        let current_year_limit = 2024; // Don't go beyond current year
        
        while papers.len() < count && current_year <= current_year_limit {
            info!("Scraping papers from year {}", current_year);
            
            let year_papers = self.scrape_year(current_year, category.clone()).await?;
            
            for paper in year_papers {
                if papers.len() >= count {
                    break;
                }
                
                // Check if paper already exists in database
                if !db.paper_exists(&paper.id).await? {
                    // Save to database
                    db.save_paper(&paper).await?;
                    papers.push(paper);
                    
                    // Rate limiting
                    sleep(Duration::from_millis(self.rate_limit_ms)).await;
                } else {
                    debug!("Paper {} already exists, skipping", paper.id);
                }
            }
            
            current_year += 1;
        }
        
        info!("Successfully scraped {} papers", papers.len());
        Ok(papers)
    }

    async fn scrape_year(&self, year: u32, category: Option<String>) -> Result<Vec<Paper>> {
        let url = format!("{}/year/{}", self.base_url, year);
        debug!("Fetching year index: {}", url);
        
        let response = self.client.get(&url).send().await
            .context("Failed to fetch year index")?;
        
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("HTTP error: {}", response.status()));
        }
        
        let html = response.text().await?;
        let document = Html::parse_document(&html);
        
        // Parse paper links from the year index
        let paper_links = self.extract_paper_links(&document, category)?;
        
        let mut papers = Vec::new();
        for link in paper_links {
            match self.scrape_paper(&link).await {
                Ok(paper) => {
                    papers.push(paper);
                    sleep(Duration::from_millis(self.rate_limit_ms)).await;
                }
                Err(e) => {
                    warn!("Failed to scrape paper {}: {}", link, e);
                }
            }
        }
        
        Ok(papers)
    }

    fn extract_paper_links(&self, document: &Html, category: Option<String>) -> Result<Vec<String>> {
        let mut links = Vec::new();
        
        // ePrint uses different selectors for paper listings
        let selectors = [
            "a[href*='/20']", // Papers have year in URL
            ".entry a",
            "td a[href*='/']",
        ];
        
        for selector_str in &selectors {
            if let Ok(selector) = Selector::parse(selector_str) {
                for element in document.select(&selector) {
                    if let Some(href) = element.value().attr("href") {
                        if self.is_paper_link(href) {
                            let full_url = if href.starts_with("http") {
                                href.to_string()
                            } else {
                                format!("{}{}", self.base_url, href)
                            };
                            
                            // Filter by category if specified
                            if let Some(ref cat) = category {
                                if self.matches_category(&full_url, cat) {
                                    links.push(full_url);
                                }
                            } else {
                                links.push(full_url);
                            }
                        }
                    }
                }
            }
        }
        
        // Remove duplicates
        links.sort();
        links.dedup();
        
        Ok(links)
    }

    fn is_paper_link(&self, href: &str) -> bool {
        // ePrint paper URLs typically follow pattern: /YYYY/NNNN
        let paper_patterns = [
            r"/20\d{2}/\d+",  // /2024/123
            r"/\d{4}/\d+",    // Generic year/number
        ];
        
        for pattern in &paper_patterns {
            if regex::Regex::new(pattern).unwrap().is_match(href) {
                return true;
            }
        }
        
        false
    }

    fn matches_category(&self, url: &str, category: &str) -> bool {
        // Simple category matching - in a real implementation,
        // you'd want more sophisticated category detection
        url.to_lowercase().contains(&category.to_lowercase())
    }

    async fn scrape_paper(&self, url: &str) -> Result<Paper> {
        debug!("Scraping paper: {}", url);
        
        let response = self.client.get(url).send().await
            .context("Failed to fetch paper page")?;
        
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("HTTP error: {}", response.status()));
        }
        
        let html = response.text().await?;
        let document = Html::parse_document(&html);
        
        // Extract paper ID from URL
        let id = self.extract_paper_id(url)?;
        
        // Extract paper metadata
        let title = self.extract_title(&document)?;
        let authors = self.extract_authors(&document)?;
        let abstract_text = self.extract_abstract(&document)?;
        let categories = self.extract_categories(&document)?;
        let publication_date = self.extract_date(&document)?;
        let pdf_url = self.extract_pdf_url(&document, url)?;
        
        // Extract citations and references (if available)
        let citations = self.extract_citations(&document)?;
        let references = self.extract_references(&document)?;
        
        // Extract keywords from abstract and title
        let keywords = self.extract_keywords(&title, &abstract_text)?;
        
        Ok(Paper {
            id,
            title,
            authors,
            abstract_text,
            categories,
            publication_date,
            url: url.to_string(),
            pdf_url,
            citations,
            references,
            keywords,
        })
    }

    fn extract_paper_id(&self, url: &str) -> Result<String> {
        let parsed_url = Url::parse(url)?;
        let path = parsed_url.path();
        
        // Extract ID from path like /2024/123
        if let Some(captures) = regex::Regex::new(r"/(\d{4}/\d+)")
            .unwrap()
            .captures(path) 
        {
            Ok(captures[1].to_string())
        } else {
            Err(anyhow::anyhow!("Could not extract paper ID from URL: {}", url))
        }
    }

    fn extract_title(&self, document: &Html) -> Result<String> {
        let selectors = ["h1", ".title", "title"];
        
        for selector_str in &selectors {
            if let Ok(selector) = Selector::parse(selector_str) {
                if let Some(element) = document.select(&selector).next() {
                    let title = element.text().collect::<String>().trim().to_string();
                    if !title.is_empty() && title.len() > 10 {
                        return Ok(title);
                    }
                }
            }
        }
        
        Err(anyhow::anyhow!("Could not extract title"))
    }

    fn extract_authors(&self, document: &Html) -> Result<Vec<String>> {
        let selectors = [".authors", ".author", "meta[name='author']"];
        
        for selector_str in &selectors {
            if let Ok(selector) = Selector::parse(selector_str) {
                if let Some(element) = document.select(&selector).next() {
                    let text = if selector_str.starts_with("meta") {
                        element.value().attr("content").unwrap_or("").to_string()
                    } else {
                        element.text().collect::<String>()
                    };
                    
                    if !text.is_empty() {
                        // Split authors by common delimiters
                        let authors: Vec<String> = text
                            .split(&[',', ';', '\n'])
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                        
                        if !authors.is_empty() {
                            return Ok(authors);
                        }
                    }
                }
            }
        }
        
        Ok(vec!["Unknown".to_string()])
    }

    fn extract_abstract(&self, document: &Html) -> Result<String> {
        let selectors = [".abstract", "#abstract", "meta[name='description']"];
        
        for selector_str in &selectors {
            if let Ok(selector) = Selector::parse(selector_str) {
                if let Some(element) = document.select(&selector).next() {
                    let text = if selector_str.starts_with("meta") {
                        element.value().attr("content").unwrap_or("").to_string()
                    } else {
                        element.text().collect::<String>()
                    };
                    
                    if !text.is_empty() && text.len() > 50 {
                        return Ok(text.trim().to_string());
                    }
                }
            }
        }
        
        Ok("No abstract available".to_string())
    }

    fn extract_categories(&self, document: &Html) -> Result<Vec<String>> {
        // Extract categories from meta tags or page content
        let mut categories = Vec::new();
        
        // Look for category meta tags
        if let Ok(selector) = Selector::parse("meta[name='keywords']") {
            if let Some(element) = document.select(&selector).next() {
                if let Some(content) = element.value().attr("content") {
                    categories.extend(
                        content.split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                    );
                }
            }
        }
        
        // Default categories for ePrint papers
        if categories.is_empty() {
            categories.push("Cryptography".to_string());
        }
        
        Ok(categories)
    }

    fn extract_date(&self, document: &Html) -> Result<String> {
        // Try to extract publication date
        let selectors = ["meta[name='date']", ".date", "time"];
        
        for selector_str in &selectors {
            if let Ok(selector) = Selector::parse(selector_str) {
                if let Some(element) = document.select(&selector).next() {
                    let date = if selector_str.starts_with("meta") {
                        element.value().attr("content").unwrap_or("").to_string()
                    } else {
                        element.text().collect::<String>()
                    };
                    
                    if !date.is_empty() {
                        return Ok(date.trim().to_string());
                    }
                }
            }
        }
        
        // Fallback to current date
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Ok(format!("{}", timestamp))
    }

    fn extract_pdf_url(&self, document: &Html, base_url: &str) -> Result<Option<String>> {
        let selectors = ["a[href$='.pdf']", "a[href*='pdf']"];
        
        for selector_str in &selectors {
            if let Ok(selector) = Selector::parse(selector_str) {
                if let Some(element) = document.select(&selector).next() {
                    if let Some(href) = element.value().attr("href") {
                        let pdf_url = if href.starts_with("http") {
                            href.to_string()
                        } else {
                            format!("{}{}", self.base_url, href)
                        };
                        return Ok(Some(pdf_url));
                    }
                }
            }
        }
        
        Ok(None)
    }

    fn extract_citations(&self, _document: &Html) -> Result<Vec<String>> {
        // Citations would need specialized parsing
        // For now, return empty vector
        Ok(Vec::new())
    }

    fn extract_references(&self, _document: &Html) -> Result<Vec<String>> {
        // References would need specialized parsing
        // For now, return empty vector
        Ok(Vec::new())
    }

    fn extract_keywords(&self, title: &str, abstract_text: &str) -> Result<Vec<String>> {
        // Simple keyword extraction - combine title and abstract text
        let combined_text = format!("{} {}", title, abstract_text);
        let words: Vec<String> = combined_text
            .split_whitespace()
            .filter(|word| word.len() > 3)
            .map(|word| word.to_lowercase())
            .filter(|word| !word.chars().any(|c| c.is_numeric()))
            .collect();
        
        // Take first 20 unique words as keywords
        let mut unique_words = Vec::new();
        for word in words {
            if !unique_words.contains(&word) {
                unique_words.push(word);
                if unique_words.len() >= 20 {
                    break;
                }
            }
        }
        
        Ok(unique_words)
    }
}