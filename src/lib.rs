//! Research Agent for Cryptography Papers
//! 
//! A comprehensive research agent that scrapes cryptography papers from eprint.iacr.org
//! and builds interconnected knowledge graphs to enable advanced analysis and discovery
//! of relationships between papers.
//! 
//! ## Features
//! 
//! - **Paper Scraping**: Intelligent scraping from IACR eprint archive
//! - **Knowledge Graphs**: Individual and interconnected knowledge graphs for papers
//! - **NLP Processing**: Entity extraction and relationship detection
//! - **Paper Analysis**: Innovation scoring, complexity assessment, and influence prediction
//! - **Semantic Search**: Query papers using natural language
//! 
//! ## Quick Start
//! 
//! ```rust,no_run
//! use research_agent::{Database, EprintScraper, KnowledgeGraphBuilder};
//! 
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Initialize database
//!     let db = Database::new("research.db").await?;
//!     db.initialize().await?;
//!     
//!     // Scrape papers
//!     let scraper = EprintScraper::new();
//!     scraper.scrape_papers(10, 2024, None, &db).await?;
//!     
//!     // Build knowledge graphs
//!     let builder = KnowledgeGraphBuilder::new(&db);
//!     builder.build_incremental_graphs().await?;
//!     
//!     // Query the graph
//!     let results = builder.query_graph("zero knowledge", 5).await?;
//!     for result in results {
//!         println!("{}: {:.3}", result.title, result.relevance_score);
//!     }
//!     
//!     Ok(())
//! }
//! ```
//! 
//! ## Modules
//! 
//! - [`scraper`]: Web scraping from eprint.iacr.org
//! - [`database`]: SQLite database operations and schema
//! - [`nlp`]: Natural language processing and entity extraction
//! - [`knowledge_graph`]: Knowledge graph construction and analysis
//! - [`embeddings`]: Semantic similarity and clustering
//! - [`paper_analyzer`]: High-level paper analysis and insights

pub mod scraper;
pub mod database;
pub mod nlp;
pub mod knowledge_graph;
pub mod embeddings;
pub mod paper_analyzer;

// Re-export commonly used types
pub use scraper::{Paper, EprintScraper};
pub use database::{Database, Entity, Relationship, PaperConnection};
pub use knowledge_graph::{KnowledgeGraph, KnowledgeGraphBuilder, QueryResult, ConnectionAnalysis};
pub use nlp::NLPProcessor;
pub use embeddings::EmbeddingGenerator;
pub use paper_analyzer::{PaperAnalyzer, PaperAnalysis};