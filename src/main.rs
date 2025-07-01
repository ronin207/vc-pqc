use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::{info, error};
use tracing_subscriber;

mod scraper;
mod knowledge_graph;
mod nlp;
mod database;
mod embeddings;
mod paper_analyzer;

use scraper::EprintScraper;
use knowledge_graph::KnowledgeGraphBuilder;
use database::Database;

#[derive(Parser)]
#[command(name = "research-agent")]
#[command(about = "A research agent that scrapes cryptography papers and builds knowledge graphs")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scrape papers from eprint.iacr.org
    Scrape {
        /// Number of papers to scrape
        #[arg(short, long, default_value = "100")]
        count: usize,
        /// Year to start scraping from
        #[arg(short, long, default_value = "2020")]
        year: u32,
        /// Category filter (e.g., "crypto", "implementation")
        #[arg(short, long)]
        category: Option<String>,
    },
    /// Build knowledge graphs from scraped papers
    BuildGraph {
        /// Rebuild the entire graph from scratch
        #[arg(short, long)]
        rebuild: bool,
    },
    /// Query the knowledge graph
    Query {
        /// Query string
        query: String,
        /// Maximum number of results
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },
    /// Analyze connections between papers
    Analyze {
        /// Paper ID to analyze
        paper_id: String,
        /// Depth of analysis
        #[arg(short, long, default_value = "2")]
        depth: usize,
    },
    /// Start web interface
    Web {
        /// Port to run on
        #[arg(short, long, default_value = "8080")]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    let cli = Cli::parse();
    
    // Initialize database
    let db = Database::new("research_agent.db").await?;
    db.initialize().await?;
    
    match cli.command {
        Commands::Scrape { count, year, category } => {
            info!("Starting paper scraping from eprint.iacr.org");
            let scraper = EprintScraper::new();
            scraper.scrape_papers(count, year, category, &db).await?;
            info!("Scraping completed");
        }
        
        Commands::BuildGraph { rebuild } => {
            info!("Building knowledge graphs");
            let builder = KnowledgeGraphBuilder::new(&db);
            if rebuild {
                builder.rebuild_all_graphs().await?;
            } else {
                builder.build_incremental_graphs().await?;
            }
            info!("Knowledge graph construction completed");
        }
        
        Commands::Query { query, limit } => {
            info!("Querying knowledge graph: {}", query);
            let builder = KnowledgeGraphBuilder::new(&db);
            let results = builder.query_graph(&query, limit).await?;
            
            for result in results {
                println!("Paper: {} - Score: {:.3}", result.title, result.relevance_score);
                println!("Authors: {}", result.authors.join(", "));
                println!("Abstract: {}\n", result.abstract_summary);
            }
        }
        
        Commands::Analyze { paper_id, depth } => {
            info!("Analyzing paper connections for ID: {}", paper_id);
            let builder = KnowledgeGraphBuilder::new(&db);
            let analysis = builder.analyze_paper_connections(&paper_id, depth).await?;
            
            println!("Connection Analysis for Paper: {}", paper_id);
            println!("Direct connections: {}", analysis.direct_connections);
            println!("Citation network size: {}", analysis.citation_network_size);
            println!("Key topics: {}", analysis.key_topics.join(", "));
            println!("Related papers: {}", analysis.related_papers.len());
        }
        
        Commands::Web { port } => {
            info!("Starting web interface on port {}", port);
            // TODO: Implement web interface
            println!("Web interface not yet implemented");
        }
    }
    
    Ok(())
}