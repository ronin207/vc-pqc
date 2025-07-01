use anyhow::Result;
use research_agent::database::Database;
use research_agent::scraper::{EprintScraper, Paper};
use research_agent::knowledge_graph::KnowledgeGraphBuilder;
use research_agent::nlp::NLPProcessor;
use research_agent::paper_analyzer::PaperAnalyzer;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    println!("🔬 Research Agent Demo");
    println!("=====================\n");
    
    // Initialize database
    println!("📊 Initializing database...");
    let db = Database::new("demo.db").await?;
    db.initialize().await?;
    println!("✅ Database ready\n");
    
    // Demo 1: Create sample papers (simulating scraped data)
    println!("📄 Creating sample papers...");
    let sample_papers = create_sample_papers();
    
    for paper in &sample_papers {
        db.save_paper(paper).await?;
        println!("  Saved: {}", paper.title);
    }
    println!("✅ {} papers saved\n", sample_papers.len());
    
    // Demo 2: Extract entities and build knowledge graphs
    println!("🧠 Building knowledge graphs...");
    let builder = KnowledgeGraphBuilder::new(&db);
    builder.build_incremental_graphs().await?;
    println!("✅ Knowledge graphs built\n");
    
    // Demo 3: Query the knowledge graph
    println!("🔍 Querying knowledge graph...");
    let query_results = builder.query_graph("zero knowledge", 3).await?;
    
    println!("Query: 'zero knowledge'");
    for result in query_results {
        println!("  📋 {} (Score: {:.3})", result.title, result.relevance_score);
        println!("     Authors: {}", result.authors.join(", "));
        println!("     Entities: {}", result.matching_entities.join(", "));
        println!();
    }
    
    // Demo 4: Analyze a specific paper
    println!("📈 Analyzing paper...");
    if let Some(paper_id) = sample_papers.first().map(|p| &p.id) {
        let mut analyzer = PaperAnalyzer::new(&db)?;
        let analysis = analyzer.analyze_paper(paper_id).await?;
        
        println!("Analysis for: {}", analysis.title);
        println!("  🔬 Research Domain: {}", analysis.analysis_summary.research_domain);
        println!("  💡 Innovation Score: {:.3}", analysis.innovation_score);
        println!("  🧮 Complexity Score: {:.3}", analysis.complexity_score);
        println!("  📊 Influence Potential: {:.3}", analysis.influence_potential);
        println!("  🔑 Key Algorithms: {}", analysis.analysis_summary.key_algorithms.join(", "));
        println!("  🛡️  Security Properties: {}", analysis.analysis_summary.security_properties.join(", "));
        println!();
    }
    
    // Demo 5: Show paper connections
    println!("🔗 Analyzing paper connections...");
    if let Some(paper_id) = sample_papers.first().map(|p| &p.id) {
        let connections = builder.analyze_paper_connections(paper_id, 2).await?;
        
        println!("Connections for paper: {}", paper_id);
        println!("  📊 Direct connections: {}", connections.direct_connections);
        println!("  🏷️  Key topics: {}", connections.key_topics.join(", "));
        println!("  📚 Related papers: {}", connections.related_papers.len());
        
        if !connections.related_papers.is_empty() {
            println!("  🔍 Most similar papers:");
            for (related_id, score) in connections.similarity_scores.iter().take(3) {
                println!("    - {} (similarity: {:.3})", related_id, score);
            }
        }
        println!();
    }
    
    // Demo 6: Export graph data
    println!("📤 Exporting graph data...");
    if let Some(paper_id) = sample_papers.first().map(|p| &p.id) {
        let graph_json = builder.export_graph_data(paper_id, "json").await?;
        println!("  Graph exported to JSON ({} characters)", graph_json.len());
        
        // Save to file for inspection
        std::fs::write("demo_graph.json", &graph_json)?;
        println!("  📁 Saved to demo_graph.json");
        println!();
    }
    
    println!("🎉 Demo completed successfully!");
    println!("\nNext steps:");
    println!("  1. Run `cargo run scrape --count 10 --year 2024` to scrape real papers");
    println!("  2. Use `cargo run query \"your topic\"` to search the knowledge graph");
    println!("  3. Analyze specific papers with `cargo run analyze <paper-id>`");
    
    Ok(())
}

fn create_sample_papers() -> Vec<Paper> {
    vec![
        Paper {
            id: "2024/001".to_string(),
            title: "Novel Zero-Knowledge Proof Systems for Post-Quantum Cryptography".to_string(),
            authors: vec!["Alice Cryptographer".to_string(), "Bob Prover".to_string()],
            abstract_text: "We present novel zero-knowledge proof systems that are secure against quantum adversaries. Our approach uses lattice-based cryptography and provides succinct proofs with post-quantum security guarantees. We demonstrate applications to blockchain and privacy-preserving protocols.".to_string(),
            categories: vec!["Zero-Knowledge".to_string(), "Post-Quantum".to_string()],
            publication_date: "2024-01-15".to_string(),
            url: "https://eprint.iacr.org/2024/001".to_string(),
            pdf_url: Some("https://eprint.iacr.org/2024/001.pdf".to_string()),
            citations: vec![],
            references: vec!["2023/456".to_string(), "2022/789".to_string()],
            keywords: vec!["zero-knowledge".to_string(), "lattice".to_string(), "post-quantum".to_string(), "blockchain".to_string()],
        },
        Paper {
            id: "2024/002".to_string(),
            title: "Efficient SNARK Construction from RLWE Assumptions".to_string(),
            authors: vec!["Charlie Researcher".to_string(), "Diana Verifier".to_string()],
            abstract_text: "This paper introduces an efficient SNARK construction based on Ring Learning With Errors (RLWE) assumptions. We achieve constant-size proofs and logarithmic verification time. Our construction is the first to combine the efficiency of SNARKs with post-quantum security from lattice assumptions.".to_string(),
            categories: vec!["SNARK".to_string(), "Lattice Cryptography".to_string()],
            publication_date: "2024-02-20".to_string(),
            url: "https://eprint.iacr.org/2024/002".to_string(),
            pdf_url: Some("https://eprint.iacr.org/2024/002.pdf".to_string()),
            citations: vec![],
            references: vec!["2024/001".to_string(), "2023/123".to_string()],
            keywords: vec!["snark".to_string(), "rlwe".to_string(), "lattice".to_string(), "verification".to_string()],
        },
        Paper {
            id: "2024/003".to_string(),
            title: "Homomorphic Encryption for Secure Multi-Party Computation".to_string(),
            authors: vec!["Eve Encryptor".to_string(), "Frank Computer".to_string(), "Grace Hider".to_string()],
            abstract_text: "We develop new homomorphic encryption schemes optimized for secure multi-party computation. Our construction supports arbitrary depth circuits and achieves practical performance for real-world applications. We provide both theoretical analysis and experimental evaluation.".to_string(),
            categories: vec!["Homomorphic Encryption".to_string(), "MPC".to_string()],
            publication_date: "2024-03-10".to_string(),
            url: "https://eprint.iacr.org/2024/003".to_string(),
            pdf_url: Some("https://eprint.iacr.org/2024/003.pdf".to_string()),
            citations: vec![],
            references: vec!["2023/999".to_string(), "2022/888".to_string()],
            keywords: vec!["homomorphic".to_string(), "encryption".to_string(), "mpc".to_string(), "circuits".to_string()],
        },
    ]
}