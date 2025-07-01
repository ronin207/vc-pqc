use anyhow::Result;
use petgraph::{Graph, Directed, graph::NodeIndex};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, debug, error};

use crate::database::{Database, Entity, Relationship, PaperConnection};
use crate::nlp::NLPProcessor;
use crate::scraper::Paper;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeGraph {
    pub paper_id: String,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub metadata: GraphMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: usize,
    pub entity_id: Option<i64>,
    pub node_type: String,
    pub label: String,
    pub properties: HashMap<String, String>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub source: usize,
    pub target: usize,
    pub relationship_type: String,
    pub weight: f64,
    pub confidence: f64,
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphMetadata {
    pub created_at: String,
    pub last_updated: String,
    pub node_count: usize,
    pub edge_count: usize,
    pub paper_title: String,
    pub paper_authors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    pub paper_id: String,
    pub title: String,
    pub authors: Vec<String>,
    pub abstract_summary: String,
    pub relevance_score: f64,
    pub matching_entities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionAnalysis {
    pub paper_id: String,
    pub direct_connections: usize,
    pub citation_network_size: usize,
    pub key_topics: Vec<String>,
    pub related_papers: Vec<String>,
    pub similarity_scores: HashMap<String, f64>,
}

pub struct KnowledgeGraphBuilder<'a> {
    database: &'a Database,
    nlp_processor: NLPProcessor,
}

impl<'a> KnowledgeGraphBuilder<'a> {
    pub fn new(database: &'a Database) -> Self {
        let nlp_processor = NLPProcessor::new().expect("Failed to initialize NLP processor");
        Self {
            database,
            nlp_processor,
        }
    }

    pub async fn build_incremental_graphs(&self) -> Result<()> {
        info!("Building incremental knowledge graphs");
        
        // Get all papers from database
        let papers = self.database.get_all_papers().await?;
        
        for paper in papers {
            // Check if we already have entities for this paper
            let existing_entities = self.database.get_entities_for_paper(&paper.id).await?;
            
            if existing_entities.is_empty() {
                info!("Processing paper: {} - {}", paper.id, paper.title);
                self.process_paper(&paper).await?;
            } else {
                debug!("Paper {} already processed, skipping", paper.id);
            }
        }
        
        // Build connections between papers
        self.build_paper_connections().await?;
        
        info!("Incremental knowledge graph construction completed");
        Ok(())
    }

    pub async fn rebuild_all_graphs(&self) -> Result<()> {
        info!("Rebuilding all knowledge graphs from scratch");
        
        // Clear existing entities and relationships (if needed)
        // For now, we'll just rebuild everything
        
        let papers = self.database.get_all_papers().await?;
        
        for paper in papers {
            info!("Processing paper: {} - {}", paper.id, paper.title);
            self.process_paper(&paper).await?;
        }
        
        // Build connections between papers
        self.build_paper_connections().await?;
        
        info!("Complete knowledge graph reconstruction completed");
        Ok(())
    }

    async fn process_paper(&self, paper: &Paper) -> Result<()> {
        // Extract entities for this paper
        let entities = self.nlp_processor.extract_entities(paper).await?;
        
        // Save entities to database and collect their IDs
        let mut entity_ids = Vec::new();
        for entity in &entities {
            let entity_id = self.database.save_entity(entity).await?;
            entity_ids.push(entity_id);
        }
        
        // Now detect relationships using saved entities with IDs
        let relationships = self.nlp_processor.detect_relationships(&entities);

        // Save relationships to database
        for (source_idx, target_idx, rel_type, confidence) in &relationships {
            if *source_idx < entity_ids.len() && *target_idx < entity_ids.len() {
                let relationship = Relationship {
                    id: None,
                    source_entity_id: entity_ids[*source_idx],
                    target_entity_id: entity_ids[*target_idx],
                    relationship_type: rel_type.clone(),
                    weight: *confidence,
                    evidence: None,
                    confidence: *confidence,
                };
                
                self.database.save_relationship(&relationship).await?;
            }
        }
        
        debug!("Built knowledge graph for paper {} with {} entities and {} relationships",
              entities.len(), relationships.len(), paper.id);
        
        Ok(())
    }

    async fn build_paper_connections(&self) -> Result<()> {
        info!("Building connections between papers");
        
        let papers = self.database.get_all_papers().await?;
        let mut processed_pairs = std::collections::HashSet::new();
        
        for i in 0..papers.len() {
            for j in (i + 1)..papers.len() {
                let paper1 = &papers[i];
                let paper2 = &papers[j];
                
                // Create a unique identifier for this pair
                let pair_id = if paper1.id < paper2.id {
                    format!("{}:{}", paper1.id, paper2.id)
                } else {
                    format!("{}:{}", paper2.id, paper1.id)
                };
                
                if processed_pairs.contains(&pair_id) {
                    continue;
                }
                processed_pairs.insert(pair_id);
                
                // Calculate similarity between papers
                let similarity = self.calculate_paper_similarity(paper1, paper2).await?;
                
                if similarity > 0.1 { // Only save connections with significant similarity
                    let connection = PaperConnection {
                        id: None,
                        paper_id_1: paper1.id.clone(),
                        paper_id_2: paper2.id.clone(),
                        connection_type: "semantic_similarity".to_string(),
                        similarity_score: similarity,
                        shared_entities: 0, // Will be calculated separately
                        evidence: Some(format!("Semantic similarity: {:.3}", similarity)),
                    };
                    
                    self.database.save_paper_connection(&connection).await?;
                }
            }
        }
        
        info!("Paper connections built successfully");
        Ok(())
    }

    async fn calculate_paper_similarity(&self, paper1: &Paper, paper2: &Paper) -> Result<f64> {
        // Get entities for both papers
        let entities1 = self.database.get_entities_for_paper(&paper1.id).await?;
        let entities2 = self.database.get_entities_for_paper(&paper2.id).await?;
        
        // Calculate entity-based similarity
        let entity_similarity = self.nlp_processor.calculate_entity_similarity(&entities1, &entities2);
        
        // Calculate text-based similarity
        let text1 = format!("{} {}", paper1.title, paper1.abstract_text);
        let text2 = format!("{} {}", paper2.title, paper2.abstract_text);
        let text_similarity = self.nlp_processor.calculate_text_similarity(&text1, &text2);
        
        // Calculate author overlap
        let author_similarity = self.calculate_author_similarity(&paper1.authors, &paper2.authors);
        
        // Weighted combination of similarities
        let combined_similarity = 
            0.5 * entity_similarity + 
            0.3 * text_similarity + 
            0.2 * author_similarity;
        
        Ok(combined_similarity)
    }

    fn calculate_author_similarity(&self, authors1: &[String], authors2: &[String]) -> f64 {
        if authors1.is_empty() || authors2.is_empty() {
            return 0.0;
        }
        
        let set1: std::collections::HashSet<_> = authors1.iter().collect();
        let set2: std::collections::HashSet<_> = authors2.iter().collect();
        
        let intersection = set1.intersection(&set2).count();
        let union = set1.union(&set2).count();
        
        if union == 0 {
            0.0
        } else {
            intersection as f64 / union as f64
        }
    }

    pub async fn get_knowledge_graph(&self, paper_id: &str) -> Result<Option<KnowledgeGraph>> {
        // Get paper details
        let paper = match self.database.get_paper(paper_id).await? {
            Some(p) => p,
            None => return Ok(None),
        };
        
        // Get entities for the paper
        let entities = self.database.get_entities_for_paper(paper_id).await?;
        
        // Create graph nodes
        let mut nodes = Vec::new();
        let mut entity_to_node: HashMap<i64, usize> = HashMap::new();
        
        for (idx, entity) in entities.iter().enumerate() {
            if let Some(entity_id) = entity.id {
                entity_to_node.insert(entity_id, idx);
            }
            
            let mut properties = HashMap::new();
            properties.insert("type".to_string(), entity.entity_type.clone());
            if let Some(ref value) = entity.entity_value {
                properties.insert("value".to_string(), value.clone());
            }
            if let Some(ref context) = entity.context {
                properties.insert("context".to_string(), context.clone());
            }
            
            nodes.push(GraphNode {
                id: idx,
                entity_id: entity.id,
                node_type: entity.entity_type.clone(),
                label: entity.entity_name.clone(),
                properties,
                confidence: entity.confidence,
            });
        }
        
        // Get relationships and create edges
        let mut edges = Vec::new();
        // This would require a more complex query to get relationships for specific entities
        // For now, we'll create a simplified version
        
        let metadata = GraphMetadata {
            created_at: chrono::Utc::now().to_rfc3339(),
            last_updated: chrono::Utc::now().to_rfc3339(),
            node_count: nodes.len(),
            edge_count: edges.len(),
            paper_title: paper.title.clone(),
            paper_authors: paper.authors.clone(),
        };
        
        Ok(Some(KnowledgeGraph {
            paper_id: paper_id.to_string(),
            nodes,
            edges,
            metadata,
        }))
    }

    pub async fn query_graph(&self, query: &str, limit: usize) -> Result<Vec<QueryResult>> {
        // Simple text-based search for now
        let papers = self.database.search_papers(query, limit).await?;
        
        let mut results = Vec::new();
        for paper in papers {
            // Get entities to find matching ones
            let entities = self.database.get_entities_for_paper(&paper.id).await?;
            let matching_entities: Vec<String> = entities
                .iter()
                .filter(|e| e.entity_name.to_lowercase().contains(&query.to_lowercase()))
                .map(|e| e.entity_name.clone())
                .collect();
            
            // Calculate relevance score based on matches
            let relevance_score = self.calculate_relevance_score(&paper, query, &matching_entities);
            
            // Create abstract summary (truncated)
            let abstract_summary = if paper.abstract_text.len() > 200 {
                format!("{}...", &paper.abstract_text[..200])
            } else {
                paper.abstract_text.clone()
            };
            
            results.push(QueryResult {
                paper_id: paper.id,
                title: paper.title,
                authors: paper.authors,
                abstract_summary,
                relevance_score,
                matching_entities,
            });
        }
        
        // Sort by relevance score
        results.sort_by(|a, b| b.relevance_score.partial_cmp(&a.relevance_score).unwrap());
        
        Ok(results)
    }

    fn calculate_relevance_score(&self, paper: &Paper, query: &str, matching_entities: &[String]) -> f64 {
        let query_lower = query.to_lowercase();
        let mut score = 0.0;
        
        // Title match (highest weight)
        if paper.title.to_lowercase().contains(&query_lower) {
            score += 0.5;
        }
        
        // Abstract match
        if paper.abstract_text.to_lowercase().contains(&query_lower) {
            score += 0.3;
        }
        
        // Entity matches
        score += 0.2 * (matching_entities.len() as f64 / 10.0).min(1.0);
        
        // Keywords match
        let keyword_matches = paper.keywords.iter()
            .filter(|k| k.to_lowercase().contains(&query_lower))
            .count();
        score += 0.1 * (keyword_matches as f64 / 5.0).min(1.0);
        
        score.min(1.0)
    }

    pub async fn analyze_paper_connections(&self, paper_id: &str, depth: usize) -> Result<ConnectionAnalysis> {
        // Get direct connections
        let connections = self.database.get_paper_connections(paper_id).await?;
        
        // Get entities for topic analysis
        let entities = self.database.get_entities_for_paper(paper_id).await?;
        let key_topics: Vec<String> = entities
            .iter()
            .filter(|e| e.confidence > 0.8)
            .take(10)
            .map(|e| e.entity_name.clone())
            .collect();
        
        // Get related papers
        let mut related_papers = Vec::new();
        let mut similarity_scores = HashMap::new();
        
        for connection in &connections {
            let related_paper_id = if connection.paper_id_1 == paper_id {
                &connection.paper_id_2
            } else {
                &connection.paper_id_1
            };
            
            related_papers.push(related_paper_id.clone());
            similarity_scores.insert(related_paper_id.clone(), connection.similarity_score);
        }
        
        // For now, citation network size is approximated by direct connections
        let citation_network_size = connections.len();
        
        Ok(ConnectionAnalysis {
            paper_id: paper_id.to_string(),
            direct_connections: connections.len(),
            citation_network_size,
            key_topics,
            related_papers,
            similarity_scores,
        })
    }

    pub async fn get_connected_papers(&self, paper_id: &str, min_similarity: f64) -> Result<Vec<Paper>> {
        let connections = self.database.get_paper_connections(paper_id).await?;
        let mut connected_papers = Vec::new();
        
        for connection in connections {
            if connection.similarity_score >= min_similarity {
                let connected_paper_id = if connection.paper_id_1 == paper_id {
                    &connection.paper_id_2
                } else {
                    &connection.paper_id_1
                };
                
                if let Some(paper) = self.database.get_paper(connected_paper_id).await? {
                    connected_papers.push(paper);
                }
            }
        }
        
        Ok(connected_papers)
    }

    pub async fn export_graph_data(&self, paper_id: &str, format: &str) -> Result<String> {
        let graph = self.get_knowledge_graph(paper_id).await?;
        
        match graph {
            Some(kg) => {
                match format.to_lowercase().as_str() {
                    "json" => Ok(serde_json::to_string_pretty(&kg)?),
                    "dot" => self.export_as_dot(&kg),
                    _ => Err(anyhow::anyhow!("Unsupported export format: {}", format)),
                }
            }
            None => Err(anyhow::anyhow!("Knowledge graph not found for paper: {}", paper_id)),
        }
    }

    fn export_as_dot(&self, graph: &KnowledgeGraph) -> Result<String> {
        let mut dot = String::new();
        dot.push_str(&format!("digraph \"{}\" {{\n", graph.paper_id));
        dot.push_str("  rankdir=LR;\n");
        dot.push_str("  node [shape=ellipse];\n\n");
        
        // Add nodes
        for node in &graph.nodes {
            dot.push_str(&format!(
                "  \"{}\" [label=\"{}\" color=\"{}\"];\n",
                node.id,
                node.label,
                self.get_node_color(&node.node_type)
            ));
        }
        
        // Add edges
        for edge in &graph.edges {
            dot.push_str(&format!(
                "  \"{}\" -> \"{}\" [label=\"{}\" weight={}];\n",
                edge.source,
                edge.target,
                edge.relationship_type,
                edge.weight
            ));
        }
        
        dot.push_str("}\n");
        Ok(dot)
    }

    fn get_node_color(&self, node_type: &str) -> &str {
        match node_type {
            "cryptographic_algorithm" => "red",
            "mathematical_concept" => "blue",
            "security_property" => "green",
            "author" => "purple",
            "keyword" => "orange",
            "category" => "brown",
            _ => "black",
        }
    }
}