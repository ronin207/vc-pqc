use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::{info, debug};

use crate::database::{Database, Entity};
use crate::scraper::Paper;
use crate::nlp::NLPProcessor;
use crate::embeddings::EmbeddingGenerator;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaperAnalysis {
    pub paper_id: String,
    pub title: String,
    pub analysis_summary: AnalysisSummary,
    pub entity_analysis: EntityAnalysis,
    pub topic_analysis: TopicAnalysis,
    pub relationship_analysis: RelationshipAnalysis,
    pub innovation_score: f64,
    pub complexity_score: f64,
    pub influence_potential: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSummary {
    pub main_contributions: Vec<String>,
    pub key_algorithms: Vec<String>,
    pub security_properties: Vec<String>,
    pub mathematical_foundations: Vec<String>,
    pub research_domain: String,
    pub novelty_indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityAnalysis {
    pub entity_count_by_type: HashMap<String, usize>,
    pub high_confidence_entities: Vec<String>,
    pub entity_interconnections: usize,
    pub unique_entities: usize,
    pub shared_entities_with_others: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicAnalysis {
    pub primary_topics: Vec<String>,
    pub secondary_topics: Vec<String>,
    pub topic_coherence_score: f64,
    pub cross_domain_indicators: Vec<String>,
    pub emerging_topics: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipAnalysis {
    pub citation_patterns: CitationPatterns,
    pub collaboration_network: CollaborationNetwork,
    pub conceptual_relationships: Vec<ConceptualRelationship>,
    pub influence_metrics: InfluenceMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CitationPatterns {
    pub citing_papers: usize,
    pub cited_papers: usize,
    pub self_citations: usize,
    pub cross_domain_citations: usize,
    pub temporal_citation_trend: Vec<(String, usize)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollaborationNetwork {
    pub co_authors: Vec<String>,
    pub institutional_affiliations: Vec<String>,
    pub collaboration_frequency: HashMap<String, usize>,
    pub network_centrality_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConceptualRelationship {
    pub related_paper_id: String,
    pub relationship_type: String,
    pub strength: f64,
    pub shared_concepts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfluenceMetrics {
    pub citation_count: usize,
    pub h_index_contribution: f64,
    pub field_impact_score: f64,
    pub innovation_index: f64,
    pub practical_impact_score: f64,
}

pub struct PaperAnalyzer<'a> {
    database: &'a Database,
    nlp_processor: NLPProcessor,
    embedding_generator: EmbeddingGenerator,
}

impl<'a> PaperAnalyzer<'a> {
    pub fn new(database: &'a Database) -> Result<Self> {
        let nlp_processor = NLPProcessor::new()?;
        let embedding_generator = EmbeddingGenerator::new(256); // 256-dimensional embeddings
        
        Ok(Self {
            database,
            nlp_processor,
            embedding_generator,
        })
    }

    pub async fn analyze_paper(&mut self, paper_id: &str) -> Result<PaperAnalysis> {
        info!("Analyzing paper: {}", paper_id);
        
        // Get paper and its entities
        let paper = self.database.get_paper(paper_id).await?
            .ok_or_else(|| anyhow::anyhow!("Paper not found: {}", paper_id))?;
        
        let entities = self.database.get_entities_for_paper(paper_id).await?;
        
        // Perform different types of analysis
        let analysis_summary = self.generate_analysis_summary(&paper, &entities).await?;
        let entity_analysis = self.analyze_entities(&entities).await?;
        let topic_analysis = self.analyze_topics(&paper, &entities).await?;
        let relationship_analysis = self.analyze_relationships(&paper).await?;
        
        // Calculate composite scores
        let innovation_score = self.calculate_innovation_score(&paper, &entities).await?;
        let complexity_score = self.calculate_complexity_score(&paper, &entities).await?;
        let influence_potential = self.calculate_influence_potential(&paper, &entities).await?;
        
        Ok(PaperAnalysis {
            paper_id: paper_id.to_string(),
            title: paper.title.clone(),
            analysis_summary,
            entity_analysis,
            topic_analysis,
            relationship_analysis,
            innovation_score,
            complexity_score,
            influence_potential,
        })
    }

    async fn generate_analysis_summary(&self, paper: &Paper, entities: &[Entity]) -> Result<AnalysisSummary> {
        let mut main_contributions = Vec::new();
        let mut key_algorithms = Vec::new();
        let mut security_properties = Vec::new();
        let mut mathematical_foundations = Vec::new();
        let mut novelty_indicators = Vec::new();
        
        // Extract key information from entities
        for entity in entities {
            match entity.entity_type.as_str() {
                "cryptographic_algorithm" => {
                    if entity.confidence > 0.8 {
                        key_algorithms.push(entity.entity_name.clone());
                    }
                }
                "security_property" => {
                    if entity.confidence > 0.8 {
                        security_properties.push(entity.entity_name.clone());
                    }
                }
                "mathematical_concept" => {
                    if entity.confidence > 0.8 {
                        mathematical_foundations.push(entity.entity_name.clone());
                    }
                }
                _ => {}
            }
        }
        
        // Extract main contributions from title and abstract
        let key_phrases = self.nlp_processor.extract_key_phrases(&paper.abstract_text, 5);
        main_contributions.extend(key_phrases);
        
        // Detect novelty indicators
        let novelty_words = ["novel", "new", "first", "innovative", "breakthrough", "pioneering"];
        for word in novelty_words {
            if paper.title.to_lowercase().contains(word) || paper.abstract_text.to_lowercase().contains(word) {
                novelty_indicators.push(format!("Contains '{}'", word));
            }
        }
        
        // Determine research domain
        let research_domain = self.determine_research_domain(&key_algorithms, &security_properties);
        
        Ok(AnalysisSummary {
            main_contributions,
            key_algorithms,
            security_properties,
            mathematical_foundations,
            research_domain,
            novelty_indicators,
        })
    }

    fn determine_research_domain(&self, algorithms: &[String], properties: &[String]) -> String {
        // Simple heuristic to determine research domain
        let mut domain_scores: HashMap<String, f64> = HashMap::new();
        
        let domain_keywords = vec![
            ("Post-Quantum Cryptography", vec!["kyber", "dilithium", "falcon", "lattice", "lwe", "rlwe"]),
            ("Zero-Knowledge Proofs", vec!["snark", "stark", "zkp", "zero knowledge", "proof"]),
            ("Blockchain Cryptography", vec!["signature", "hash", "merkle", "consensus"]),
            ("Symmetric Cryptography", vec!["aes", "chacha", "stream cipher", "block cipher"]),
            ("Asymmetric Cryptography", vec!["rsa", "ecc", "elliptic curve", "discrete logarithm"]),
            ("Secure Computation", vec!["mpc", "homomorphic", "secret sharing", "garbled circuits"]),
        ];
        
        for (domain, keywords) in domain_keywords {
            let mut score = 0.0;
            for keyword in keywords {
                for alg in algorithms {
                    if alg.to_lowercase().contains(keyword) {
                        score += 1.0;
                    }
                }
                for prop in properties {
                    if prop.to_lowercase().contains(keyword) {
                        score += 0.5;
                    }
                }
            }
            domain_scores.insert(domain.to_string(), score);
        }
        
        domain_scores
            .into_iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
            .map(|(domain, _)| domain)
            .unwrap_or_else(|| "General Cryptography".to_string())
    }

    async fn analyze_entities(&self, entities: &[Entity]) -> Result<EntityAnalysis> {
        let mut entity_count_by_type: HashMap<String, usize> = HashMap::new();
        let mut high_confidence_entities = Vec::new();
        
        for entity in entities {
            *entity_count_by_type.entry(entity.entity_type.clone()).or_insert(0) += 1;
            
            if entity.confidence > 0.9 {
                high_confidence_entities.push(entity.entity_name.clone());
            }
        }
        
        // Calculate interconnections (simplified)
        let entity_interconnections = entities.len() * entities.len() / 10; // Placeholder calculation
        let unique_entities = entities.len();
        let shared_entities_with_others = 0; // Would require comparison with other papers
        
        Ok(EntityAnalysis {
            entity_count_by_type,
            high_confidence_entities,
            entity_interconnections,
            unique_entities,
            shared_entities_with_others,
        })
    }

    async fn analyze_topics(&self, paper: &Paper, entities: &[Entity]) -> Result<TopicAnalysis> {
        // Extract topics from entities and content
        let mut primary_topics = Vec::new();
        let mut secondary_topics = Vec::new();
        let mut cross_domain_indicators = Vec::new();
        
        // Group entities by type to identify primary topics
        let mut topic_strength: HashMap<String, f64> = HashMap::new();
        
        for entity in entities {
            let strength = entity.confidence;
            *topic_strength.entry(entity.entity_name.clone()).or_insert(0.0) += strength;
        }
        
        // Sort topics by strength
        let mut sorted_topics: Vec<_> = topic_strength.into_iter().collect();
        sorted_topics.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        
        // Split into primary and secondary
        let split_point = std::cmp::min(5, sorted_topics.len());
        primary_topics = sorted_topics[..split_point].iter()
            .map(|(topic, _)| topic.clone())
            .collect();
        
        if sorted_topics.len() > split_point {
            secondary_topics = sorted_topics[split_point..std::cmp::min(split_point + 5, sorted_topics.len())].iter()
                .map(|(topic, _)| topic.clone())
                .collect();
        }
        
        // Detect cross-domain indicators
        let domains = ["cryptography", "machine learning", "quantum", "blockchain", "security"];
        let text = format!("{} {}", paper.title, paper.abstract_text).to_lowercase();
        
        let mut domain_mentions = 0;
        for domain in domains {
            if text.contains(domain) {
                domain_mentions += 1;
                cross_domain_indicators.push(domain.to_string());
            }
        }
        
        // Calculate topic coherence (simplified)
        let topic_coherence_score = if primary_topics.len() > 0 {
            1.0 / (primary_topics.len() as f64).sqrt()
        } else {
            0.0
        };
        
        // Detect emerging topics (placeholder)
        let emerging_topics = vec!["quantum-resistant".to_string(), "ai-assisted".to_string()];
        
        Ok(TopicAnalysis {
            primary_topics,
            secondary_topics,
            topic_coherence_score,
            cross_domain_indicators,
            emerging_topics,
        })
    }

    async fn analyze_relationships(&self, paper: &Paper) -> Result<RelationshipAnalysis> {
        // Get paper connections
        let connections = self.database.get_paper_connections(&paper.id).await?;
        
        // Analyze citation patterns (simplified since we don't have real citation data)
        let citation_patterns = CitationPatterns {
            citing_papers: connections.len(),
            cited_papers: paper.references.len(),
            self_citations: 0,
            cross_domain_citations: 0,
            temporal_citation_trend: vec![],
        };
        
        // Analyze collaboration network
        let collaboration_network = CollaborationNetwork {
            co_authors: paper.authors.clone(),
            institutional_affiliations: vec![], // Would need to extract from author data
            collaboration_frequency: HashMap::new(),
            network_centrality_score: 0.5, // Placeholder
        };
        
        // Analyze conceptual relationships
        let mut conceptual_relationships = Vec::new();
        for connection in &connections {
            let related_paper_id = if connection.paper_id_1 == paper.id {
                &connection.paper_id_2
            } else {
                &connection.paper_id_1
            };
            
            conceptual_relationships.push(ConceptualRelationship {
                related_paper_id: related_paper_id.clone(),
                relationship_type: connection.connection_type.clone(),
                strength: connection.similarity_score,
                shared_concepts: vec![], // Would need to calculate
            });
        }
        
        // Calculate influence metrics
        let influence_metrics = InfluenceMetrics {
            citation_count: connections.len(),
            h_index_contribution: (connections.len() as f64).sqrt(),
            field_impact_score: 0.5, // Placeholder
            innovation_index: 0.5, // Placeholder
            practical_impact_score: 0.5, // Placeholder
        };
        
        Ok(RelationshipAnalysis {
            citation_patterns,
            collaboration_network,
            conceptual_relationships,
            influence_metrics,
        })
    }

    async fn calculate_innovation_score(&self, paper: &Paper, entities: &[Entity]) -> Result<f64> {
        let mut score = 0.0;
        
        // Novelty indicators in title/abstract
        let novelty_words = ["novel", "new", "first", "innovative", "breakthrough", "pioneering"];
        let text = format!("{} {}", paper.title, paper.abstract_text).to_lowercase();
        
        for word in novelty_words {
            if text.contains(word) {
                score += 0.1;
            }
        }
        
        // Unique entity combinations
        let unique_algorithms = entities.iter()
            .filter(|e| e.entity_type == "cryptographic_algorithm")
            .count();
        score += (unique_algorithms as f64) * 0.05;
        
        // Cross-domain elements
        let domains = ["quantum", "machine learning", "blockchain", "ai"];
        for domain in domains {
            if text.contains(domain) {
                score += 0.15;
            }
        }
        
        Ok(score.min(1.0))
    }

    async fn calculate_complexity_score(&self, paper: &Paper, entities: &[Entity]) -> Result<f64> {
        let mut score = 0.0;
        
        // Number of mathematical concepts
        let math_concepts = entities.iter()
            .filter(|e| e.entity_type == "mathematical_concept")
            .count();
        score += (math_concepts as f64) * 0.1;
        
        // Abstract length (longer abstracts often indicate more complex work)
        let abstract_length = paper.abstract_text.split_whitespace().count();
        score += (abstract_length as f64 / 1000.0).min(0.3);
        
        // Number of different entity types
        let entity_types: HashSet<_> = entities.iter()
            .map(|e| &e.entity_type)
            .collect();
        score += (entity_types.len() as f64) * 0.1;
        
        Ok(score.min(1.0))
    }

    async fn calculate_influence_potential(&self, paper: &Paper, entities: &[Entity]) -> Result<f64> {
        let mut score = 0.0;
        
        // High-confidence entities suggest clear contributions
        let high_conf_entities = entities.iter()
            .filter(|e| e.confidence > 0.9)
            .count();
        score += (high_conf_entities as f64) * 0.1;
        
        // Practical security properties
        let security_entities = entities.iter()
            .filter(|e| e.entity_type == "security_property")
            .count();
        score += (security_entities as f64) * 0.15;
        
        // Author count (more authors might indicate broader impact)
        score += (paper.authors.len() as f64) * 0.05;
        
        // Trendy keywords
        let trendy_keywords = ["post-quantum", "zero-knowledge", "blockchain", "ai", "quantum"];
        let text = format!("{} {}", paper.title, paper.abstract_text).to_lowercase();
        
        for keyword in trendy_keywords {
            if text.contains(keyword) {
                score += 0.1;
            }
        }
        
        Ok(score.min(1.0))
    }

    pub async fn compare_papers(&mut self, paper_id1: &str, paper_id2: &str) -> Result<PaperComparison> {
        let analysis1 = self.analyze_paper(paper_id1).await?;
        let analysis2 = self.analyze_paper(paper_id2).await?;
        
        let shared_topics = self.find_shared_elements(&analysis1.topic_analysis.primary_topics, 
                                                     &analysis2.topic_analysis.primary_topics);
        
        let shared_algorithms = self.find_shared_elements(&analysis1.analysis_summary.key_algorithms,
                                                         &analysis2.analysis_summary.key_algorithms);
        
        Ok(PaperComparison {
            paper1: analysis1,
            paper2: analysis2,
            shared_topics,
            shared_algorithms,
            similarity_score: 0.5, // Placeholder
            relationship_strength: 0.5, // Placeholder
        })
    }

    fn find_shared_elements(&self, list1: &[String], list2: &[String]) -> Vec<String> {
        let set1: HashSet<_> = list1.iter().collect();
        let set2: HashSet<_> = list2.iter().collect();
        
        set1.intersection(&set2)
            .map(|s| s.to_string())
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaperComparison {
    pub paper1: PaperAnalysis,
    pub paper2: PaperAnalysis,
    pub shared_topics: Vec<String>,
    pub shared_algorithms: Vec<String>,
    pub similarity_score: f64,
    pub relationship_strength: f64,
}