use anyhow::Result;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use unicode_normalization::UnicodeNormalization;
use tracing::{debug, info};

use crate::database::Entity;
use crate::scraper::Paper;

pub struct NLPProcessor {
    // Pre-compiled regex patterns for entity extraction
    crypto_algorithms: Regex,
    mathematical_concepts: Regex,
    security_properties: Regex,
    authors_pattern: Regex,
    citations_pattern: Regex,
    stop_words: HashSet<String>,
}

impl NLPProcessor {
    pub fn new() -> Result<Self> {
        let stop_words = Self::load_stop_words();
        
        Ok(Self {
            crypto_algorithms: Regex::new(r"\b(?i)(AES|RSA|ECC|ECDSA|SHA|MD5|DES|DH|Diffie[- ]?Hellman|ElGamal|Paillier|BLS|Schnorr|DSA|ECDH|ChaCha|Poly1305|Curve25519|secp256k1|NTRU|Kyber|Dilithium|Falcon|SPHINCS|McEliece|Goppa|LWE|RLWE|MLWE|lattice|isogeny|SIKE|SIDH)\b")?,
            mathematical_concepts: Regex::new(r"\b(?i)(polynomial|matrix|vector|field|ring|group|elliptic curve|discrete logarithm|factorization|prime|modular|arithmetic|algebraic|geometric|homomorphic|zero[- ]?knowledge|SNARK|STARK|commitment|proof|verifier|prover|simulator|reduction|hardness|assumption|security|indistinguishability|semantic)\b")?,
            security_properties: Regex::new(r"\b(?i)(CPA|CCA|IND|semantic security|perfect forward secrecy|PFS|authentication|integrity|confidentiality|non[- ]?repudiation|anonymity|unlinkability|unforgeability|soundness|completeness|extractability|simulatability|composability|UC|ROM|QROM|post[- ]?quantum|classical|quantum)\b")?,
            authors_pattern: Regex::new(r"\b[A-Z][a-z]+ [A-Z][a-z]+\b")?,
            citations_pattern: Regex::new(r"\[(\d+)\]|\(([^)]+\d{4}[^)]*)\)")?,
            stop_words,
        })
    }

    fn load_stop_words() -> HashSet<String> {
        // Common English stop words plus domain-specific ones
        let words = vec![
            "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for", "of", "with",
            "by", "from", "up", "about", "into", "through", "during", "before", "after", "above",
            "below", "between", "among", "this", "that", "these", "those", "i", "me", "my", "myself",
            "we", "our", "ours", "ourselves", "you", "your", "yours", "yourself", "yourselves",
            "he", "him", "his", "himself", "she", "her", "hers", "herself", "it", "its", "itself",
            "they", "them", "their", "theirs", "themselves", "what", "which", "who", "whom",
            "whose", "this", "that", "these", "those", "am", "is", "are", "was", "were", "be",
            "been", "being", "have", "has", "had", "having", "do", "does", "did", "doing",
            "will", "would", "could", "should", "may", "might", "must", "can", "shall",
            // Domain-specific stop words
            "paper", "work", "approach", "method", "scheme", "algorithm", "system", "protocol",
            "implementation", "analysis", "study", "research", "result", "conclusion", "abstract",
            "introduction", "section", "figure", "table", "appendix", "reference", "citation",
        ];
        
        words.into_iter().map(|s| s.to_lowercase()).collect()
    }

    pub async fn extract_entities(&self, paper: &Paper) -> Result<Vec<Entity>> {
        let mut entities = Vec::new();
        
        // Combine title and abstract for entity extraction
        let text = format!("{} {}", paper.title, paper.abstract_text);
        let normalized_text = self.normalize_text(&text);
        
        // Extract different types of entities
        entities.extend(self.extract_crypto_algorithms(&paper.id, &normalized_text)?);
        entities.extend(self.extract_mathematical_concepts(&paper.id, &normalized_text)?);
        entities.extend(self.extract_security_properties(&paper.id, &normalized_text)?);
        entities.extend(self.extract_author_entities(&paper.id, &paper.authors)?);
        entities.extend(self.extract_keyword_entities(&paper.id, &paper.keywords)?);
        entities.extend(self.extract_category_entities(&paper.id, &paper.categories)?);
        
        info!("Extracted {} entities from paper {}", entities.len(), paper.id);
        Ok(entities)
    }

    fn normalize_text(&self, text: &str) -> String {
        text.nfd()
            .filter(|c| !c.is_control())
            .collect::<String>()
            .to_lowercase()
    }

    fn extract_crypto_algorithms(&self, paper_id: &str, text: &str) -> Result<Vec<Entity>> {
        let mut entities = Vec::new();
        let mut seen = HashSet::new();
        
        for capture in self.crypto_algorithms.find_iter(text) {
            let algorithm = capture.as_str().to_lowercase();
            if seen.insert(algorithm.clone()) {
                entities.push(Entity {
                    id: None,
                    paper_id: paper_id.to_string(),
                    entity_type: "cryptographic_algorithm".to_string(),
                    entity_name: algorithm,
                    entity_value: None,
                    confidence: 0.9,
                    context: Some(self.get_context(text, capture.start(), capture.end())),
                });
            }
        }
        
        Ok(entities)
    }

    fn extract_mathematical_concepts(&self, paper_id: &str, text: &str) -> Result<Vec<Entity>> {
        let mut entities = Vec::new();
        let mut seen = HashSet::new();
        
        for capture in self.mathematical_concepts.find_iter(text) {
            let concept = capture.as_str().to_lowercase();
            if seen.insert(concept.clone()) {
                entities.push(Entity {
                    id: None,
                    paper_id: paper_id.to_string(),
                    entity_type: "mathematical_concept".to_string(),
                    entity_name: concept,
                    entity_value: None,
                    confidence: 0.8,
                    context: Some(self.get_context(text, capture.start(), capture.end())),
                });
            }
        }
        
        Ok(entities)
    }

    fn extract_security_properties(&self, paper_id: &str, text: &str) -> Result<Vec<Entity>> {
        let mut entities = Vec::new();
        let mut seen = HashSet::new();
        
        for capture in self.security_properties.find_iter(text) {
            let property = capture.as_str().to_lowercase();
            if seen.insert(property.clone()) {
                entities.push(Entity {
                    id: None,
                    paper_id: paper_id.to_string(),
                    entity_type: "security_property".to_string(),
                    entity_name: property,
                    entity_value: None,
                    confidence: 0.85,
                    context: Some(self.get_context(text, capture.start(), capture.end())),
                });
            }
        }
        
        Ok(entities)
    }

    fn extract_author_entities(&self, paper_id: &str, authors: &[String]) -> Result<Vec<Entity>> {
        let mut entities = Vec::new();
        
        for author in authors {
            if author != "Unknown" && !author.is_empty() {
                entities.push(Entity {
                    id: None,
                    paper_id: paper_id.to_string(),
                    entity_type: "author".to_string(),
                    entity_name: author.clone(),
                    entity_value: None,
                    confidence: 1.0,
                    context: None,
                });
            }
        }
        
        Ok(entities)
    }

    fn extract_keyword_entities(&self, paper_id: &str, keywords: &[String]) -> Result<Vec<Entity>> {
        let mut entities = Vec::new();
        
        for keyword in keywords {
            if !self.stop_words.contains(&keyword.to_lowercase()) && keyword.len() > 2 {
                entities.push(Entity {
                    id: None,
                    paper_id: paper_id.to_string(),
                    entity_type: "keyword".to_string(),
                    entity_name: keyword.clone(),
                    entity_value: None,
                    confidence: 0.7,
                    context: None,
                });
            }
        }
        
        Ok(entities)
    }

    fn extract_category_entities(&self, paper_id: &str, categories: &[String]) -> Result<Vec<Entity>> {
        let mut entities = Vec::new();
        
        for category in categories {
            entities.push(Entity {
                id: None,
                paper_id: paper_id.to_string(),
                entity_type: "category".to_string(),
                entity_name: category.clone(),
                entity_value: None,
                confidence: 1.0,
                context: None,
            });
        }
        
        Ok(entities)
    }

    fn get_context(&self, text: &str, start: usize, end: usize) -> String {
        let context_size = 50;
        let context_start = start.saturating_sub(context_size);
        let context_end = std::cmp::min(end + context_size, text.len());
        
        text.chars()
            .skip(context_start)
            .take(context_end - context_start)
            .collect()
    }

    pub fn calculate_text_similarity(&self, text1: &str, text2: &str) -> f64 {
        let words1 = self.extract_significant_words(text1);
        let words2 = self.extract_significant_words(text2);
        
        if words1.is_empty() || words2.is_empty() {
            return 0.0;
        }
        
        let intersection_size = words1.intersection(&words2).count();
        let union_size = words1.union(&words2).count();
        
        if union_size == 0 {
            0.0
        } else {
            intersection_size as f64 / union_size as f64
        }
    }

    fn extract_significant_words(&self, text: &str) -> HashSet<String> {
        let normalized = self.normalize_text(text);
        normalized
            .split_whitespace()
            .filter(|word| word.len() > 3 && !self.stop_words.contains(*word))
            .map(|word| word.to_string())
            .collect()
    }

    pub fn extract_key_phrases(&self, text: &str, max_phrases: usize) -> Vec<String> {
        let normalized = self.normalize_text(text);
        let words: Vec<&str> = normalized
            .split_whitespace()
            .filter(|word| word.len() > 3 && !self.stop_words.contains(*word))
            .collect();
        
        let mut phrases = Vec::new();
        
        // Extract 2-grams and 3-grams
        for window_size in 2..=3 {
            for window in words.windows(window_size) {
                let phrase = window.join(" ");
                if !phrases.contains(&phrase) {
                    phrases.push(phrase);
                }
                
                if phrases.len() >= max_phrases {
                    break;
                }
            }
            
            if phrases.len() >= max_phrases {
                break;
            }
        }
        
        // Add single significant words
        for word in words {
            if !phrases.iter().any(|p| p.contains(word)) {
                phrases.push(word.to_string());
                
                if phrases.len() >= max_phrases {
                    break;
                }
            }
        }
        
        phrases.truncate(max_phrases);
        phrases
    }

    pub fn calculate_entity_similarity(&self, entities1: &[Entity], entities2: &[Entity]) -> f64 {
        if entities1.is_empty() || entities2.is_empty() {
            return 0.0;
        }
        
        let mut similarity_scores = Vec::new();
        
        // Group entities by type for more accurate comparison
        let mut groups1: HashMap<String, Vec<&Entity>> = HashMap::new();
        let mut groups2: HashMap<String, Vec<&Entity>> = HashMap::new();
        
        for entity in entities1 {
            groups1.entry(entity.entity_type.clone()).or_default().push(entity);
        }
        
        for entity in entities2 {
            groups2.entry(entity.entity_type.clone()).or_default().push(entity);
        }
        
        // Calculate similarity for each entity type
        for (entity_type, entities_group1) in &groups1 {
            if let Some(entities_group2) = groups2.get(entity_type) {
                let names1: HashSet<_> = entities_group1.iter()
                    .map(|e| e.entity_name.clone())
                    .collect();
                let names2: HashSet<_> = entities_group2.iter()
                    .map(|e| e.entity_name.clone())
                    .collect();
                
                let intersection = names1.intersection(&names2).count();
                let union = names1.union(&names2).count();
                
                if union > 0 {
                    similarity_scores.push(intersection as f64 / union as f64);
                }
            }
        }
        
        if similarity_scores.is_empty() {
            0.0
        } else {
            similarity_scores.iter().sum::<f64>() / similarity_scores.len() as f64
        }
    }

    pub fn detect_relationships(&self, entities: &[Entity]) -> Vec<(usize, usize, String, f64)> {
        let mut relationships = Vec::new();
        
        for (i, entity1) in entities.iter().enumerate() {
            for (j, entity2) in entities.iter().enumerate() {
                if i >= j {
                    continue;
                }
                
                let relationship = self.infer_relationship(entity1, entity2);
                if let Some((rel_type, confidence)) = relationship {
                    relationships.push((i, j, rel_type, confidence));
                }
            }
        }
        
        relationships
    }

    fn infer_relationship(&self, entity1: &Entity, entity2: &Entity) -> Option<(String, f64)> {
        // Define relationship rules based on entity types
        match (entity1.entity_type.as_str(), entity2.entity_type.as_str()) {
            ("cryptographic_algorithm", "security_property") => {
                Some(("provides".to_string(), 0.8))
            }
            ("mathematical_concept", "cryptographic_algorithm") => {
                Some(("underlies".to_string(), 0.7))
            }
            ("author", "cryptographic_algorithm") => {
                Some(("researches".to_string(), 0.6))
            }
            ("cryptographic_algorithm", "cryptographic_algorithm") => {
                // Check if algorithms are related
                if self.are_algorithms_related(&entity1.entity_name, &entity2.entity_name) {
                    Some(("related_to".to_string(), 0.5))
                } else {
                    None
                }
            }
            ("mathematical_concept", "mathematical_concept") => {
                if self.are_concepts_related(&entity1.entity_name, &entity2.entity_name) {
                    Some(("related_to".to_string(), 0.4))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn are_algorithms_related(&self, alg1: &str, alg2: &str) -> bool {
        let families = vec![
            vec!["aes", "des", "chacha", "salsa"],  // Symmetric encryption
            vec!["rsa", "ecc", "ecdsa", "dsa"],     // Asymmetric
            vec!["sha", "md5", "blake"],            // Hash functions
            vec!["kyber", "dilithium", "falcon"],   // Post-quantum
        ];
        
        for family in families {
            let in_family1 = family.iter().any(|&alg| alg1.to_lowercase().contains(alg));
            let in_family2 = family.iter().any(|&alg| alg2.to_lowercase().contains(alg));
            
            if in_family1 && in_family2 {
                return true;
            }
        }
        
        false
    }

    fn are_concepts_related(&self, concept1: &str, concept2: &str) -> bool {
        let related_concepts = vec![
            vec!["polynomial", "ring", "field"],
            vec!["discrete logarithm", "elliptic curve", "group"],
            vec!["zero knowledge", "proof", "verifier", "prover"],
            vec!["lattice", "lwe", "rlwe", "mlwe"],
        ];
        
        for group in related_concepts {
            let in_group1 = group.iter().any(|&concept| concept1.to_lowercase().contains(concept));
            let in_group2 = group.iter().any(|&concept| concept2.to_lowercase().contains(concept));
            
            if in_group1 && in_group2 {
                return true;
            }
        }
        
        false
    }
}