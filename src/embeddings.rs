use anyhow::Result;
use std::collections::HashMap;
use tracing::{info, debug};

use crate::scraper::Paper;
use crate::database::{Database, Entity};

pub struct EmbeddingGenerator {
    // For now, we'll use simple bag-of-words embeddings
    // In a real implementation, you'd use transformers or word2vec
    vocabulary: HashMap<String, usize>,
    embedding_dim: usize,
}

impl EmbeddingGenerator {
    pub fn new(embedding_dim: usize) -> Self {
        Self {
            vocabulary: HashMap::new(),
            embedding_dim,
        }
    }

    pub async fn generate_paper_embedding(&mut self, paper: &Paper) -> Result<Vec<f32>> {
        // Combine title, abstract, and keywords for embedding
        let text = format!("{} {} {}", 
            paper.title, 
            paper.abstract_text, 
            paper.keywords.join(" ")
        );
        
        let embedding = self.text_to_embedding(&text);
        Ok(embedding)
    }

    pub async fn generate_entity_embedding(&mut self, entity: &Entity) -> Result<Vec<f32>> {
        // Create embedding based on entity name and context
        let text = match &entity.context {
            Some(context) => format!("{} {}", entity.entity_name, context),
            None => entity.entity_name.clone(),
        };
        
        let embedding = self.text_to_embedding(&text);
        Ok(embedding)
    }

    fn text_to_embedding(&mut self, text: &str) -> Vec<f32> {
        // Simple TF-IDF-like embedding
        let words = self.tokenize(text);
        let mut embedding = vec![0.0; self.embedding_dim];
        
        // Build vocabulary if needed
        for word in &words {
            if !self.vocabulary.contains_key(word) {
                let index = self.vocabulary.len() % self.embedding_dim;
                self.vocabulary.insert(word.clone(), index);
            }
        }
        
        // Create embedding vector
        let mut word_counts: HashMap<String, f32> = HashMap::new();
        for word in &words {
            *word_counts.entry(word.clone()).or_insert(0.0) += 1.0;
        }
        
        // Normalize by document length
        let doc_length = words.len() as f32;
        for (word, count) in word_counts {
            if let Some(&index) = self.vocabulary.get(&word) {
                embedding[index] += count / doc_length;
            }
        }
        
        // L2 normalize
        let norm = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for val in &mut embedding {
                *val /= norm;
            }
        }
        
        embedding
    }

    fn tokenize(&self, text: &str) -> Vec<String> {
        text.to_lowercase()
            .split_whitespace()
            .filter(|word| word.len() > 2)
            .map(|word| {
                // Remove punctuation
                word.chars()
                    .filter(|c| c.is_alphabetic())
                    .collect()
            })
            .filter(|word: &String| !word.is_empty())
            .collect()
    }

    pub fn cosine_similarity(&self, vec1: &[f32], vec2: &[f32]) -> f32 {
        if vec1.len() != vec2.len() {
            return 0.0;
        }
        
        let dot_product: f32 = vec1.iter().zip(vec2.iter()).map(|(a, b)| a * b).sum();
        let norm1: f32 = vec1.iter().map(|x| x * x).sum::<f32>().sqrt();
        let norm2: f32 = vec2.iter().map(|x| x * x).sum::<f32>().sqrt();
        
        if norm1 == 0.0 || norm2 == 0.0 {
            0.0
        } else {
            dot_product / (norm1 * norm2)
        }
    }

    pub async fn build_vocabulary_from_papers(&mut self, papers: &[Paper]) -> Result<()> {
        info!("Building vocabulary from {} papers", papers.len());
        
        let mut all_words = Vec::new();
        for paper in papers {
            let text = format!("{} {} {}", 
                paper.title, 
                paper.abstract_text, 
                paper.keywords.join(" ")
            );
            let words = self.tokenize(&text);
            all_words.extend(words);
        }
        
        // Count word frequencies
        let mut word_counts: HashMap<String, usize> = HashMap::new();
        for word in all_words {
            *word_counts.entry(word).or_insert(0) += 1;
        }
        
        // Keep only words that appear at least 2 times
        let filtered_words: Vec<_> = word_counts
            .into_iter()
            .filter(|(_, count)| *count >= 2)
            .collect();
        
        // Build vocabulary with most frequent words
        self.vocabulary.clear();
        for (i, (word, _)) in filtered_words.into_iter().take(self.embedding_dim).enumerate() {
            self.vocabulary.insert(word, i);
        }
        
        info!("Built vocabulary with {} words", self.vocabulary.len());
        Ok(())
    }

    pub async fn save_embeddings(&self, db: &Database, paper_id: &str, embedding: &[f32]) -> Result<()> {
        // Convert embedding to bytes
        let embedding_bytes: Vec<u8> = embedding
            .iter()
            .flat_map(|&x| x.to_le_bytes().to_vec())
            .collect();
        
        // Save to database (this would require extending the database module)
        // For now, we'll just log it
        debug!("Would save embedding of {} dimensions for paper {}", embedding.len(), paper_id);
        
        Ok(())
    }

    pub async fn load_embedding(&self, db: &Database, paper_id: &str) -> Result<Option<Vec<f32>>> {
        // Load from database (this would require extending the database module)
        // For now, return None
        Ok(None)
    }

    pub async fn find_similar_papers(&mut self, 
        target_paper: &Paper, 
        candidate_papers: &[Paper], 
        threshold: f32
    ) -> Result<Vec<(String, f32)>> {
        let target_embedding = self.generate_paper_embedding(target_paper).await?;
        let mut similarities = Vec::new();
        
        for candidate in candidate_papers {
            if candidate.id == target_paper.id {
                continue; // Skip self
            }
            
            let candidate_embedding = self.generate_paper_embedding(candidate).await?;
            let similarity = self.cosine_similarity(&target_embedding, &candidate_embedding);
            
            if similarity >= threshold {
                similarities.push((candidate.id.clone(), similarity));
            }
        }
        
        // Sort by similarity descending
        similarities.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        
        Ok(similarities)
    }

    pub async fn cluster_papers(&mut self, papers: &[Paper], num_clusters: usize) -> Result<Vec<Vec<String>>> {
        // Simple k-means-like clustering
        info!("Clustering {} papers into {} clusters", papers.len(), num_clusters);
        
        if papers.is_empty() || num_clusters == 0 {
            return Ok(vec![]);
        }
        
        // Generate embeddings for all papers
        let mut embeddings = Vec::new();
        for paper in papers {
            let embedding = self.generate_paper_embedding(paper).await?;
            embeddings.push(embedding);
        }
        
        // Initialize cluster centers randomly
        let mut centers = Vec::new();
        for i in 0..num_clusters {
            if i < embeddings.len() {
                centers.push(embeddings[i].clone());
            } else {
                centers.push(vec![0.0; self.embedding_dim]);
            }
        }
        
        // K-means iterations
        for _iteration in 0..10 {
            let mut clusters: Vec<Vec<usize>> = vec![Vec::new(); num_clusters];
            
            // Assign papers to clusters
            for (paper_idx, embedding) in embeddings.iter().enumerate() {
                let mut best_cluster = 0;
                let mut best_similarity = -1.0;
                
                for (cluster_idx, center) in centers.iter().enumerate() {
                    let similarity = self.cosine_similarity(embedding, center);
                    if similarity > best_similarity {
                        best_similarity = similarity;
                        best_cluster = cluster_idx;
                    }
                }
                
                clusters[best_cluster].push(paper_idx);
            }
            
            // Update cluster centers
            for (cluster_idx, cluster) in clusters.iter().enumerate() {
                if !cluster.is_empty() {
                    let mut new_center = vec![0.0; self.embedding_dim];
                    
                    for &paper_idx in cluster {
                        for (dim, value) in embeddings[paper_idx].iter().enumerate() {
                            new_center[dim] += value;
                        }
                    }
                    
                    // Average
                    for value in &mut new_center {
                        *value /= cluster.len() as f32;
                    }
                    
                    centers[cluster_idx] = new_center;
                }
            }
        }
        
        // Convert cluster indices to paper IDs
        let mut result_clusters = Vec::new();
        for i in 0..num_clusters {
            let mut cluster_papers = Vec::new();
            
            for (paper_idx, embedding) in embeddings.iter().enumerate() {
                let mut best_cluster = 0;
                let mut best_similarity = -1.0;
                
                for (cluster_idx, center) in centers.iter().enumerate() {
                    let similarity = self.cosine_similarity(embedding, center);
                    if similarity > best_similarity {
                        best_similarity = similarity;
                        best_cluster = cluster_idx;
                    }
                }
                
                if best_cluster == i {
                    cluster_papers.push(papers[paper_idx].id.clone());
                }
            }
            
            result_clusters.push(cluster_papers);
        }
        
        info!("Clustering completed");
        Ok(result_clusters)
    }
}