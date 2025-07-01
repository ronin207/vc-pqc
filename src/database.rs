use anyhow::Result;
use rusqlite::{Connection, params};
use serde_json;
use std::path::Path;
use tracing::{info, error, debug};

use crate::scraper::Paper;

pub struct Database {
    conn: Connection,
}

impl Database {
    pub async fn new<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        Ok(Self { conn })
    }

    pub async fn initialize(&self) -> Result<()> {
        self.create_tables().await?;
        info!("Database initialized successfully");
        Ok(())
    }

    async fn create_tables(&self) -> Result<()> {
        // Papers table
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS papers (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                authors TEXT NOT NULL,
                abstract_text TEXT NOT NULL,
                categories TEXT NOT NULL,
                publication_date TEXT NOT NULL,
                url TEXT NOT NULL,
                pdf_url TEXT,
                citations TEXT NOT NULL,
                paper_references TEXT NOT NULL,
                keywords TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        // Entities table (for knowledge graph nodes)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS entities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                paper_id TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_name TEXT NOT NULL,
                entity_value TEXT,
                confidence REAL DEFAULT 0.0,
                context TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (paper_id) REFERENCES papers (id)
            )",
            [],
        )?;

        // Relationships table (for knowledge graph edges)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS relationships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_entity_id INTEGER NOT NULL,
                target_entity_id INTEGER NOT NULL,
                relationship_type TEXT NOT NULL,
                weight REAL DEFAULT 1.0,
                evidence TEXT,
                confidence REAL DEFAULT 0.0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (source_entity_id) REFERENCES entities (id),
                FOREIGN KEY (target_entity_id) REFERENCES entities (id)
            )",
            [],
        )?;

        // Paper connections (for connecting papers through shared concepts)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS paper_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                paper_id_1 TEXT NOT NULL,
                paper_id_2 TEXT NOT NULL,
                connection_type TEXT NOT NULL,
                similarity_score REAL DEFAULT 0.0,
                shared_entities INTEGER DEFAULT 0,
                evidence TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (paper_id_1) REFERENCES papers (id),
                FOREIGN KEY (paper_id_2) REFERENCES papers (id)
            )",
            [],
        )?;

        // Embeddings table (for semantic search)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS embeddings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                paper_id TEXT NOT NULL,
                embedding_type TEXT NOT NULL,
                embedding_data BLOB NOT NULL,
                model_name TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (paper_id) REFERENCES papers (id)
            )",
            [],
        )?;

        // Create indices for better performance
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_papers_id ON papers (id)",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_entities_paper_id ON entities (paper_id)",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_entities_type_name ON entities (entity_type, entity_name)",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_relationships_source ON relationships (source_entity_id)",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_relationships_target ON relationships (target_entity_id)",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_paper_connections_papers ON paper_connections (paper_id_1, paper_id_2)",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_embeddings_paper_id ON embeddings (paper_id)",
            [],
        )?;

        Ok(())
    }

    pub async fn save_paper(&self, paper: &Paper) -> Result<()> {
        let authors_json = serde_json::to_string(&paper.authors)?;
        let categories_json = serde_json::to_string(&paper.categories)?;
        let citations_json = serde_json::to_string(&paper.citations)?;
        let references_json = serde_json::to_string(&paper.references)?;
        let keywords_json = serde_json::to_string(&paper.keywords)?;

        self.conn.execute(
            "INSERT OR REPLACE INTO papers 
            (id, title, authors, abstract_text, categories, publication_date, url, pdf_url, citations, paper_references, keywords, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, CURRENT_TIMESTAMP)",
            params![
                paper.id,
                paper.title,
                authors_json,
                paper.abstract_text,
                categories_json,
                paper.publication_date,
                paper.url,
                paper.pdf_url,
                citations_json,
                references_json,
                keywords_json
            ],
        )?;

        debug!("Saved paper: {}", paper.id);
        Ok(())
    }

    pub async fn paper_exists(&self, paper_id: &str) -> Result<bool> {
        let mut stmt = self.conn.prepare("SELECT COUNT(*) FROM papers WHERE id = ?1")?;
        let count: i64 = stmt.query_row(params![paper_id], |row| row.get(0))?;
        Ok(count > 0)
    }

    pub async fn get_paper(&self, paper_id: &str) -> Result<Option<Paper>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, title, authors, abstract_text, categories, publication_date, url, pdf_url, citations, paper_references, keywords
             FROM papers WHERE id = ?1"
        )?;

        let paper = stmt.query_row(params![paper_id], |row| {
            let authors_json: String = row.get(2)?;
            let categories_json: String = row.get(4)?;
            let citations_json: String = row.get(8)?;
            let references_json: String = row.get(9)?;
            let keywords_json: String = row.get(10)?;

            Ok(Paper {
                id: row.get(0)?,
                title: row.get(1)?,
                authors: serde_json::from_str(&authors_json).unwrap_or_default(),
                abstract_text: row.get(3)?,
                categories: serde_json::from_str(&categories_json).unwrap_or_default(),
                publication_date: row.get(5)?,
                url: row.get(6)?,
                pdf_url: row.get(7)?,
                citations: serde_json::from_str(&citations_json).unwrap_or_default(),
                references: serde_json::from_str(&references_json).unwrap_or_default(),
                keywords: serde_json::from_str(&keywords_json).unwrap_or_default(),
            })
        });

        match paper {
            Ok(p) => Ok(Some(p)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn get_all_papers(&self) -> Result<Vec<Paper>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, title, authors, abstract_text, categories, publication_date, url, pdf_url, citations, paper_references, keywords
             FROM papers ORDER BY publication_date DESC"
        )?;

        let paper_iter = stmt.query_map([], |row| {
            let authors_json: String = row.get(2)?;
            let categories_json: String = row.get(4)?;
            let citations_json: String = row.get(8)?;
            let references_json: String = row.get(9)?;
            let keywords_json: String = row.get(10)?;

            Ok(Paper {
                id: row.get(0)?,
                title: row.get(1)?,
                authors: serde_json::from_str(&authors_json).unwrap_or_default(),
                abstract_text: row.get(3)?,
                categories: serde_json::from_str(&categories_json).unwrap_or_default(),
                publication_date: row.get(5)?,
                url: row.get(6)?,
                pdf_url: row.get(7)?,
                citations: serde_json::from_str(&citations_json).unwrap_or_default(),
                references: serde_json::from_str(&references_json).unwrap_or_default(),
                keywords: serde_json::from_str(&keywords_json).unwrap_or_default(),
            })
        })?;

        let mut papers = Vec::new();
        for paper in paper_iter {
            papers.push(paper?);
        }

        Ok(papers)
    }

    pub async fn save_entity(&self, entity: &Entity) -> Result<i64> {
        let mut stmt = self.conn.prepare(
            "INSERT INTO entities (paper_id, entity_type, entity_name, entity_value, confidence, context)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        )?;

        stmt.execute(params![
            entity.paper_id,
            entity.entity_type,
            entity.entity_name,
            entity.entity_value,
            entity.confidence,
            entity.context
        ])?;

        Ok(self.conn.last_insert_rowid())
    }

    pub async fn save_relationship(&self, relationship: &Relationship) -> Result<i64> {
        let mut stmt = self.conn.prepare(
            "INSERT INTO relationships (source_entity_id, target_entity_id, relationship_type, weight, evidence, confidence)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        )?;

        stmt.execute(params![
            relationship.source_entity_id,
            relationship.target_entity_id,
            relationship.relationship_type,
            relationship.weight,
            relationship.evidence,
            relationship.confidence
        ])?;

        Ok(self.conn.last_insert_rowid())
    }

    pub async fn save_paper_connection(&self, connection: &PaperConnection) -> Result<i64> {
        let mut stmt = self.conn.prepare(
            "INSERT OR REPLACE INTO paper_connections 
             (paper_id_1, paper_id_2, connection_type, similarity_score, shared_entities, evidence)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        )?;

        stmt.execute(params![
            connection.paper_id_1,
            connection.paper_id_2,
            connection.connection_type,
            connection.similarity_score,
            connection.shared_entities,
            connection.evidence
        ])?;

        Ok(self.conn.last_insert_rowid())
    }

    pub async fn get_entities_for_paper(&self, paper_id: &str) -> Result<Vec<Entity>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, paper_id, entity_type, entity_name, entity_value, confidence, context
             FROM entities WHERE paper_id = ?1"
        )?;

        let entity_iter = stmt.query_map(params![paper_id], |row| {
            Ok(Entity {
                id: Some(row.get(0)?),
                paper_id: row.get(1)?,
                entity_type: row.get(2)?,
                entity_name: row.get(3)?,
                entity_value: row.get(4)?,
                confidence: row.get(5)?,
                context: row.get(6)?,
            })
        })?;

        let mut entities = Vec::new();
        for entity in entity_iter {
            entities.push(entity?);
        }

        Ok(entities)
    }

    pub async fn get_paper_connections(&self, paper_id: &str) -> Result<Vec<PaperConnection>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, paper_id_1, paper_id_2, connection_type, similarity_score, shared_entities, evidence
             FROM paper_connections 
             WHERE paper_id_1 = ?1 OR paper_id_2 = ?1
             ORDER BY similarity_score DESC"
        )?;

        let connection_iter = stmt.query_map(params![paper_id], |row| {
            Ok(PaperConnection {
                id: Some(row.get(0)?),
                paper_id_1: row.get(1)?,
                paper_id_2: row.get(2)?,
                connection_type: row.get(3)?,
                similarity_score: row.get(4)?,
                shared_entities: row.get(5)?,
                evidence: row.get(6)?,
            })
        })?;

        let mut connections = Vec::new();
        for connection in connection_iter {
            connections.push(connection?);
        }

        Ok(connections)
    }

    pub async fn search_papers(&self, query: &str, limit: usize) -> Result<Vec<Paper>> {
        let search_term = format!("%{}%", query.to_lowercase());
        
        let mut stmt = self.conn.prepare(
            "SELECT id, title, authors, abstract_text, categories, publication_date, url, pdf_url, citations, paper_references, keywords
             FROM papers 
             WHERE LOWER(title) LIKE ?1 
                OR LOWER(abstract_text) LIKE ?1 
                OR LOWER(keywords) LIKE ?1
             ORDER BY 
                CASE 
                    WHEN LOWER(title) LIKE ?1 THEN 3
                    WHEN LOWER(abstract_text) LIKE ?1 THEN 2
                    ELSE 1
                END DESC
             LIMIT ?2"
        )?;

        let paper_iter = stmt.query_map(params![search_term, limit], |row| {
            let authors_json: String = row.get(2)?;
            let categories_json: String = row.get(4)?;
            let citations_json: String = row.get(8)?;
            let references_json: String = row.get(9)?;
            let keywords_json: String = row.get(10)?;

            Ok(Paper {
                id: row.get(0)?,
                title: row.get(1)?,
                authors: serde_json::from_str(&authors_json).unwrap_or_default(),
                abstract_text: row.get(3)?,
                categories: serde_json::from_str(&categories_json).unwrap_or_default(),
                publication_date: row.get(5)?,
                url: row.get(6)?,
                pdf_url: row.get(7)?,
                citations: serde_json::from_str(&citations_json).unwrap_or_default(),
                references: serde_json::from_str(&references_json).unwrap_or_default(),
                keywords: serde_json::from_str(&keywords_json).unwrap_or_default(),
            })
        })?;

        let mut papers = Vec::new();
        for paper in paper_iter {
            papers.push(paper?);
        }

        Ok(papers)
    }
}

#[derive(Debug, Clone)]
pub struct Entity {
    pub id: Option<i64>,
    pub paper_id: String,
    pub entity_type: String,
    pub entity_name: String,
    pub entity_value: Option<String>,
    pub confidence: f64,
    pub context: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Relationship {
    pub id: Option<i64>,
    pub source_entity_id: i64,
    pub target_entity_id: i64,
    pub relationship_type: String,
    pub weight: f64,
    pub evidence: Option<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone)]
pub struct PaperConnection {
    pub id: Option<i64>,
    pub paper_id_1: String,
    pub paper_id_2: String,
    pub connection_type: String,
    pub similarity_score: f64,
    pub shared_entities: i32,
    pub evidence: Option<String>,
}