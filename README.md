# Research Agent for Cryptography Papers

A comprehensive research agent that scrapes cryptography papers from [eprint.iacr.org](https://eprint.iacr.org) and builds interconnected knowledge graphs to enable advanced analysis and discovery of relationships between papers.

## Features

### 🔍 **Intelligent Paper Scraping**
- Scrapes papers from the IACR eprint archive with configurable filters
- Extracts metadata including titles, authors, abstracts, and PDFs
- Respects rate limits and implements ethical scraping practices
- Supports category filtering and year-based crawling

### 🕸️ **Knowledge Graph Construction**
- Creates individual knowledge graphs for each paper
- Extracts entities: algorithms, mathematical concepts, security properties, authors
- Builds relationships between entities within and across papers
- Connects papers through shared concepts and semantic similarity

### 🧠 **Advanced NLP Processing**
- Entity extraction using regex patterns for cryptographic terms
- Relationship detection between different entity types
- Text similarity analysis using bag-of-words embeddings
- Keyword and key phrase extraction from paper content

### 📊 **Paper Analysis & Insights**
- Innovation scoring based on novelty indicators
- Complexity assessment using mathematical concept density
- Influence potential prediction using multiple factors
- Research domain classification (Post-Quantum, ZK, Blockchain, etc.)

### 🔗 **Interconnected Graph Network**
- Papers connected through shared entities and concepts
- Semantic similarity scoring between papers
- Citation pattern analysis (when data available)
- Author collaboration network mapping

## Architecture

```
research-agent/
├── src/
│   ├── main.rs              # CLI interface and orchestration
│   ├── scraper.rs           # Web scraping from eprint.iacr.org
│   ├── database.rs          # SQLite database operations
│   ├── nlp.rs               # Text processing and entity extraction
│   ├── knowledge_graph.rs   # Graph construction and analysis
│   ├── embeddings.rs        # Semantic similarity and clustering
│   └── paper_analyzer.rs    # High-level paper analysis
├── Cargo.toml               # Dependencies and configuration
└── README.md               # This file
```

## Installation

### Prerequisites
- Rust 1.70+ 
- SQLite 3
- Internet connection for scraping

### Setup
```bash
git clone <repository-url>
cd research-agent
cargo build --release
```

## Usage

### Basic Commands

#### 1. Scrape Papers
```bash
# Scrape 50 papers from 2020 onwards
./target/release/research-agent scrape --count 50 --year 2020

# Scrape with category filter
./target/release/research-agent scrape --count 100 --year 2022 --category "zero-knowledge"
```

#### 2. Build Knowledge Graphs
```bash
# Build graphs incrementally (only new papers)
./target/release/research-agent build-graph

# Rebuild all graphs from scratch
./target/release/research-agent build-graph --rebuild
```

#### 3. Query the Knowledge Graph
```bash
# Search for papers related to specific topics
./target/release/research-agent query "zero knowledge proofs" --limit 10
./target/release/research-agent query "post-quantum cryptography" --limit 5
./target/release/research-agent query "lattice-based" --limit 15
```

#### 4. Analyze Paper Connections
```bash
# Analyze connections for a specific paper
./target/release/research-agent analyze "2024/123" --depth 2
```

### Advanced Usage

#### Batch Processing
```bash
# Scrape papers in batches by year
for year in {2020..2024}; do
    ./target/release/research-agent scrape --count 50 --year $year
    ./target/release/research-agent build-graph
done
```

#### Domain-Specific Analysis
```bash
# Focus on post-quantum cryptography
./target/release/research-agent scrape --category "post-quantum" --count 200 --year 2020
./target/release/research-agent build-graph --rebuild
./target/release/research-agent query "CRYSTALS-Kyber" --limit 20
```

## Database Schema

The system uses SQLite with the following key tables:

### Papers Table
- `id`: Unique paper identifier (e.g., "2024/123")
- `title`: Paper title
- `authors`: JSON array of author names
- `abstract_text`: Full abstract content
- `categories`: JSON array of categories
- `publication_date`: Publication timestamp
- `url`: Link to paper page
- `pdf_url`: Direct PDF link
- `keywords`: Extracted keywords

### Entities Table
- `paper_id`: Foreign key to papers
- `entity_type`: Type (algorithm, concept, property, author, etc.)
- `entity_name`: Name of the entity
- `confidence`: Extraction confidence score
- `context`: Surrounding text context

### Relationships Table
- `source_entity_id`: Source entity
- `target_entity_id`: Target entity
- `relationship_type`: Type of relationship
- `weight`: Relationship strength
- `confidence`: Relationship confidence

### Paper Connections Table
- `paper_id_1`, `paper_id_2`: Connected papers
- `connection_type`: Type of connection
- `similarity_score`: Similarity strength
- `shared_entities`: Number of shared entities

## Entity Types

The system recognizes several entity types:

### Cryptographic Algorithms
- Symmetric: AES, ChaCha20, DES
- Asymmetric: RSA, ECC, DSA
- Post-Quantum: Kyber, Dilithium, Falcon
- Hash Functions: SHA, Blake2, MD5

### Mathematical Concepts
- Algebraic structures: groups, rings, fields
- Geometric concepts: elliptic curves, lattices
- Proof systems: zero-knowledge, SNARKs
- Computational problems: discrete log, factorization

### Security Properties
- Confidentiality, authentication, integrity
- Forward secrecy, anonymity, unlinkability
- CPA, CCA, IND security models
- Post-quantum resistance

## Knowledge Graph Features

### Node Types
- **Algorithm Nodes**: Cryptographic algorithms and schemes
- **Concept Nodes**: Mathematical and theoretical concepts
- **Author Nodes**: Researchers and their contributions
- **Property Nodes**: Security properties and guarantees

### Edge Types
- **Provides**: Algorithm → Security Property
- **Underlies**: Mathematical Concept → Algorithm
- **Researches**: Author → Algorithm/Concept
- **Related_to**: Similar entities within same type
- **Cites**: Paper → Paper (when citation data available)

### Graph Analysis
- Connected component analysis
- Centrality measurements
- Community detection
- Path finding between concepts

## Analysis Metrics

### Innovation Score
- Novelty indicators in title/abstract
- Unique algorithm combinations
- Cross-domain research elements
- First-of-kind contributions

### Complexity Score
- Mathematical concept density
- Abstract length and technicality
- Number of entity types involved
- Interdisciplinary connections

### Influence Potential
- High-confidence entity extractions
- Practical security implications
- Author collaboration patterns
- Trending research areas

## Example Queries and Outputs

### Query: "lattice cryptography"
```
Paper: CRYSTALS-Kyber: A CCA-Secure Module-Lattice-Based KEM - Score: 0.892
Authors: Joppe Bos, Léo Ducas, Eike Kiltz
Abstract: We introduce CRYSTALS-Kyber, a lattice-based key encapsulation mechanism...

Paper: Learning With Errors and Applications - Score: 0.854
Authors: Oded Regev
Abstract: We introduce a new computational problem called Learning With Errors...
```

### Connection Analysis: "2024/123"
```
Connection Analysis for Paper: 2024/123
Direct connections: 15
Citation network size: 15
Key topics: zero-knowledge, snark, proof-systems, recursion, plonk
Related papers: 12
```

## Configuration

### Environment Variables
- `RESEARCH_AGENT_DB_PATH`: Database file path (default: `research_agent.db`)
- `RESEARCH_AGENT_RATE_LIMIT`: Scraping rate limit in ms (default: `1000`)
- `RESEARCH_AGENT_LOG_LEVEL`: Logging level (default: `info`)

### Custom Entity Patterns
You can extend entity recognition by modifying the regex patterns in `src/nlp.rs`:

```rust
// Add custom algorithm patterns
crypto_algorithms: Regex::new(r"\b(?i)(YOUR_ALGORITHM|ANOTHER_ALG)\b")?
```

## Performance

### Scraping Performance
- ~1 paper per second (with 1s rate limit)
- ~100 papers: ~2 minutes
- ~1000 papers: ~20 minutes

### Graph Building Performance
- Entity extraction: ~10ms per paper
- Relationship detection: ~50ms per paper
- Paper-to-paper connections: O(n²) for n papers

### Query Performance
- Simple text search: <100ms
- Complex graph traversal: <1s
- Full analysis: 1-5s per paper

## Extensibility

### Adding New Entity Types
1. Extend the Entity struct in `database.rs`
2. Add extraction logic in `nlp.rs`
3. Update relationship rules in `knowledge_graph.rs`

### Custom Analysis Metrics
1. Implement new scoring functions in `paper_analyzer.rs`
2. Add database fields for new metrics
3. Update CLI output formatting

### Integration with External APIs
- Add citation data from Semantic Scholar
- Integrate with arXiv for broader coverage
- Connect with institutional repositories

## Research Applications

### Literature Review
- Discover related work automatically
- Track research evolution over time
- Identify influential papers and authors

### Trend Analysis
- Emerging research directions
- Technology adoption patterns
- Cross-domain fertilization

### Collaboration Discovery
- Find potential collaborators
- Identify expertise areas
- Map research communities

### Gap Analysis
- Underexplored research areas
- Missing connections between fields
- Opportunity identification

## Limitations

### Current Limitations
- Limited to IACR eprint papers
- Simple bag-of-words embeddings
- No real-time citation tracking
- Basic relationship inference

### Future Improvements
- Transformer-based embeddings
- PDF content extraction
- Real-time citation networks
- Interactive web interface
- Multi-source paper aggregation

## Contributing

### Development Setup
```bash
git clone <repository-url>
cd research-agent
cargo test
cargo fmt
cargo clippy
```

### Adding Features
1. Create feature branch
2. Implement changes with tests
3. Update documentation
4. Submit pull request

## License

This project is for educational and research purposes. Please respect the terms of service of eprint.iacr.org and use responsibly.

## Citation

If you use this research agent in academic work, please cite:

```bibtex
@software{research_agent_2024,
  title={Research Agent for Cryptography Papers},
  author={Your Name},
  year={2024},
  url={https://github.com/your-repo/research-agent}
}
```

## Contact

For questions, issues, or collaboration opportunities, please open an issue on GitHub or contact [your-email].

---

**Note**: This tool is designed for research and educational purposes. Please use responsibly and respect the terms of service of target websites.
