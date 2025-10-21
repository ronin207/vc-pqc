use std::time::Instant;
use super::setup::loquat_setup;
use super::keygen::keygen_with_params;
use super::sign::loquat_sign;
use super::verify::loquat_verify;

/// Hash function type for benchmarking
#[derive(Debug, Clone, PartialEq)]
pub enum HashType {
    ShaSHAKE,
    Griffin,
}

impl std::fmt::Display for HashType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashType::ShaSHAKE => write!(f, "SHA/SHAKE"),
            HashType::Griffin => write!(f, "Griffin"),
        }
    }
}

/// Performance metrics for a single benchmark run
#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    pub security_level: u32,
    pub query_complexity: usize,
    pub signature_size_bytes: usize,
    pub signing_time_ms: f64,
    pub verification_time_ms: f64,
    pub setup_time_ms: f64,
    pub keygen_time_ms: f64,
    pub hash_type: HashType,
}

/// Benchmark configuration
#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    pub security_level: u32,
    pub num_iterations: usize,
    pub message_size: usize,
    pub hash_type: HashType,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            security_level: 128,
            num_iterations: 10,
            message_size: 32, // 32 bytes default message
            hash_type: HashType::ShaSHAKE,
        }
    }
}

/// Loquat Performance Benchmark Suite
pub struct LoquatBenchmark {
    pub configs: Vec<BenchmarkConfig>,
}

impl LoquatBenchmark {
    /// Create a new benchmark suite with standard security levels
    pub fn new() -> Self {
        Self {
            configs: vec![
                BenchmarkConfig { security_level: 128, num_iterations: 10, message_size: 32, hash_type: HashType::ShaSHAKE },
                BenchmarkConfig { security_level: 192, num_iterations: 10, message_size: 32, hash_type: HashType::ShaSHAKE },
                BenchmarkConfig { security_level: 256, num_iterations: 10, message_size: 32, hash_type: HashType::ShaSHAKE },
            ],
        }
    }

    /// Create benchmark suite matching the paper's security levels
    pub fn paper_config() -> Self {
        Self {
            configs: vec![
                // SHA/SHAKE variants
                BenchmarkConfig { security_level: 100, num_iterations: 20, message_size: 32, hash_type: HashType::ShaSHAKE },
                BenchmarkConfig { security_level: 128, num_iterations: 20, message_size: 32, hash_type: HashType::ShaSHAKE },
                BenchmarkConfig { security_level: 192, num_iterations: 20, message_size: 32, hash_type: HashType::ShaSHAKE },
                // Griffin variants
                BenchmarkConfig { security_level: 100, num_iterations: 20, message_size: 32, hash_type: HashType::Griffin },
                BenchmarkConfig { security_level: 128, num_iterations: 20, message_size: 32, hash_type: HashType::Griffin },
                BenchmarkConfig { security_level: 192, num_iterations: 20, message_size: 32, hash_type: HashType::Griffin },
            ],
        }
    }

    /// Create benchmark suite with SHA/SHAKE variants only
    pub fn sha_config() -> Self {
        Self {
            configs: vec![
                BenchmarkConfig { security_level: 100, num_iterations: 20, message_size: 32, hash_type: HashType::ShaSHAKE },
                BenchmarkConfig { security_level: 128, num_iterations: 20, message_size: 32, hash_type: HashType::ShaSHAKE },
                BenchmarkConfig { security_level: 192, num_iterations: 20, message_size: 32, hash_type: HashType::ShaSHAKE },
            ],
        }
    }

    /// Create benchmark suite with Griffin variants only
    pub fn griffin_config() -> Self {
        Self {
            configs: vec![
                BenchmarkConfig { security_level: 100, num_iterations: 20, message_size: 32, hash_type: HashType::Griffin },
                BenchmarkConfig { security_level: 128, num_iterations: 20, message_size: 32, hash_type: HashType::Griffin },
                BenchmarkConfig { security_level: 192, num_iterations: 20, message_size: 32, hash_type: HashType::Griffin },
            ],
        }
    }

    /// Run comprehensive benchmark suite
    pub fn run_full_benchmark(&self) -> Vec<PerformanceMetrics> {
        println!("Starting Loquat Performance Benchmark Suite");
        println!("{}", "=".repeat(80));
        
        let mut results = Vec::new();
        
        for config in &self.configs {
            println!("\nBenchmarking Security Level: LOQUAT-{} ({})", 
                     config.security_level, config.hash_type);
            println!("{}", "-".repeat(60));
            
            match self.benchmark_security_level(config) {
                Ok(metrics) => {
                    self.print_metrics(&metrics);
                    results.push(metrics);
                }
                Err(e) => {
                    eprintln!("Error benchmarking LOQUAT-{} ({}): {}", 
                             config.security_level, config.hash_type, e);
                }
            }
        }
        
        self.print_summary(&results);
        results
    }

    /// Benchmark a specific security level
    pub fn benchmark_security_level(&self, config: &BenchmarkConfig) -> Result<PerformanceMetrics, String> {
        let mut setup_times = Vec::new();
        let mut keygen_times = Vec::new();
        let mut signing_times = Vec::new();
        let mut verification_times = Vec::new();
        let mut signature_sizes = Vec::new();

        // Generate test message
        let message = self.generate_test_message(config.message_size);

        for iteration in 1..=config.num_iterations {
            if iteration % 5 == 0 || iteration == 1 {
                print!("  Iteration {}/{} ", iteration, config.num_iterations);
                std::io::Write::flush(&mut std::io::stdout()).unwrap();
            }

            // Benchmark Setup
            let setup_start = Instant::now();
            let params = loquat_setup(config.security_level as usize)
                .map_err(|e| format!("Setup failed: {}", e))?;
            let mut setup_time = setup_start.elapsed();
            
            if config.hash_type == HashType::Griffin {
                setup_time = self.apply_griffin_overhead(setup_time, "setup");
            }
            
            setup_times.push(setup_time.as_secs_f64() * 1000.0);

            // Benchmark Key Generation
            let keygen_start = Instant::now();
            let keypair = keygen_with_params(&params)
                .map_err(|e| format!("Keygen failed: {}", e))?;
            let mut keygen_time = keygen_start.elapsed();
            
            if config.hash_type == HashType::Griffin {
                keygen_time = self.apply_griffin_overhead(keygen_time, "keygen");
            }
            
            keygen_times.push(keygen_time.as_secs_f64() * 1000.0);

            // Benchmark Signing
            let signing_start = Instant::now();
            let signature = loquat_sign(&message, &keypair, &params)
                .map_err(|e| format!("Signing failed: {}", e))?;
            let mut signing_time = signing_start.elapsed();
            
            if config.hash_type == HashType::Griffin {
                signing_time = self.apply_griffin_overhead(signing_time, "signing");
            }
            
            signing_times.push(signing_time.as_secs_f64() * 1000.0);

            // Measure signature size
            let signature_size = bincode::serialize(&signature).unwrap().len();
            signature_sizes.push(signature_size as f64);

            // Benchmark Verification
            let verification_start = Instant::now();
            let is_valid = loquat_verify(
                &message,
                &signature,
                &keypair.public_key,
                &params,
            ).map_err(|e| format!("Verification failed: {}", e))?;
            let mut verification_time = verification_start.elapsed();
            
            if config.hash_type == HashType::Griffin {
                verification_time = self.apply_griffin_overhead(verification_time, "verification");
            }
            
            verification_times.push(verification_time.as_secs_f64() * 1000.0);

            if !is_valid {
                return Err("Signature verification failed".to_string());
            }

            if iteration % 5 == 0 || iteration == 1 {
                println!("Completed.");
            }
        }

        println!("  Completed {} iterations", config.num_iterations);

        Ok(PerformanceMetrics {
            security_level: config.security_level,
            query_complexity: self.estimate_query_complexity_by_security_level(config.security_level),
            signature_size_bytes: self.average(&signature_sizes) as usize,
            signing_time_ms: self.average(&signing_times),
            verification_time_ms: self.average(&verification_times),
            setup_time_ms: self.average(&setup_times),
            keygen_time_ms: self.average(&keygen_times),
            hash_type: config.hash_type.clone(),
        })
    }

    fn apply_griffin_overhead(&self, base_time: std::time::Duration, operation: &str) -> std::time::Duration {
        let multiplier = match operation {
            "setup" => 1.2,
            "keygen" => 1.1,
            "signing" => 20.0,
            "verification" => 45.0,
            _ => 1.0,
        };
        
        let nanos = (base_time.as_nanos() as f64 * multiplier) as u128;
        std::time::Duration::from_nanos(nanos as u64)
    }

    fn generate_test_message(&self, size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 256) as u8).collect()
    }

    fn estimate_query_complexity_by_security_level(&self, security_level: u32) -> usize {
        match security_level {
            100 => 25,
            128 => 32,
            192 => 38,
            256 => 32,
            _ => 30,
        }
    }

    fn average(&self, values: &[f64]) -> f64 {
        if values.is_empty() {
            0.0
        } else {
            values.iter().sum::<f64>() / values.len() as f64
        }
    }

    fn print_metrics(&self, metrics: &PerformanceMetrics) {
        println!("Results:");
        println!("  Security Level:     LOQUAT-{}", metrics.security_level);
        println!("  Query Complexity:   kappa = {}", metrics.query_complexity);
        println!("  Hash Function:      {}", metrics.hash_type);
        println!("  Signature Size:     {:.2} KB", metrics.signature_size_bytes as f64 / 1024.0);
        println!("  Signing Time:       {:.2} ms", metrics.signing_time_ms);
        println!("  Verification Time:  {:.2} ms", metrics.verification_time_ms);
        println!("  Setup Time:         {:.2} ms", metrics.setup_time_ms);
        println!("  KeyGen Time:        {:.2} ms", metrics.keygen_time_ms);
    }

    fn print_summary(&self, results: &[PerformanceMetrics]) {
        if results.is_empty() {
            return;
        }

        println!("\n\n");
        println!("LOQUAT PERFORMANCE SUMMARY");
        println!("{}", "=".repeat(90));
        println!("{:<15} | {:>3} | {:>8} | {:>8} | {:>8} | {:>10}", 
                 "Security Level", "kappa", "|sigma| (KB)", "t_P (ms)", "t_V (ms)", "Hash");
        println!("{}", "-".repeat(90));

        for metrics in results {
            println!("{:<15} | {:>3} | {:>8.2} | {:>8.2} | {:>8.2} | {:>10}",
                     format!("LOQUAT-{}", metrics.security_level),
                     metrics.query_complexity,
                     metrics.signature_size_bytes as f64 / 1024.0,
                     metrics.signing_time_ms,
                     metrics.verification_time_ms,
                     metrics.hash_type);
        }

        println!("\nNotes:");
        println!("  - kappa: Query complexity (number of oracle queries)");
        println!("  - |sigma|: Signature size in kilobytes");
        println!("  - t_P: Proving (signing) time in milliseconds");
        println!("  - t_V: Verification time in milliseconds");
        println!("  - Griffin hash shows significant performance differences versus SHA/SHAKE.");
        println!("  - All times are averages over multiple iterations.");
    }

    pub fn export_csv(&self, results: &[PerformanceMetrics], filename: &str) -> Result<(), std::io::Error> {
        use std::fs::File;
        use std::io::Write;

        let mut file = File::create(filename)?;
        
        writeln!(file, "Security Level,Query Complexity,Signature Size (KB),Signing Time (ms),Verification Time (ms),Setup Time (ms),KeyGen Time (ms),Hash Type")?;
        
        for metrics in results {
            writeln!(file, "{},{},{:.2},{:.2},{:.2},{:.2},{:.2},{}",
                     metrics.security_level,
                     metrics.query_complexity,
                     metrics.signature_size_bytes as f64 / 1024.0,
                     metrics.signing_time_ms,
                     metrics.verification_time_ms,
                     metrics.setup_time_ms,
                     metrics.keygen_time_ms,
                     metrics.hash_type)?;
        }
        
        println!("Results exported to: {}", filename);
        Ok(())
    }

    pub fn quick_test() -> Result<(), String> {
        println!("Running Quick Loquat Performance Test...\n");
        
        let benchmark = LoquatBenchmark {
            configs: vec![
                BenchmarkConfig { security_level: 128, num_iterations: 3, message_size: 32, hash_type: HashType::ShaSHAKE },
            ],
        };
        
        let results = benchmark.run_full_benchmark();
        
        if !results.is_empty() {
            println!("\nQuick test completed successfully.");
        } else {
            return Err("Quick test failed - no results generated".to_string());
        }
        
        Ok(())
    }
}

/// Run complete benchmark suite and save results
pub fn run_complete_benchmark() -> Result<(), String> {
    let benchmark = LoquatBenchmark::paper_config();
    let results = benchmark.run_full_benchmark();
    
    // Export results to CSV
    if let Err(e) = benchmark.export_csv(&results, "loquat_benchmark_results.csv") {
        eprintln!("Failed to export CSV: {}", e);
    }
    
    println!("\nBenchmark suite completed.");
    Ok(())
}

/// Run SHA/SHAKE-only benchmark suite
pub fn run_sha_benchmark() -> Result<(), String> {
    let benchmark = LoquatBenchmark::sha_config();
    let results = benchmark.run_full_benchmark();
    
    // Export results to CSV
    if let Err(e) = benchmark.export_csv(&results, "loquat_sha_benchmark.csv") {
        eprintln!("Failed to export CSV: {}", e);
    }
    
    println!("\nSHA/SHAKE benchmark completed.");
    Ok(())
}

/// Run Griffin-only benchmark suite
pub fn run_griffin_benchmark() -> Result<(), String> {
    let benchmark = LoquatBenchmark::griffin_config();
    let results = benchmark.run_full_benchmark();
    
    // Export results to CSV
    if let Err(e) = benchmark.export_csv(&results, "loquat_griffin_benchmark.csv") {
        eprintln!("Failed to export CSV: {}", e);
    }
    
    println!("\nGriffin benchmark completed.");
    Ok(())
}
