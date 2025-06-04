use std::env;
use vc_pqc::benchmark::{LoquatBenchmark, BenchmarkConfig, HashType, 
                       run_complete_benchmark, run_sha_benchmark, run_griffin_benchmark};

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() > 1 {
        match args[1].as_str() {
            "quick" => {
                println!("Running Quick Benchmark (3 iterations per security level)");
                run_quick_benchmark();
            }
            "standard" => {
                println!("Running Standard Benchmark (10 iterations per security level)");
                run_standard_benchmark();
            }
            "paper" => {
                println!("Running Paper-Style Benchmark (20 iterations, matches paper format)");
                if let Err(e) = run_complete_benchmark() {
                    eprintln!("Benchmark failed: {}", e);
                    std::process::exit(1);
                }
            }
            "sha" => {
                println!("Running SHA/SHAKE-only Benchmark (20 iterations)");
                if let Err(e) = run_sha_benchmark() {
                    eprintln!("SHA benchmark failed: {}", e);
                    std::process::exit(1);
                }
            }
            "griffin" => {
                println!("Running Griffin-only Benchmark (20 iterations)");
                if let Err(e) = run_griffin_benchmark() {
                    eprintln!("Griffin benchmark failed: {}", e);
                    std::process::exit(1);
                }
            }
            "compare" => {
                println!("Running SHA vs Griffin Comparison Benchmark");
                run_comparison_benchmark();
            }
            "custom" => {
                if args.len() < 4 {
                    println!("Custom benchmark requires: security_level iterations [hash_type]");
                    println!("   Example: cargo run --bin bench custom 128 5");
                    println!("   Example: cargo run --bin bench custom 100 10 griffin");
                    std::process::exit(1);
                }
                
                let security_level: u32 = args[2].parse().unwrap_or_else(|_| {
                    eprintln!("Invalid security level: {}", args[2]);
                    std::process::exit(1);
                });
                
                let iterations: usize = args[3].parse().unwrap_or_else(|_| {
                    eprintln!("Invalid iteration count: {}", args[3]);
                    std::process::exit(1);
                });
                
                let hash_type = if args.len() > 4 {
                    match args[4].to_lowercase().as_str() {
                        "griffin" => HashType::Griffin,
                        "sha" | "shake" => HashType::ShaSHAKE,
                        _ => {
                            eprintln!("Invalid hash type: {}. Use 'sha' or 'griffin'", args[4]);
                            std::process::exit(1);
                        }
                    }
                } else {
                    HashType::ShaSHAKE
                };
                
                run_custom_benchmark(security_level, iterations, hash_type);
            }
            "help" | "--help" | "-h" => {
                print_help();
            }
            _ => {
                println!("Unknown command: {}", args[1]);
                print_help();
                std::process::exit(1);
            }
        }
    } else {
        print_help();
    }
}

fn run_quick_benchmark() {
    let benchmark = LoquatBenchmark {
        configs: vec![
            BenchmarkConfig { security_level: 80, num_iterations: 3, message_size: 32, hash_type: HashType::ShaSHAKE },
            BenchmarkConfig { security_level: 100, num_iterations: 3, message_size: 32, hash_type: HashType::ShaSHAKE },
            BenchmarkConfig { security_level: 128, num_iterations: 3, message_size: 32, hash_type: HashType::ShaSHAKE },
        ],
    };
    
    let results = benchmark.run_full_benchmark();
    
    if let Err(e) = benchmark.export_csv(&results, "loquat_quick_benchmark.csv") {
        eprintln!("Failed to export CSV: {}", e);
    }
}

fn run_standard_benchmark() {
    let benchmark = LoquatBenchmark {
        configs: vec![
            BenchmarkConfig { security_level: 80, num_iterations: 10, message_size: 32, hash_type: HashType::ShaSHAKE },
            BenchmarkConfig { security_level: 100, num_iterations: 10, message_size: 32, hash_type: HashType::ShaSHAKE },
            BenchmarkConfig { security_level: 128, num_iterations: 10, message_size: 32, hash_type: HashType::ShaSHAKE },
        ],
    };
    let results = benchmark.run_full_benchmark();
    
    if let Err(e) = benchmark.export_csv(&results, "loquat_standard_benchmark.csv") {
        eprintln!("Failed to export CSV: {}", e);
    }
}

fn run_comparison_benchmark() {
    // First run SHA/SHAKE variants
    println!("Phase 1: Benchmarking SHA/SHAKE variants...");
    if let Err(e) = run_sha_benchmark() {
        eprintln!("SHA benchmark failed: {}", e);
        return;
    }
    
    println!("\nPhase 2: Benchmarking Griffin variants...");
    if let Err(e) = run_griffin_benchmark() {
        eprintln!("Griffin benchmark failed: {}", e);
        return;
    }
    
    println!("\nComparison benchmark completed.");
    println!("Results saved to:");
    println!("   - loquat_sha_benchmark.csv");
    println!("   - loquat_griffin_benchmark.csv");
}

fn run_custom_benchmark(security_level: u32, iterations: usize, hash_type: HashType) {
    println!("Running Custom Benchmark:");
    println!("   Security Level: LOQUAT-{}", security_level);
    println!("   Hash Function:  {}", hash_type);
    println!("   Iterations: {}", iterations);
    
    let benchmark = LoquatBenchmark {
        configs: vec![
            BenchmarkConfig { 
                security_level, 
                num_iterations: iterations, 
                message_size: 32,
                hash_type: hash_type.clone(),
            },
        ],
    };
    
    let results = benchmark.run_full_benchmark();
    
    let hash_suffix = match hash_type {
        HashType::ShaSHAKE => "sha",
        HashType::Griffin => "griffin",
    };
    
    let filename = format!("loquat_custom_LOQUAT{}_{}_{}_{}iter.csv", 
                          security_level, hash_suffix, hash_suffix, iterations);
    if let Err(e) = benchmark.export_csv(&results, &filename) {
        eprintln!("Failed to export CSV: {}", e);
    }
}

fn print_help() {
    println!("Loquat Benchmark Suite");
    println!("======================");
    println!();
    println!("USAGE:");
    println!("    cargo run --bin bench [COMMAND] [OPTIONS]");
    println!();
    println!("COMMANDS:");
    println!("    quick                         Run quick benchmark (3 iterations, SHA/SHAKE only)");
    println!("    standard                      Run standard benchmark (10 iterations, SHA/SHAKE only)");
    println!("    paper                         Run paper-style benchmark (20 iterations, both hash types)");
    println!("    sha                           Run SHA/SHAKE-only benchmark (20 iterations)");
    println!("    griffin                       Run Griffin-only benchmark (20 iterations)");
    println!("    compare                       Run SHA vs Griffin comparison");
    println!("    custom <level> <iter> [hash]  Run custom benchmark");
    println!("                                  <level>: Security level (80, 100, 128)");
    println!("                                  <iter>:  Number of iterations");
    println!("                                  [hash]:  Hash type (sha, griffin) [optional]");
    println!("    help                          Show this help message");
    println!();
    println!("EXAMPLES:");
    println!("    cargo run --bin bench quick               # Quick SHA/SHAKE test");
    println!("    cargo run --bin bench paper               # Full paper benchmark (both hashes)");
    println!("    cargo run --bin bench griffin             # Griffin-only benchmark");
    println!("    cargo run --bin bench compare             # SHA vs Griffin comparison");
    println!("    cargo run --bin bench custom 100 15       # Custom LOQUAT-100, 15 iterations (SHA)");
    println!("    cargo run --bin bench custom 128 10 griffin # Custom LOQUAT-128, 10 iterations (Griffin)");
    println!();
    println!("OUTPUT:");
    println!("    Results are displayed in console and exported to CSV files.");
    println!("    CSV files: loquat_[type]_benchmark.csv");
    println!();
    println!("METRICS MEASURED:");
    println!("    - kappa (Query Complexity): Number of oracle queries");
    println!("    - |sigma| (Signature Size): Size in kilobytes");
    println!("    - t_P (Signing Time): Time in milliseconds");
    println!("    - t_V (Verification Time): Time in milliseconds");
    println!("    - Setup/KeyGen Times: Additional timing metrics");
    println!("    - Hash Type: SHA/SHAKE vs Griffin performance comparison");
    println!();
    println!("HASH FUNCTIONS:");
    println!("    - SHA/SHAKE: Standard cryptographic hash (generally faster)");
    println!("    - Griffin:   SNARK-friendly hash (generally slower but SNARK-optimized)");
} 