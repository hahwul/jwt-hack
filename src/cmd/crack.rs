use std::path::PathBuf;
use log::{error, info};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use rayon::prelude::*;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};

use crate::jwt;
use crate::crack;

/// Execute the crack command
pub fn execute(
    token: &str,
    mode: &str,
    wordlist: &Option<PathBuf>,
    chars: &str,
    concurrency: usize,
    max: usize,
    power: bool,
    verbose: bool,
) {
    println!("[*] Start {} cracking mode", mode);
    
    if mode == "dict" {
        if let Some(wordlist_path) = wordlist {
            if let Err(e) = crack_dictionary(token, wordlist_path, concurrency, power, verbose) {
                error!("Dictionary cracking failed: {}", e);
            }
        } else {
            error!("Wordlist is required for dictionary mode");
            error!("e.g jwt-hack crack {{JWT_CODE}} -w {{WORDLIST}}");
        }
    } else if mode == "brute" {
        if let Err(e) = crack_bruteforce(token, chars, max, concurrency, power, verbose) {
            error!("Bruteforce cracking failed: {}", e);
        }
    } else {
        error!("Invalid mode: {}", mode);
        error!("Supported modes: 'dict' or 'brute'");
    }
}

fn crack_dictionary(
    token: &str,
    wordlist_path: &PathBuf,
    concurrency: usize,
    power: bool,
    verbose: bool,
) -> anyhow::Result<()> {
    // Load wordlist
    let file = File::open(wordlist_path)?;
    let reader = BufReader::new(file);
    
    // Deduplicate words
    let mut words: HashSet<String> = HashSet::new();
    for line in reader.lines() {
        if let Ok(word) = line {
            words.insert(word);
        }
    }
    
    let words_vec: Vec<String> = words.into_iter().collect();
    info!("Loaded words (remove duplicated) size={}", words_vec.len());
    
    let found = Arc::new(Mutex::new(None::<String>));
    let pb = if !verbose {
        let progress = ProgressBar::new(words_vec.len() as u64);
        progress.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.red} [{elapsed_precise}] Cracking.. [{bar:40.cyan/blue}] {pos}/{len} ({percent}%)")
                .unwrap()
                .progress_chars("#>-")
        );
        Some(progress)
    } else {
        None
    };
    
    // Configure thread pool
    let pool_size = if power {
        rayon::current_num_threads()
    } else {
        concurrency.min(rayon::current_num_threads())
    };
    
    // Create a local thread pool instead of a global one
    let pool = match rayon::ThreadPoolBuilder::new()
        .num_threads(pool_size)
        .build() {
            Ok(pool) => pool,
            Err(e) => {
                error!("Failed to build thread pool: {}", e);
                return Err(anyhow::anyhow!("Thread pool initialization failed: {}", e));
            }
        };
    
    // Process words in parallel using the local pool
    pool.install(|| {
        words_vec.par_iter().for_each(|word| {
            // Skip if already found
            if found.lock().unwrap().is_some() {
                return;
            }
            
            // Update progress bar
            if let Some(pb) = &pb {
                pb.inc(1);
            }
            
            // Try to verify the token with this word
            match jwt::verify(token, word) {
                Ok(true) => {
                    if verbose {
                        info!("Found! Token signature secret is {} Signature=Verified Word={}", word, word);
                    } else if let Some(pb) = &pb {
                        pb.finish_and_clear();
                    }
                    
                    *found.lock().unwrap() = Some(word.clone());
                },
                _ => {
                    if verbose {
                        info!("Invalid signature word={}", word);
                    }
                }
            }
        });
    });
    
    if let Some(pb) = pb {
        pb.finish_and_clear();
    }
    
    if let Some(secret) = found.lock().unwrap().clone() {
        println!("[+] Found! JWT signature secret: {}", secret.bright_yellow());
    } else {
        println!("[-] Secret not found in wordlist");
    }
    
    println!("[+] Finish crack mode");
    Ok(())
}

fn crack_bruteforce(
    token: &str,
    chars: &str,
    max_length: usize,
    concurrency: usize,
    power: bool,
    verbose: bool,
) -> anyhow::Result<()> {
    let payloads = crack::generate_bruteforce_payloads(chars, max_length);
    info!("Generated {} potential payloads for bruteforce", payloads.len());
    
    // Now use the dictionary method with the generated payloads
    let temp_path = std::env::temp_dir().join("jwt-hack-bruteforce-temp.txt");
    {
        let mut file = File::create(&temp_path)?;
        use std::io::Write;
        for payload in &payloads {
            writeln!(file, "{}", payload)?;
        }
    }
    
    crack_dictionary(token, &temp_path, concurrency, power, verbose)?;
    
    // Clean up temporary file
    std::fs::remove_file(temp_path)?;
    
    Ok(())
}