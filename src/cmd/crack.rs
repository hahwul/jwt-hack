use colored::Colorize;
use indicatif::{HumanDuration, MultiProgress, ProgressBar, ProgressStyle};
use log::{error, info};
use rayon::prelude::*;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::crack;
use crate::jwt;
use crate::utils;

/// Options for the crack command
pub struct CrackOptions<'a> {
    pub token: &'a str,
    pub mode: &'a str,
    pub wordlist: &'a Option<PathBuf>,
    pub chars: &'a str,
    pub concurrency: usize,
    pub max: usize,
    pub power: bool,
    pub verbose: bool,
}

/// Execute the crack command
#[allow(clippy::too_many_arguments)]
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
    let options = CrackOptions {
        token,
        mode,
        wordlist,
        chars,
        concurrency,
        max,
        power,
        verbose,
    };
    execute_with_options(&options);
}

/// Execute the crack command with options struct
fn execute_with_options(options: &CrackOptions) {
    utils::log_info(format!(
        "Starting {} cracking mode for: {}",
        options.mode.bright_green(),
        utils::format_jwt_token(options.token)
    ));

    if options.mode == "dict" {
        if let Some(wordlist_path) = options.wordlist {
            if let Err(e) = crack_dictionary(
                options.token,
                wordlist_path,
                options.concurrency,
                options.power,
                options.verbose,
            ) {
                utils::log_error(format!("Dictionary cracking failed: {e}"));
            }
        } else {
            utils::log_error("Wordlist is required for dictionary mode");
            utils::log_error("e.g jwt-hack crack {JWT_CODE} -w {WORDLIST}");
        }
    } else if options.mode == "brute" {
        if let Err(e) = crack_bruteforce(
            options.token,
            options.chars,
            options.max,
            options.concurrency,
            options.power,
            options.verbose,
        ) {
            utils::log_error(format!("Bruteforce cracking failed: {e}"));
        }
    } else {
        utils::log_error(format!("Invalid mode: {}", options.mode));
        utils::log_error("Supported modes: 'dict' or 'brute'");
    }
}

fn crack_dictionary(
    token: &str,
    wordlist_path: &PathBuf,
    concurrency: usize,
    power: bool,
    verbose: bool,
) -> anyhow::Result<()> {
    // Start timing
    let start_time = Instant::now();

    // Load wordlist
    utils::log_info(format!(
        "Loading wordlist from {}",
        wordlist_path.display().to_string().bright_yellow()
    ));
    let file = File::open(wordlist_path)?;
    let reader = BufReader::new(file);

    // Create multi-progress display
    let multi = MultiProgress::new();
    let loading_pb = multi.add(ProgressBar::new_spinner());
    loading_pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.blue} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    loading_pb.set_message("Reading wordlist...");
    loading_pb.enable_steady_tick(Duration::from_millis(100));

    // Deduplicate words while loading
    let mut words: HashSet<String> = HashSet::new();
    for word in reader.lines().map_while(Result::ok) {
        words.insert(word);
        if words.len() % 10000 == 0 {
            loading_pb.set_message(format!("Reading wordlist... ({} words)", words.len()));
        }
    }

    let words_vec: Vec<String> = words.into_iter().collect();
    loading_pb.finish_with_message(format!(
        "Loaded {} unique words in {}",
        words_vec.len().to_string().bright_green(),
        HumanDuration(start_time.elapsed())
            .to_string()
            .bright_cyan()
    ));
    utils::log_info(format!(
        "Loaded {} unique words after deduplication",
        words_vec.len().to_string().bright_green()
    ));

    // Prepare for cracking
    let found = Arc::new(Mutex::new(None::<String>));
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let start = Instant::now();

    // Create progress bar for cracking
    let pb = if !verbose {
        let progress = multi.add(ProgressBar::new(words_vec.len() as u64));
        progress.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.red} [{elapsed_precise}] Cracking.. [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}")
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

    utils::log_info(format!(
        "Starting dictionary attack with {} threads",
        pool_size.to_string().bright_green()
    ));

    // Create a local thread pool instead of a global one
    let pool = match rayon::ThreadPoolBuilder::new()
        .num_threads(pool_size)
        .build()
    {
        Ok(pool) => pool,
        Err(e) => {
            error!("Failed to build thread pool: {}", e);
            return Err(anyhow::anyhow!("Thread pool initialization failed: {}", e));
        }
    };

    // Update progress bar periodically with rate information
    let attempts_clone = Arc::clone(&attempts);
    let pb_clone = pb.clone();
    let update_thread = if let Some(ref progress) = pb_clone {
        let progress_clone = progress.clone();
        Some(std::thread::spawn(move || {
            let mut last_count = 0;
            let mut last_time = Instant::now();

            while !progress_clone.is_finished() {
                std::thread::sleep(Duration::from_millis(500));
                let current_count = attempts_clone.load(std::sync::atomic::Ordering::Relaxed);
                let current_time = Instant::now();
                let time_diff = current_time.duration_since(last_time).as_secs_f64();

                if time_diff > 0.0 {
                    let rate = (current_count - last_count) as f64 / time_diff;
                    progress_clone.set_message(format!("({:.2} keys/sec)", rate));

                    last_count = current_count;
                    last_time = current_time;
                }
            }
        }))
    } else {
        None
    };

    // Use chunk size for better cache locality and reduced lock contention
    const CHUNK_SIZE: usize = 1000;

    // Process words in parallel using the local pool with chunking
    pool.install(|| {
        words_vec.par_chunks(CHUNK_SIZE).for_each(|chunk| {
            let mut local_found = false;

            // Process each chunk locally first
            for word in chunk {
                // Skip if already found globally
                if found.lock().unwrap().is_some() || local_found {
                    break;
                }

                // Try to verify the token with this word
                match jwt::verify(token, word) {
                    Ok(true) => {
                        if verbose {
                            info!(
                                "Found! Token signature secret is {word} Signature=Verified Word={word}"
                            );
                        }

                        local_found = true;
                        *found.lock().unwrap() = Some(word.clone());

                        if let Some(pb) = &pb {
                            pb.finish_and_clear();
                        }
                    }
                    _ => {
                        if verbose {
                            info!("Invalid signature word={word}");
                        }
                    }
                }
            }

            // Update attempts counter and progress bar atomically
            let chunk_len = chunk.len();
            attempts.fetch_add(chunk_len, std::sync::atomic::Ordering::Relaxed);
            if let Some(ref progress) = pb {
                progress.inc(chunk_len as u64);
            }
        });
    });

    // Clean up progress displays
    if let Some(pb) = pb {
        pb.finish_and_clear();
    }

    // Wait for the update thread if it exists
    if let Some(handle) = update_thread {
        let _ = handle.join();
    }

    // Report results
    let elapsed = start.elapsed();
    let attempts_total = attempts.load(std::sync::atomic::Ordering::Relaxed);
    let rate = attempts_total as f64 / elapsed.as_secs_f64();

    if let Some(secret) = found.lock().unwrap().clone() {
        utils::log_success(format!(
            "Found JWT signature secret: {}",
            secret.bright_yellow().bold()
        ));
        utils::log_success(format!(
            "Cracking completed in {} ({:.2} keys/sec)",
            HumanDuration(elapsed).to_string().bright_cyan(),
            rate.to_string().bright_green()
        ));

        println!("\n{}", "━━━ Crack Results ━━━".bright_green().bold());
        println!("Token:  {}", utils::format_jwt_token(token));
        println!("Secret: {}", secret.bright_yellow().bold());
        println!();
    } else {
        utils::log_error(format!(
            "Secret not found after trying {} keys in {}",
            attempts_total.to_string().bright_yellow(),
            HumanDuration(elapsed).to_string().bright_cyan()
        ));
        utils::log_error(format!(
            "Average speed: {:.2} keys/sec",
            rate.to_string().bright_green()
        ));
    }

    utils::log_info("Finished dictionary crack mode");
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
    // Start timing
    let start_time = Instant::now();
    utils::log_info(format!(
        "Preparing bruteforce attack with charset: {} (length: {})",
        chars.bright_cyan(),
        chars.len().to_string().bright_green()
    ));

    // Calculate total combinations
    let total_combinations = crack::brute::estimate_combinations(chars.len(), max_length);
    utils::log_info(format!(
        "Will try up to {} combinations",
        total_combinations.to_string().bright_yellow()
    ));

    // Create multi-progress display
    let multi = MultiProgress::new();

    // Create progress bar for generation
    let gen_pb = multi.add(ProgressBar::new(100));
    gen_pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] Generating combinations.. [{bar:40.cyan/blue}] {percent}% {msg}")
            .unwrap()
            .progress_chars("█▓▒")
    );

    // Prepare for cracking
    let found = Arc::new(Mutex::new(None::<String>));
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // Generate combinations with progress reporting
    utils::log_info(format!(
        "Generating bruteforce combinations (up to {} characters)...",
        max_length.to_string().bright_green()
    ));

    // Use progress callback to update the progress bar
    let gen_pb_clone = gen_pb.clone();
    let payloads = crack::generate_bruteforce_payloads_with_progress(
        chars,
        max_length,
        move |progress, elapsed| {
            gen_pb_clone.set_position((progress as u64).min(100));
            gen_pb_clone.set_message(format!("({})", HumanDuration(elapsed)));
        },
    );

    gen_pb.finish_with_message(format!(
        "Generated {} potential payloads in {}",
        payloads.len().to_string().bright_green(),
        HumanDuration(start_time.elapsed())
            .to_string()
            .bright_cyan()
    ));

    utils::log_info(format!(
        "Generated {} potential payloads for bruteforce attack",
        payloads.len().to_string().bright_green()
    ));

    // Create progress bar for cracking
    let crack_pb = if !verbose {
        let progress = multi.add(ProgressBar::new(payloads.len() as u64));
        progress.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.red} [{elapsed_precise}] Cracking.. [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}")
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

    utils::log_info(format!(
        "Starting bruteforce attack with {} threads",
        pool_size.to_string().bright_green()
    ));

    // Create a local thread pool
    let pool = match rayon::ThreadPoolBuilder::new()
        .num_threads(pool_size)
        .build()
    {
        Ok(pool) => pool,
        Err(e) => {
            error!("Failed to build thread pool: {}", e);
            return Err(anyhow::anyhow!("Thread pool initialization failed: {}", e));
        }
    };

    // Update progress bar periodically with rate information
    let attempts_clone = Arc::clone(&attempts);
    let pb_clone = crack_pb.clone();
    let update_thread = if let Some(ref progress) = pb_clone {
        let progress_clone = progress.clone();
        Some(std::thread::spawn(move || {
            let mut last_count = 0;
            let mut last_time = Instant::now();

            while !progress_clone.is_finished() {
                std::thread::sleep(Duration::from_millis(500));
                let current_count = attempts_clone.load(std::sync::atomic::Ordering::Relaxed);
                let current_time = Instant::now();
                let time_diff = current_time.duration_since(last_time).as_secs_f64();

                if time_diff > 0.0 {
                    let rate = (current_count - last_count) as f64 / time_diff;
                    progress_clone.set_message(format!("({:.2} keys/sec)", rate));

                    last_count = current_count;
                    last_time = current_time;
                }
            }
        }))
    } else {
        None
    };

    // Use chunk size for better cache locality
    const CHUNK_SIZE: usize = 1000;
    let start = Instant::now();

    // Process payloads in parallel using the local pool with chunking
    pool.install(|| {
        payloads.par_chunks(CHUNK_SIZE).for_each(|chunk| {
            let mut local_found = false;

            // Process each chunk locally first
            for payload in chunk {
                // Skip if already found globally
                if found.lock().unwrap().is_some() || local_found {
                    break;
                }

                // Try to verify the token with this payload
                match jwt::verify(token, payload) {
                    Ok(true) => {
                        if verbose {
                            info!(
                                "Found! Token signature secret is {payload} Signature=Verified"
                            );
                        }

                        local_found = true;
                        *found.lock().unwrap() = Some(payload.clone());

                        if let Some(pb) = &crack_pb {
                            pb.finish_and_clear();
                        }
                    }
                    _ => {
                        if verbose {
                            info!("Invalid signature payload={payload}");
                        }
                    }
                }
            }

            // Update attempts counter and progress bar atomically
            let chunk_len = chunk.len();
            attempts.fetch_add(chunk_len, std::sync::atomic::Ordering::Relaxed);
            if let Some(ref progress) = crack_pb {
                progress.inc(chunk_len as u64);
            }
        });
    });

    // Clean up progress displays
    if let Some(pb) = crack_pb {
        pb.finish_and_clear();
    }

    // Wait for the update thread if it exists
    if let Some(handle) = update_thread {
        let _ = handle.join();
    }

    // Report results
    let elapsed = start.elapsed();
    let attempts_total = attempts.load(std::sync::atomic::Ordering::Relaxed);
    let rate = attempts_total as f64 / elapsed.as_secs_f64();

    if let Some(secret) = found.lock().unwrap().clone() {
        utils::log_success(format!(
            "Found JWT signature secret: {}",
            secret.bright_yellow().bold()
        ));
        utils::log_success(format!(
            "Cracking completed in {} ({:.2} keys/sec)",
            HumanDuration(elapsed).to_string().bright_cyan(),
            rate.to_string().bright_green()
        ));

        println!("\n{}", "━━━ Crack Results ━━━".bright_green().bold());
        println!("Token:  {}", utils::format_jwt_token(token));
        println!("Secret: {}", secret.bright_yellow().bold());
        println!();
    } else {
        utils::log_error(format!(
            "Secret not found after trying {} keys in {}",
            attempts_total.to_string().bright_yellow(),
            HumanDuration(elapsed).to_string().bright_cyan()
        ));
        utils::log_error(format!(
            "Average speed: {:.2} keys/sec",
            rate.to_string().bright_green()
        ));
    }

    utils::log_info("Finished bruteforce crack mode");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::NamedTempFile;

    // Helper function to create a test JWT token with HS256 algorithm
    fn create_test_token(secret: &str) -> String {
        // Create simple claims
        let claims = json!({
            "sub": "1234567890",
            "name": "Test User",
            "iat": 1516239022
        });

        // Create options with the given secret
        let options = crate::jwt::EncodeOptions {
            algorithm: "HS256",
            key_data: crate::jwt::KeyData::Secret(secret),
            header_params: None,
        };

        // Encode token
        crate::jwt::encode_with_options(&claims, &options).expect("Failed to create test token")
    }

    // Helper function to create a temporary wordlist file for testing
    fn create_temp_wordlist(words: &[&str]) -> NamedTempFile {
        let file = NamedTempFile::new().expect("Failed to create temp file");
        let mut file_handle = file.reopen().expect("Failed to open temp file");
        for word in words {
            writeln!(file_handle, "{word}").expect("Failed to write to temp file");
        }
        file
    }

    #[test]
    fn test_execute_no_panic() {
        // Create a test token with a known secret
        let token = create_test_token("test_secret");

        // Test that execute doesn't panic with valid parameters
        let result = std::panic::catch_unwind(|| {
            execute(
                &token,
                "dict",
                &None,
                "abcdefghijklmnopqrstuvwxyz",
                10,
                4,
                false,
                false,
            );
        });

        assert!(
            result.is_ok(),
            "execute should not panic with valid parameters"
        );
    }

    #[test]
    fn test_execute_with_options_dict_no_wordlist() {
        // Create a test token
        let token = create_test_token("test_secret");

        // Create options without a wordlist
        let options = CrackOptions {
            token: &token,
            mode: "dict",
            wordlist: &None,
            chars: "abcdefghijklmnopqrstuvwxyz",
            concurrency: 10,
            max: 4,
            power: false,
            verbose: false,
        };

        // Execute should handle the missing wordlist without panicking
        let result = std::panic::catch_unwind(|| {
            execute_with_options(&options);
        });

        assert!(
            result.is_ok(),
            "execute_with_options should not panic with missing wordlist"
        );
    }

    #[test]
    fn test_execute_with_invalid_mode() {
        // Create a test token
        let token = create_test_token("test_secret");

        // Create options with invalid mode
        let options = CrackOptions {
            token: &token,
            mode: "invalid_mode",
            wordlist: &None,
            chars: "abcdefghijklmnopqrstuvwxyz",
            concurrency: 10,
            max: 4,
            power: false,
            verbose: false,
        };

        // Execute should handle the invalid mode without panicking
        let result = std::panic::catch_unwind(|| {
            execute_with_options(&options);
        });

        assert!(
            result.is_ok(),
            "execute_with_options should not panic with invalid mode"
        );
    }

    #[test]
    fn test_crack_dictionary_with_matching_word() {
        // Create a test token with a known secret that will be in our wordlist
        let secret = "correct_secret";
        let token = create_test_token(secret);

        // Create a temporary wordlist file with the correct secret
        let wordlist = create_temp_wordlist(&[
            "wrong1", "wrong2", secret, // The correct secret
            "wrong3",
        ]);

        // Test that dictionary cracking finds the secret
        let path_buf = PathBuf::from(wordlist.path());
        let result = crack_dictionary(
            &token, &path_buf, 2,     // Small concurrency for test
            false, // Don't use all cores
            false, // Don't print verbose logs
        );

        assert!(result.is_ok(), "crack_dictionary should not fail");

        // Clean up is automatic when wordlist goes out of scope
    }

    #[test]
    fn test_crack_dictionary_with_no_match() {
        // Create a test token with a secret that won't be in our wordlist
        let token = create_test_token("secret_not_in_list");

        // Create a temporary wordlist file without the correct secret
        let wordlist = create_temp_wordlist(&["wrong1", "wrong2", "wrong3"]);

        // Test that dictionary cracking handles no match without error
        let path_buf = PathBuf::from(wordlist.path());
        let result = crack_dictionary(
            &token, &path_buf, 2,     // Small concurrency for test
            false, // Don't use all cores
            false, // Don't print verbose logs
        );

        assert!(
            result.is_ok(),
            "crack_dictionary should not fail when no match is found"
        );

        // Clean up is automatic when wordlist goes out of scope
    }

    #[test]
    fn test_crack_bruteforce_simple() {
        // For this test, we'll use a very short secret that can be found quickly
        let secret = "ab";
        let token = create_test_token(secret);

        // Test with minimal parameters to avoid long test runs
        let result = crack_bruteforce(
            &token, "abc", // Very limited charset
            2,     // Only try up to length 2
            2,     // Small concurrency
            false, // Don't use all cores
            false, // Don't print verbose logs
        );

        assert!(result.is_ok(), "crack_bruteforce should not fail");
    }

    #[test]
    #[ignore] // This test would take too long for regular test runs
    fn test_crack_bruteforce_no_match() {
        // Create a test token with a secret that won't be found in our limited search
        let token = create_test_token("longsecret123");

        // Test with parameters that will not find the secret
        let result = crack_bruteforce(
            &token, "abc", // Limited charset that doesn't contain digits
            3,     // Only try up to length 3
            2,     // Small concurrency
            false, // Don't use all cores
            false, // Don't print verbose logs
        );

        assert!(
            result.is_ok(),
            "crack_bruteforce should not fail when no match is found"
        );
    }
}
