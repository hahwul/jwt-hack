use colored::Colorize;
use indicatif::{HumanDuration, MultiProgress, ProgressBar, ProgressStyle};
use log::{error, info};
use rayon::prelude::*;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

use crate::crack;
use crate::jwt;
use crate::utils;

/// Maps preset names to their corresponding character sets
pub fn get_preset_chars(preset: &str) -> Option<String> {
    match preset {
        "az" => Some("abcdefghijklmnopqrstuvwxyz".to_string()),
        "AZ" => Some("ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string()),
        "aZ" => Some("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string()),
        "19" => Some("0123456789".to_string()),
        "aZ19" => Some("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".to_string()),
        "ascii" => Some(
            " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~".to_string()
        ),
        _ => None,
    }
}

/// Options for the crack command
pub struct CrackOptions<'a> {
    pub token: &'a str,
    pub mode: &'a str,
    pub wordlist: &'a Option<PathBuf>,
    pub chars: &'a str,
    pub preset: &'a Option<String>,
    pub concurrency: usize,
    pub max: usize,
    pub power: bool,
    pub verbose: bool,
    pub target_field: &'a Option<String>,
    pub pattern: &'a Option<String>,
}

/// Execute the crack command
#[allow(clippy::too_many_arguments)]
pub fn execute(
    token: &str,
    mode: &str,
    wordlist: &Option<PathBuf>,
    chars: &str,
    preset: &Option<String>,
    concurrency: usize,
    max: usize,
    power: bool,
    verbose: bool,
    target_field: &Option<String>,
    pattern: &Option<String>,
) {
    let options = CrackOptions {
        token,
        mode,
        wordlist,
        chars,
        preset,
        concurrency,
        max,
        power,
        verbose,
        target_field,
        pattern,
    };
    execute_with_options(&options);
}

/// Execute the crack command with options struct
fn execute_with_options(options: &CrackOptions) {
    // Handle targeted field cracking mode
    if let Some(target_field) = options.target_field {
        if let Err(e) = crack_target_field(options, target_field) {
            utils::log_error(format!("Targeted field cracking failed: {e}"));
        }
        return;
    }

    // Detect if this is a JWE token
    let token_type = jwt::detect_token_type(options.token);
    let is_jwe = token_type == jwt::TokenType::Jwe;

    if is_jwe {
        utils::log_info("Detected JWE token (5-part structure) - using JWE cracking mode");
        utils::log_info(
            "JWE cracking attempts direct key decryption instead of signature verification",
        );
    }

    if options.mode == "dict" {
        if let Some(wordlist_path) = options.wordlist {
            if let Err(e) = crack_dictionary(
                options.token,
                wordlist_path,
                options.concurrency,
                options.power,
                options.verbose,
                is_jwe,
            ) {
                utils::log_error(format!("Dictionary cracking failed: {e}"));
            }
        } else {
            utils::log_error("Wordlist is required for dictionary mode");
            utils::log_error("e.g jwt-hack crack {JWT_CODE} -w {WORDLIST}");
        }
    } else if options.mode == "brute" {
        // Resolve the character set to use - preset takes priority over chars
        let chars_to_use = if let Some(preset) = options.preset {
            match get_preset_chars(preset) {
                Some(preset_chars) => {
                    utils::log_info(format!("Using preset '{}': {}", preset, preset_chars));
                    preset_chars
                }
                None => {
                    utils::log_error(format!("Unknown preset: '{}'", preset));
                    utils::log_error("Available presets: az, AZ, aZ, 19, aZ19, ascii");
                    return;
                }
            }
        } else {
            options.chars.to_string()
        };

        if let Err(e) = crack_bruteforce(
            options.token,
            &chars_to_use,
            options.max,
            options.concurrency,
            options.power,
            options.verbose,
            is_jwe,
        ) {
            utils::log_error(format!("Bruteforce cracking failed: {e}"));
        }
    } else {
        utils::log_error(format!("Invalid mode: {}", options.mode));
        utils::log_error("Supported modes: 'dict' or 'brute'");
    }
}

const CHUNK_SIZE: usize = 4096;

fn create_crack_progress_bar(
    multi: &MultiProgress,
    total: u64,
    verbose: bool,
) -> Option<ProgressBar> {
    if verbose {
        return None;
    }
    let progress = multi.add(ProgressBar::new(total));
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.red} [{elapsed_precise}] Cracking.. [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}")
            .expect("valid progress bar template")
            .progress_chars("#>-")
    );
    Some(progress)
}

fn build_thread_pool(
    concurrency: usize,
    power: bool,
    _mode_name: &str,
) -> anyhow::Result<rayon::ThreadPool> {
    let pool_size = if power {
        rayon::current_num_threads()
    } else {
        concurrency.min(rayon::current_num_threads())
    };

    rayon::ThreadPoolBuilder::new()
        .num_threads(pool_size)
        .build()
        .map_err(|e| {
            error!("Failed to build thread pool: {e}");
            anyhow::anyhow!("Thread pool initialization failed: {}", e)
        })
}

fn spawn_rate_update_thread(
    attempts: &Arc<AtomicUsize>,
    pb: &Option<ProgressBar>,
) -> Option<std::thread::JoinHandle<()>> {
    let pb_clone = pb.clone();
    if let Some(ref progress) = pb_clone {
        let progress_clone = progress.clone();
        let attempts_clone = Arc::clone(attempts);
        Some(std::thread::spawn(move || {
            let mut last_count = 0;
            let mut last_time = Instant::now();

            while !progress_clone.is_finished() {
                std::thread::sleep(Duration::from_millis(500));
                let current_count = attempts_clone.load(Ordering::Relaxed);
                let current_time = Instant::now();
                let time_diff = current_time.duration_since(last_time).as_secs_f64();

                if time_diff > 0.0 {
                    let rate = (current_count - last_count) as f64 / time_diff;
                    progress_clone.set_message(format!("({rate:.2} keys/sec)"));

                    last_count = current_count;
                    last_time = current_time;
                }
            }
        }))
    } else {
        None
    }
}

#[allow(clippy::too_many_arguments)]
fn run_parallel_crack(
    pool: &rayon::ThreadPool,
    candidates: &[String],
    token: &str,
    found: &Arc<Mutex<Option<String>>>,
    found_flag: &Arc<AtomicBool>,
    attempts: &Arc<AtomicUsize>,
    pb: &Option<ProgressBar>,
    verbose: bool,
    is_jwe: bool,
) {
    pool.install(|| {
        candidates.par_chunks(CHUNK_SIZE).for_each(|chunk| {
            // Fast lock-free check before processing chunk
            if found_flag.load(Ordering::Relaxed) {
                return;
            }

            for candidate in chunk {
                // Lock-free early exit check
                if found_flag.load(Ordering::Relaxed) {
                    break;
                }

                let verification_result = if is_jwe {
                    jwt::decrypt_jwe(token, candidate).map(|_| true)
                } else {
                    jwt::verify(token, candidate)
                };

                match verification_result {
                    Ok(true) => {
                        if verbose {
                            let message = if is_jwe {
                                format!("Found! JWE encryption key is {candidate} Decryption=Success")
                            } else {
                                format!("Found! Token signature secret is {candidate} Signature=Verified")
                            };
                            info!("{}", message);
                        }

                        found_flag.store(true, Ordering::Relaxed);
                        *found.lock().unwrap_or_else(|e| e.into_inner()) = Some(candidate.clone());

                        if let Some(pb) = pb {
                            pb.finish_and_clear();
                        }
                        break;
                    }
                    _ => {
                        if verbose {
                            info!("Invalid signature candidate={candidate}");
                        }
                    }
                }
            }

            let chunk_len = chunk.len();
            attempts.fetch_add(chunk_len, Ordering::Relaxed);
            if let Some(ref progress) = pb {
                progress.inc(chunk_len as u64);
            }
        });
    });
}

fn cleanup_crack_progress(
    pb: Option<ProgressBar>,
    update_thread: Option<std::thread::JoinHandle<()>>,
) {
    if let Some(pb) = pb {
        pb.finish_and_clear();
    }
    if let Some(handle) = update_thread {
        let _ = handle.join();
    }
}

fn report_crack_results(
    found: &Arc<Mutex<Option<String>>>,
    elapsed: Duration,
    attempts_total: usize,
    token: &str,
    is_jwe: bool,
) {
    let elapsed_secs = elapsed.as_secs_f64();
    let rate = if elapsed_secs > 0.0 {
        attempts_total as f64 / elapsed_secs
    } else {
        0.0
    };

    if let Some(secret) = found.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        let label = if is_jwe {
            "Encryption key found"
        } else {
            "Secret found"
        };
        let secret_label = if is_jwe { "Key" } else { "Secret" };

        eprintln!("\n  {} {}", "✓".green(), label.bold());
        println!();
        println!("  {:<14}{}", secret_label.bold(), secret.bold());
        println!(
            "  {:<14}{} ({:.2} keys/sec)",
            "Time".bold(),
            HumanDuration(elapsed),
            rate
        );
        println!("  {:<14}{}", "Token".bold(), utils::format_jwt_token(token));
    } else {
        let label = if is_jwe {
            "Key not found"
        } else {
            "Secret not found"
        };
        eprintln!(
            "\n  {} {} ({} keys in {}, {:.2} keys/sec)",
            "✗".red(),
            label.bold(),
            attempts_total,
            HumanDuration(elapsed),
            rate
        );
    }
}

fn crack_dictionary(
    token: &str,
    wordlist_path: &PathBuf,
    concurrency: usize,
    power: bool,
    verbose: bool,
    is_jwe: bool,
) -> anyhow::Result<()> {
    let start_time = Instant::now();

    let file = File::open(wordlist_path)?;
    let reader = BufReader::new(file);

    let multi = MultiProgress::new();
    let loading_pb = multi.add(ProgressBar::new_spinner());
    loading_pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.blue} {msg}")
            .expect("valid spinner template")
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    loading_pb.set_message("Reading wordlist...");
    loading_pb.enable_steady_tick(Duration::from_millis(100));

    let mut words: HashSet<String> = HashSet::new();
    for word in reader.lines().map_while(Result::ok) {
        words.insert(word);
        if words.len().is_multiple_of(10000) {
            loading_pb.set_message(format!("Reading wordlist... ({} words)", words.len()));
        }
    }

    let words_vec: Vec<String> = words.into_iter().collect();
    loading_pb.finish_with_message(format!(
        "Loaded {} unique words in {}",
        words_vec.len(),
        HumanDuration(start_time.elapsed())
    ));
    let found = Arc::new(Mutex::new(None::<String>));
    let found_flag = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();

    let pb = create_crack_progress_bar(&multi, words_vec.len() as u64, verbose);
    let pool = build_thread_pool(concurrency, power, "dictionary")?;
    let update_thread = spawn_rate_update_thread(&attempts, &pb);

    run_parallel_crack(
        &pool,
        &words_vec,
        token,
        &found,
        &found_flag,
        &attempts,
        &pb,
        verbose,
        is_jwe,
    );
    cleanup_crack_progress(pb, update_thread);

    // Zeroize wordlist candidates from memory
    let mut words_vec = words_vec;
    for word in &mut words_vec {
        word.zeroize();
    }

    let elapsed = start.elapsed();
    let attempts_total = attempts.load(Ordering::Relaxed);
    report_crack_results(&found, elapsed, attempts_total, token, is_jwe);

    Ok(())
}

/// Streaming brute-force: generates and cracks simultaneously without pre-allocating all combinations.
/// This dramatically reduces memory usage and eliminates generation latency.
fn crack_bruteforce(
    token: &str,
    chars: &str,
    max_length: usize,
    concurrency: usize,
    power: bool,
    verbose: bool,
    is_jwe: bool,
) -> anyhow::Result<()> {
    let start_time = Instant::now();
    let multi = MultiProgress::new();

    let total_combinations = crack::brute::estimate_combinations(chars.len(), max_length);

    let found = Arc::new(Mutex::new(None::<String>));
    let found_flag = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicUsize::new(0));

    let pb = create_crack_progress_bar(&multi, total_combinations, verbose);
    let pool = build_thread_pool(concurrency, power, "bruteforce")?;
    let update_thread = spawn_rate_update_thread(&attempts, &pb);

    utils::log_info(format!(
        "Streaming brute-force: {} total combinations (length 1..{})",
        total_combinations, max_length
    ));

    // Stream through each length, generating chunks and cracking them immediately
    const GEN_CHUNK_SIZE: usize = 10000;

    for length in 1..=max_length {
        if found_flag.load(Ordering::Relaxed) {
            break;
        }

        for mut chunk in crack::brute::generate_combinations_chunked(chars, length, GEN_CHUNK_SIZE)
        {
            if found_flag.load(Ordering::Relaxed) {
                break;
            }

            // Crack this chunk immediately using the thread pool
            run_parallel_crack(
                &pool,
                &chunk,
                token,
                &found,
                &found_flag,
                &attempts,
                &pb,
                verbose,
                is_jwe,
            );

            // Zeroize brute-force candidates from memory
            for candidate in &mut chunk {
                candidate.zeroize();
            }
        }
    }

    cleanup_crack_progress(pb, update_thread);

    let elapsed = start_time.elapsed();
    let attempts_total = attempts.load(Ordering::Relaxed);
    report_crack_results(&found, elapsed, attempts_total, token, is_jwe);

    Ok(())
}

/// Targeted field brute-force: modify a specific JWT header/payload field (e.g., kid, jti)
/// and test each variation against the target. Useful for testing key ID injection,
/// path traversal in kid, or discovering valid JTI values.
fn crack_target_field(options: &CrackOptions, target_field: &str) -> anyhow::Result<()> {
    let start_time = Instant::now();
    let multi = MultiProgress::new();

    // Decode the original token to get header and claims
    let decoded =
        jwt::decode(options.token).map_err(|e| anyhow::anyhow!("Failed to decode token: {e}"))?;

    let header = decoded.header;
    let claims = decoded.claims;

    // Determine algorithm from header
    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("HS256")
        .to_string();

    // Determine if field is in header or payload
    let field_location = if header.contains_key(target_field) {
        "header"
    } else if claims.get(target_field).is_some() {
        "payload"
    } else {
        // Default: kid goes in header, jti goes in payload
        match target_field {
            "kid" | "jku" | "x5u" | "x5c" | "cty" | "typ" => "header",
            _ => "payload",
        }
    };

    utils::log_info(format!(
        "Targeted field cracking: field='{}' location='{}' algorithm='{}'",
        target_field, field_location, alg
    ));

    // Generate candidates based on mode
    let candidates: Vec<String> = if options.mode == "dict" {
        if let Some(wordlist_path) = options.wordlist {
            let file = File::open(wordlist_path)?;
            let reader = BufReader::new(file);
            let mut words: HashSet<String> = HashSet::new();
            for word in reader.lines().map_while(Result::ok) {
                words.insert(word);
            }
            words.into_iter().collect()
        } else {
            return Err(anyhow::anyhow!("Wordlist is required for dictionary mode"));
        }
    } else {
        vec![]
    };

    let pattern = options.pattern.as_deref();
    let found = Arc::new(Mutex::new(None::<String>));
    let found_flag = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicUsize::new(0));
    let pool = build_thread_pool(options.concurrency, options.power, "target-field")?;

    // Convert header HashMap to a shareable form
    let header_map: std::collections::HashMap<String, String> = header
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
        .collect();

    if options.mode == "brute" {
        let chars_to_use = if let Some(preset) = options.preset {
            get_preset_chars(preset)
                .ok_or_else(|| anyhow::anyhow!("Unknown preset: '{}'", preset))?
        } else {
            options.chars.to_string()
        };

        let total = crack::brute::estimate_combinations(chars_to_use.len(), options.max);
        let pb = create_crack_progress_bar(&multi, total, options.verbose);
        let update_thread = spawn_rate_update_thread(&attempts, &pb);

        for length in 1..=options.max {
            if found_flag.load(Ordering::Relaxed) {
                break;
            }
            for chunk in crack::brute::generate_combinations_chunked(&chars_to_use, length, 10000) {
                if found_flag.load(Ordering::Relaxed) {
                    break;
                }
                let expanded: Vec<String> = chunk
                    .into_iter()
                    .map(|v| apply_pattern(pattern, &v))
                    .collect();

                run_target_field_crack(
                    &pool,
                    &expanded,
                    &header_map,
                    &claims,
                    target_field,
                    field_location,
                    &alg,
                    options.token,
                    &found,
                    &found_flag,
                    &attempts,
                    &pb,
                    options.verbose,
                );
            }
        }

        cleanup_crack_progress(pb, update_thread);
    } else {
        let pb = create_crack_progress_bar(&multi, candidates.len() as u64, options.verbose);
        let update_thread = spawn_rate_update_thread(&attempts, &pb);

        let expanded: Vec<String> = candidates
            .into_iter()
            .map(|v| apply_pattern(pattern, &v))
            .collect();

        run_target_field_crack(
            &pool,
            &expanded,
            &header_map,
            &claims,
            target_field,
            field_location,
            &alg,
            options.token,
            &found,
            &found_flag,
            &attempts,
            &pb,
            options.verbose,
        );

        cleanup_crack_progress(pb, update_thread);
    }

    let elapsed = start_time.elapsed();
    let attempts_total = attempts.load(Ordering::Relaxed);
    let rate = if elapsed.as_secs_f64() > 0.0 {
        attempts_total as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };

    if let Some(value) = found.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        eprintln!(
            "\n  {} {}",
            "✓".green(),
            "Matching field value found".bold()
        );
        println!();
        println!("  {:<14}{}", "Field".bold(), target_field.bold());
        println!("  {:<14}{}", "Value".bold(), value.bold());
        println!(
            "  {:<14}{} ({:.2} attempts/sec)",
            "Time".bold(),
            HumanDuration(elapsed),
            rate
        );
    } else {
        eprintln!(
            "\n  {} {} ({} attempts in {}, {:.2} attempts/sec)",
            "✗".red(),
            "No matching field value found".bold(),
            attempts_total,
            HumanDuration(elapsed),
            rate
        );
    }

    Ok(())
}

/// Apply a pattern template to a value. If pattern contains `{}`, replace it.
/// Otherwise, use the value as-is.
fn apply_pattern(pattern: Option<&str>, value: &str) -> String {
    match pattern {
        Some(p) if p.contains("{}") => p.replace("{}", value),
        _ => value.to_string(),
    }
}

/// Run parallel cracking for targeted field brute-force
#[allow(clippy::too_many_arguments)]
fn run_target_field_crack(
    pool: &rayon::ThreadPool,
    candidates: &[String],
    header_map: &std::collections::HashMap<String, String>,
    claims: &serde_json::Value,
    target_field: &str,
    field_location: &str,
    alg: &str,
    original_token: &str,
    found: &Arc<Mutex<Option<String>>>,
    found_flag: &Arc<AtomicBool>,
    attempts: &Arc<AtomicUsize>,
    pb: &Option<ProgressBar>,
    verbose: bool,
) {
    pool.install(|| {
        candidates.par_chunks(CHUNK_SIZE).for_each(|chunk| {
            if found_flag.load(Ordering::Relaxed) {
                return;
            }

            for candidate in chunk {
                if found_flag.load(Ordering::Relaxed) {
                    break;
                }

                // Build modified header params and claims
                let mut extra_headers: std::collections::HashMap<&str, &str> =
                    std::collections::HashMap::new();
                let mut modified_claims = claims.clone();

                // Add existing non-standard header params
                for (k, v) in header_map.iter() {
                    if k != "alg" && k != "typ" {
                        extra_headers.insert(k.as_str(), v.as_str());
                    }
                }

                if field_location == "header" {
                    extra_headers.insert(target_field, candidate.as_str());
                } else {
                    modified_claims[target_field] = serde_json::Value::String(candidate.clone());
                }

                let encode_options = jwt::EncodeOptions {
                    algorithm: alg,
                    key_data: jwt::KeyData::Secret(""),
                    header_params: if extra_headers.is_empty() {
                        None
                    } else {
                        Some(extra_headers)
                    },
                    compress_payload: false,
                };

                match jwt::encode_with_options(&modified_claims, &encode_options) {
                    Ok(new_token) => {
                        // Check if the token with this field value produces a matching signature
                        let original_parts: Vec<&str> = original_token.split('.').collect();
                        let new_parts: Vec<&str> = new_token.split('.').collect();

                        if original_parts.len() >= 3
                            && new_parts.len() >= 3
                            && original_parts[2] == new_parts[2]
                        {
                            if verbose {
                                info!(
                                    "Match found! {}={} produces matching token",
                                    target_field, candidate
                                );
                            }

                            found_flag.store(true, Ordering::Relaxed);
                            *found.lock().unwrap_or_else(|e| e.into_inner()) = Some(candidate.clone());

                            if let Some(pb) = pb {
                                pb.finish_and_clear();
                            }
                            break;
                        }
                    }
                    Err(_) => {
                        if verbose {
                            info!("Failed to encode with {}={}", target_field, candidate);
                        }
                    }
                }
            }

            let chunk_len = chunk.len();
            attempts.fetch_add(chunk_len, Ordering::Relaxed);
            if let Some(ref progress) = pb {
                progress.inc(chunk_len as u64);
            }
        });
    });
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
            compress_payload: false,
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
                &None, // preset
                10,
                4,
                false,
                false,
                &None, // target_field
                &None, // pattern
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
            preset: &None, // preset
            concurrency: 10,
            max: 4,
            power: false,
            verbose: false,
            target_field: &None,
            pattern: &None,
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
            preset: &None, // preset
            concurrency: 10,
            max: 4,
            power: false,
            verbose: false,
            target_field: &None,
            pattern: &None,
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
            false, // Not a JWE token
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
            false, // Not a JWE token
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
            false, // Not a JWE token
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
            false, // Not a JWE token
        );

        assert!(
            result.is_ok(),
            "crack_bruteforce should not fail when no match is found"
        );
    }

    #[test]
    fn test_get_preset_chars() {
        // Test valid presets
        assert_eq!(
            get_preset_chars("az"),
            Some("abcdefghijklmnopqrstuvwxyz".to_string())
        );
        assert_eq!(
            get_preset_chars("AZ"),
            Some("ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string())
        );
        assert_eq!(
            get_preset_chars("aZ"),
            Some("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string())
        );
        assert_eq!(get_preset_chars("19"), Some("0123456789".to_string()));
        assert_eq!(
            get_preset_chars("aZ19"),
            Some("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".to_string())
        );

        // Test ascii preset contains expected characters
        let ascii_chars = get_preset_chars("ascii").unwrap();
        assert!(ascii_chars.contains(" "));
        assert!(ascii_chars.contains("!"));
        assert!(ascii_chars.contains("~"));
        assert!(ascii_chars.contains("0"));
        assert!(ascii_chars.contains("A"));
        assert!(ascii_chars.contains("a"));

        // Test invalid preset
        assert_eq!(get_preset_chars("invalid"), None);
        assert_eq!(get_preset_chars(""), None);
    }

    #[test]
    fn test_execute_with_preset() {
        let token = create_test_token("ab");

        // Test with 'az' preset - should find the secret "ab"
        let preset = Some("az".to_string());
        let options = CrackOptions {
            token: &token,
            mode: "brute",
            wordlist: &None,
            chars: "default_not_used", // Should be overridden by preset
            preset: &preset,
            concurrency: 2,
            max: 2,
            power: false,
            verbose: false,
            target_field: &None,
            pattern: &None,
        };

        // This should execute without panicking
        let result = std::panic::catch_unwind(|| {
            execute_with_options(&options);
        });
        assert!(
            result.is_ok(),
            "execute_with_options should work with valid preset"
        );
    }

    #[test]
    fn test_execute_with_invalid_preset() {
        let token = create_test_token("secret");

        // Test with invalid preset
        let preset = Some("invalid_preset".to_string());
        let options = CrackOptions {
            token: &token,
            mode: "brute",
            wordlist: &None,
            chars: "abc",
            preset: &preset,
            concurrency: 2,
            max: 2,
            power: false,
            verbose: false,
            target_field: &None,
            pattern: &None,
        };

        // This should execute without panicking (but will print error)
        let result = std::panic::catch_unwind(|| {
            execute_with_options(&options);
        });
        assert!(
            result.is_ok(),
            "execute_with_options should handle invalid preset gracefully"
        );
    }

    #[test]
    fn test_execute_without_preset() {
        let token = create_test_token("ab");

        // Test without preset - should use chars
        let options = CrackOptions {
            token: &token,
            mode: "brute",
            wordlist: &None,
            chars: "abc", // Should be used since no preset
            preset: &None,
            concurrency: 2,
            max: 2,
            power: false,
            verbose: false,
            target_field: &None,
            pattern: &None,
        };

        // This should execute without panicking
        let result = std::panic::catch_unwind(|| {
            execute_with_options(&options);
        });
        assert!(
            result.is_ok(),
            "execute_with_options should work without preset"
        );
    }
}
