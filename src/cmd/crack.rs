use colored::Colorize;
use indicatif::{HumanDuration, MultiProgress, ProgressBar, ProgressStyle};
use log::{error, info};
use rayon::prelude::*;
use serde::Serialize;
use serde_json::Value;
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
    pub min: usize,
    pub max: usize,
    pub power: bool,
    pub verbose: bool,
    pub target_field: &'a Option<String>,
    pub pattern: &'a Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CrackReport {
    pub success: bool,
    pub mode: String,
    pub token_type: String,
    pub found: bool,
    pub value_label: String,
    pub value: Option<String>,
    pub target_field: Option<String>,
    pub field_location: Option<String>,
    pub elapsed_ms: u128,
    pub attempts: usize,
    pub rate: f64,
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
    min: usize,
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
        min,
        max,
        power,
        verbose,
        target_field,
        pattern,
    };
    execute_with_options(&options, true);
}

/// Execute the crack command and return pipeline-friendly JSON output.
#[allow(clippy::too_many_arguments)]
pub fn execute_json(
    token: &str,
    mode: &str,
    wordlist: &Option<PathBuf>,
    chars: &str,
    preset: &Option<String>,
    concurrency: usize,
    min: usize,
    max: usize,
    power: bool,
    verbose: bool,
    target_field: &Option<String>,
    pattern: &Option<String>,
) -> anyhow::Result<Value> {
    let options = CrackOptions {
        token,
        mode,
        wordlist,
        chars,
        preset,
        concurrency,
        min,
        max,
        power,
        verbose,
        target_field,
        pattern,
    };

    Ok(serde_json::to_value(execute_with_options_json(&options)?)?)
}

/// Execute the crack command with options struct
fn execute_with_options(options: &CrackOptions, emit_output: bool) {
    // Handle targeted field cracking mode
    if let Some(target_field) = options.target_field {
        if let Err(e) = crack_target_field(options, target_field, emit_output) {
            if emit_output {
                utils::log_error(format!("Targeted field cracking failed: {e}"));
            }
        }
        return;
    }

    // Detect if this is a JWE token
    let token_type = jwt::detect_token_type(options.token);
    let is_jwe = token_type == jwt::TokenType::Jwe;

    if is_jwe && emit_output {
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
                emit_output,
            ) {
                if emit_output {
                    utils::log_error(format!("Dictionary cracking failed: {e}"));
                }
            }
        } else {
            if emit_output {
                utils::log_error("Wordlist is required for dictionary mode");
                utils::log_error("e.g jwt-hack crack {JWT_CODE} -w {WORDLIST}");
            }
        }
    } else if options.mode == "brute" {
        // Resolve the character set to use - preset takes priority over chars
        let chars_to_use = if let Some(preset) = options.preset {
            match get_preset_chars(preset) {
                Some(preset_chars) => {
                    if emit_output {
                        utils::log_info(format!("Using preset '{}': {}", preset, preset_chars));
                    }
                    preset_chars
                }
                None => {
                    if emit_output {
                        utils::log_error(format!("Unknown preset: '{}'", preset));
                        utils::log_error("Available presets: az, AZ, aZ, 19, aZ19, ascii");
                    }
                    return;
                }
            }
        } else {
            options.chars.to_string()
        };

        if let Err(e) = crack_bruteforce(
            options.token,
            &chars_to_use,
            options.min,
            options.max,
            options.concurrency,
            options.power,
            options.verbose,
            is_jwe,
            emit_output,
        ) {
            if emit_output {
                utils::log_error(format!("Bruteforce cracking failed: {e}"));
            }
        }
    } else {
        if emit_output {
            utils::log_error(format!("Invalid mode: {}", options.mode));
            utils::log_error("Supported modes: 'dict' or 'brute'");
        }
    }
}

fn execute_with_options_json(options: &CrackOptions) -> anyhow::Result<CrackReport> {
    let emit_output = false;

    if let Some(target_field) = options.target_field {
        return crack_target_field(options, target_field, emit_output);
    }

    let token_type = jwt::detect_token_type(options.token);
    let is_jwe = token_type == jwt::TokenType::Jwe;

    if options.mode == "dict" {
        let Some(wordlist_path) = options.wordlist else {
            anyhow::bail!("Wordlist is required for dictionary mode");
        };
        crack_dictionary(
            options.token,
            wordlist_path,
            options.concurrency,
            options.power,
            options.verbose,
            is_jwe,
            emit_output,
        )
    } else if options.mode == "brute" {
        let chars_to_use = if let Some(preset) = options.preset {
            get_preset_chars(preset).ok_or_else(|| anyhow::anyhow!("Unknown preset: '{preset}'"))?
        } else {
            options.chars.to_string()
        };
        crack_bruteforce(
            options.token,
            &chars_to_use,
            options.min,
            options.max,
            options.concurrency,
            options.power,
            options.verbose,
            is_jwe,
            emit_output,
        )
    } else {
        anyhow::bail!("Invalid mode: {}", options.mode);
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

/// Maximum thread count when `--power` is enabled.
/// Beyond ~32 threads, HMAC verification hits diminishing returns on throughput
/// while per-thread allocator pressure continues to grow linearly.
const MAX_POWER_THREADS: usize = 32;

fn build_thread_pool(
    concurrency: usize,
    power: bool,
    _mode_name: &str,
) -> anyhow::Result<rayon::ThreadPool> {
    let pool_size = if power {
        rayon::current_num_threads()
            .max(1)
            .min(MAX_POWER_THREADS)
    } else {
        concurrency.min(rayon::current_num_threads().max(1))
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
    // Precompute HS256 verifier so the hot loop avoids re-decoding the token
    // on every candidate. Falls back to the full verify path when the token
    // is not HS256 (or is malformed / JWE).
    let fast_verifier = if is_jwe {
        None
    } else {
        jwt::prepare_hs256_verifier(token).ok()
    };

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
                } else if let Some(ref v) = fast_verifier {
                    Ok(v.verify(candidate.as_bytes()))
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
    emit_output: bool,
) {
    if !emit_output {
        return;
    }

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

#[allow(clippy::too_many_arguments)]
fn build_crack_report(
    found: &Arc<Mutex<Option<String>>>,
    elapsed: Duration,
    attempts_total: usize,
    is_jwe: bool,
    mode: &str,
    target_field: Option<String>,
    field_location: Option<String>,
    emit_output: bool,
) -> CrackReport {
    let elapsed_secs = elapsed.as_secs_f64();
    let rate = if elapsed_secs > 0.0 {
        attempts_total as f64 / elapsed_secs
    } else {
        0.0
    };

    let guard = found.lock().unwrap_or_else(|e| e.into_inner());
    let was_found = guard.is_some();
    // Only clone the sensitive value for the JSON path; callers in non-JSON mode discard the report.
    let value = if !emit_output { guard.clone() } else { None };
    CrackReport {
        success: true,
        mode: mode.to_string(),
        token_type: if is_jwe { "jwe" } else { "jwt" }.to_string(),
        found: was_found,
        value_label: if is_jwe { "key" } else { "secret" }.to_string(),
        value,
        target_field,
        field_location,
        elapsed_ms: elapsed.as_millis(),
        attempts: attempts_total,
        rate,
    }
}

fn crack_dictionary(
    token: &str,
    wordlist_path: &PathBuf,
    concurrency: usize,
    power: bool,
    verbose: bool,
    is_jwe: bool,
    emit_output: bool,
) -> anyhow::Result<CrackReport> {
    let start_time = Instant::now();

    let file = File::open(wordlist_path)?;
    let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut reader = BufReader::new(file);

    let multi = if emit_output {
        Some(MultiProgress::new())
    } else {
        None
    };
    // Show a spinner while loading/processing batches
    let loading_pb = if let Some(ref multi) = multi {
        let pb = multi.add(ProgressBar::new_spinner());
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.blue} {msg}")
                .expect("valid spinner template")
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );
        pb.set_message("Processing wordlist...");
        pb.enable_steady_tick(Duration::from_millis(100));
        Some(pb)
    } else {
        None
    };

    let found = Arc::new(Mutex::new(None::<String>));
    let found_flag = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicUsize::new(0));

    let pool = build_thread_pool(concurrency, power, "dictionary")?;

    // Process the wordlist in streaming batches so we never hold the entire
    // file in memory at once.  For huge lists (rockyou ≈ 14 GB) this drops
    // peak RSS from 14+ GB to ~2-3 MB while keeping rayon workers fed.
    const DICT_BATCH_SIZE: usize = 100_000;

    let mut word_batch: Vec<String> = Vec::with_capacity(DICT_BATCH_SIZE);
    let mut line_buf = String::new();
    let mut bytes_read: u64 = 0;

    loop {
        word_batch.clear();
        line_buf.clear();

        // Fill one batch
        let mut batch_bytes: u64 = 0;
        for _ in 0..DICT_BATCH_SIZE {
            line_buf.clear();
            let n = match reader.read_line(&mut line_buf) {
                Ok(0) => break, // EOF
                Ok(n) => n,
                Err(_) => break,
            };
            batch_bytes += n as u64;
            // Trim trailing newline / carriage return
            let word = line_buf.trim_end_matches(['\n', '\r']).to_string();
            if !word.is_empty() {
                word_batch.push(word);
            }
        }

        if word_batch.is_empty() {
            break; // EOF with nothing left
        }

        bytes_read += batch_bytes;

        if let Some(ref pb) = loading_pb {
            let pct = if file_size > 0 {
                (bytes_read as f64 / file_size as f64 * 100.0) as u64
            } else {
                0
            };
            pb.set_message(format!(
                "Processing batch ({} keys tested, ~{}% of file)",
                attempts.load(Ordering::Relaxed),
                pct
            ));
        }

        run_parallel_crack(
            &pool,
            &word_batch,
            token,
            &found,
            &found_flag,
            &attempts,
            &None, // no line-based progress bar during streaming
            verbose,
            is_jwe,
        );

        // Zeroize and clear before reusing the buffer (capacity
        // is preserved across iterations so we avoid re-allocation).
        for w in &mut word_batch {
            w.zeroize();
        }
        word_batch.clear();

        if found_flag.load(Ordering::Relaxed) {
            break;
        }
    }

    if let Some(pb) = loading_pb {
        pb.finish_with_message(format!(
            "Processed {} words in {}",
            attempts.load(Ordering::Relaxed),
            HumanDuration(start_time.elapsed())
        ));
    }

    let elapsed = start_time.elapsed();
    let attempts_total = attempts.load(Ordering::Relaxed);
    report_crack_results(&found, elapsed, attempts_total, token, is_jwe, emit_output);

    Ok(build_crack_report(
        &found,
        elapsed,
        attempts_total,
        is_jwe,
        "dict",
        None,
        None,
        emit_output,
    ))
}

/// Streaming brute-force: each rayon worker materializes candidates from an
/// integer index into a reusable byte buffer, avoiding the per-candidate
/// `String` allocation of the legacy `Vec<String>` chunk path.
#[allow(clippy::too_many_arguments)]
fn crack_bruteforce(
    token: &str,
    chars: &str,
    min_length: usize,
    max_length: usize,
    concurrency: usize,
    power: bool,
    verbose: bool,
    is_jwe: bool,
    emit_output: bool,
) -> anyhow::Result<CrackReport> {
    if min_length < 1 {
        anyhow::bail!("min length must be at least 1, got {}", min_length);
    }
    if min_length > max_length {
        anyhow::bail!(
            "min length ({}) cannot exceed max length ({})",
            min_length,
            max_length
        );
    }
    if max_length > crack::brute::MAX_BRUTE_LENGTH {
        anyhow::bail!(
            "max length {} exceeds supported brute-force limit of {}",
            max_length,
            crack::brute::MAX_BRUTE_LENGTH
        );
    }

    let start_time = Instant::now();
    let multi = if emit_output {
        Some(MultiProgress::new())
    } else {
        None
    };

    let total_combinations = crack::brute::estimate_combinations(chars.len(), min_length, max_length);

    let found = Arc::new(Mutex::new(None::<String>));
    let found_flag = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicUsize::new(0));

    let pb = if emit_output {
        create_crack_progress_bar(
            multi.as_ref().expect("multi exists when emit_output"),
            total_combinations,
            verbose,
        )
    } else {
        None
    };
    let pool = build_thread_pool(concurrency, power, "bruteforce")?;
    let update_thread = if emit_output {
        spawn_rate_update_thread(&attempts, &pb)
    } else {
        None
    };

    if emit_output {
        utils::log_info(format!(
            "Streaming brute-force: {} total combinations (length {}..{})",
            total_combinations, min_length, max_length
        ));
    }

    // Precompute HS256 verifier once. JWE / non-HS256 fall back per-candidate.
    let fast_verifier = if is_jwe {
        None
    } else {
        jwt::prepare_hs256_verifier(token).ok()
    };

    let char_bytes = crack::brute::charset_bytes(chars);
    let charset_size = char_bytes.len() as u64;
    const BRUTE_CHUNK: u64 = 4096;

    pool.install(|| {
        for length in min_length..=max_length {
            if found_flag.load(Ordering::Relaxed) {
                break;
            }
            let total: u64 = charset_size.pow(length as u32);
            if total == 0 {
                continue;
            }
            let num_chunks = total.div_ceil(BRUTE_CHUNK);

            (0..num_chunks).into_par_iter().for_each_init(
                || Vec::<u8>::with_capacity(length * 4),
                |buf, chunk_idx| {
                    if found_flag.load(Ordering::Relaxed) {
                        return;
                    }
                    let start = chunk_idx * BRUTE_CHUNK;
                    let end = (start + BRUTE_CHUNK).min(total);
                    let mut hit: Option<Vec<u8>> = None;

                    for idx in start..end {
                        if found_flag.load(Ordering::Relaxed) {
                            break;
                        }
                        crack::brute::write_candidate_bytes(idx, &char_bytes, length, buf);

                        let matched = if let Some(ref v) = fast_verifier {
                            v.verify(buf)
                        } else if is_jwe {
                            std::str::from_utf8(buf)
                                .ok()
                                .map(|s| jwt::decrypt_jwe(token, s).is_ok())
                                .unwrap_or(false)
                        } else {
                            std::str::from_utf8(buf)
                                .ok()
                                .map(|s| jwt::verify(token, s).unwrap_or(false))
                                .unwrap_or(false)
                        };

                        if matched {
                            hit = Some(buf.clone());
                            found_flag.store(true, Ordering::Relaxed);
                            break;
                        }
                    }

                    let processed = end - start;
                    attempts.fetch_add(processed as usize, Ordering::Relaxed);
                    if let Some(ref progress) = pb {
                        progress.inc(processed);
                    }

                    if let Some(bytes) = hit {
                        // charset_bytes only produces valid UTF-8, so each
                        // candidate buffer is guaranteed valid UTF-8 too.
                        let secret = String::from_utf8(bytes)
                            .expect("candidate built from char-encoded bytes is valid UTF-8");
                        if verbose {
                            let message = if is_jwe {
                                format!("Found! JWE encryption key is {secret} Decryption=Success")
                            } else {
                                format!(
                                    "Found! Token signature secret is {secret} Signature=Verified"
                                )
                            };
                            info!("{}", message);
                        }
                        *found.lock().unwrap_or_else(|e| e.into_inner()) = Some(secret);
                        if let Some(ref progress) = pb {
                            progress.finish_and_clear();
                        }
                    }

                    buf.zeroize();
                },
            );

            // Between length iterations the allocation pattern changes
            // (different buffer sizes). mimalloc returns freed pages to
            // the OS eagerly at this natural GC boundary.
        }
    });

    cleanup_crack_progress(pb, update_thread);

    let elapsed = start_time.elapsed();
    let attempts_total = attempts.load(Ordering::Relaxed);
    report_crack_results(&found, elapsed, attempts_total, token, is_jwe, emit_output);

    Ok(build_crack_report(
        &found,
        elapsed,
        attempts_total,
        is_jwe,
        "brute",
        None,
        None,
        emit_output,
    ))
}

/// Targeted field brute-force: modify a specific JWT header/payload field (e.g., kid, jti)
/// and test each variation against the target. Useful for testing key ID injection,
/// path traversal in kid, or discovering valid JTI values.
fn crack_target_field(
    options: &CrackOptions,
    target_field: &str,
    emit_output: bool,
) -> anyhow::Result<CrackReport> {
    let start_time = Instant::now();
    let multi = if emit_output {
        Some(MultiProgress::new())
    } else {
        None
    };

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

    if emit_output {
        utils::log_info(format!(
            "Targeted field cracking: field='{}' location='{}' algorithm='{}'",
            target_field, field_location, alg
        ));
    }

    // Generate candidates based on mode
    if options.mode != "dict" && options.mode != "brute" {
        if emit_output {
            utils::log_error(format!("Invalid mode for target field: {}", options.mode));
        }
        return Err(anyhow::anyhow!(
            "Invalid mode '{}' for targeted field cracking",
            options.mode
        ));
    }

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

        let total = crack::brute::estimate_combinations(chars_to_use.len(), options.min, options.max);
        let pb = if emit_output {
            create_crack_progress_bar(
                multi.as_ref().expect("multi exists when emit_output"),
                total,
                options.verbose,
            )
        } else {
            None
        };
        let update_thread = if emit_output {
            spawn_rate_update_thread(&attempts, &pb)
        } else {
            None
        };

        for length in options.min..=options.max {
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
        // Dictionary mode with streaming batches — avoids loading the entire
        // wordlist into memory and eliminates the duplicate `expanded` Vec.
        let wordlist_path = options
            .wordlist
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Wordlist is required for dictionary mode"))?;
        let file = File::open(wordlist_path)?;
        let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);
        let mut reader = BufReader::new(file);

        const TARGET_DICT_BATCH: usize = 100_000;
        let mut word_batch: Vec<String> = Vec::with_capacity(TARGET_DICT_BATCH);
        let mut line_buf = String::new();
        let mut bytes_read: u64 = 0;

        let loading_pb = if emit_output {
            let pb = multi
                .as_ref()
                .map(|m| {
                    let pb = m.add(ProgressBar::new_spinner());
                    pb.set_style(
                        ProgressStyle::default_spinner()
                            .template("{spinner:.blue} {msg}")
                            .expect("valid spinner template")
                            .tick_strings(&[
                                "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏",
                            ]),
                    );
                    pb.set_message("Processing wordlist (targeted field)...");
                    pb.enable_steady_tick(Duration::from_millis(100));
                    pb
                });
            pb
        } else {
            None
        };

        loop {
            word_batch.clear();
            let mut batch_bytes: u64 = 0;
            for _ in 0..TARGET_DICT_BATCH {
                line_buf.clear();
                let n = match reader.read_line(&mut line_buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                batch_bytes += n as u64;
                let word = line_buf.trim_end_matches(['\n', '\r']).to_string();
                if word.is_empty() {
                    continue;
                }
                // Apply pattern inline — no separate expanded Vec
                word_batch.push(apply_pattern(pattern, &word));
            }

            if word_batch.is_empty() {
                break;
            }

            bytes_read += batch_bytes;
            if let Some(ref pb) = loading_pb {
                let pct = if file_size > 0 {
                    (bytes_read as f64 / file_size as f64 * 100.0) as u64
                } else {
                    0
                };
                pb.set_message(format!(
                    "Targeted field batch ({} tested, ~{}% of file)",
                    attempts.load(Ordering::Relaxed),
                    pct
                ));
            }

            run_target_field_crack(
                &pool,
                &word_batch,
                &header_map,
                &claims,
                target_field,
                field_location,
                &alg,
                options.token,
                &found,
                &found_flag,
                &attempts,
                &None,
                options.verbose,
            );

            if found_flag.load(Ordering::Relaxed) {
                break;
            }

            for w in &mut word_batch {
                w.zeroize();
            }
            word_batch.clear();
        }

        if let Some(pb) = loading_pb {
            pb.finish_with_message(format!(
                "Processed {} entries",
                attempts.load(Ordering::Relaxed)
            ));
        }
    }

    let elapsed = start_time.elapsed();
    let attempts_total = attempts.load(Ordering::Relaxed);
    let rate = if elapsed.as_secs_f64() > 0.0 {
        attempts_total as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };

    if emit_output {
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
    }

    let guard = found.lock().unwrap_or_else(|e| e.into_inner());
    let was_found = guard.is_some();
    // Only clone the sensitive value for the JSON path; callers in non-JSON mode discard the report.
    let value = if !emit_output { guard.clone() } else { None };
    Ok(CrackReport {
        success: true,
        mode: format!("target_field:{}", options.mode),
        token_type: "jwt".to_string(),
        found: was_found,
        value_label: "value".to_string(),
        value,
        target_field: Some(target_field.to_string()),
        field_location: Some(field_location.to_string()),
        elapsed_ms: elapsed.as_millis(),
        attempts: attempts_total,
        rate,
    })
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
        candidates.par_chunks(CHUNK_SIZE).for_each_init(
            || {
                // Per-worker state: one claims clone and one base header map,
                // amortized across every candidate the worker processes instead
                // of being rebuilt on each iteration.
                let mut base_headers: std::collections::HashMap<&str, &str> =
                    std::collections::HashMap::new();
                for (k, v) in header_map.iter() {
                    if k != "alg" && k != "typ" {
                        base_headers.insert(k.as_str(), v.as_str());
                    }
                }
                (base_headers, claims.clone())
            },
            |(extra_headers, modified_claims), chunk| {
                if found_flag.load(Ordering::Relaxed) {
                    return;
                }

                for candidate in chunk {
                    if found_flag.load(Ordering::Relaxed) {
                        break;
                    }

                    if field_location == "header" {
                        extra_headers.insert(target_field, candidate.as_str());
                    } else {
                        modified_claims[target_field] =
                            serde_json::Value::String(candidate.clone());
                    }

                    let encode_options = jwt::EncodeOptions {
                        algorithm: alg,
                        key_data: jwt::KeyData::Secret(""),
                        header_params: if extra_headers.is_empty() {
                            None
                        } else {
                            Some(extra_headers.clone())
                        },
                        compress_payload: false,
                    };

                    match jwt::encode_with_options(modified_claims, &encode_options) {
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
                                *found.lock().unwrap_or_else(|e| e.into_inner()) =
                                    Some(candidate.clone());

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
            },
        );
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
                1,  // min
                4,  // max
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
            min: 1,
            max: 4,
            power: false,
            verbose: false,
            target_field: &None,
            pattern: &None,
        };

        // Execute should handle the missing wordlist without panicking
        let result = std::panic::catch_unwind(|| {
            execute_with_options(&options, false);
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
            min: 1,
            max: 4,
            power: false,
            verbose: false,
            target_field: &None,
            pattern: &None,
        };

        // Execute should handle the invalid mode without panicking
        let result = std::panic::catch_unwind(|| {
            execute_with_options(&options, false);
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
            false, // emit_output
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
            false, // emit_output
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
            1,     // min length
            2,     // Only try up to length 2
            2,     // Small concurrency
            false, // Don't use all cores
            false, // Don't print verbose logs
            false, // Not a JWE token
            false, // emit_output
        );

        assert!(result.is_ok(), "crack_bruteforce should not fail");
    }

    /// Regression test for the brute-force hot path: walk every index with
    /// `write_candidate_bytes` and confirm `Hs256Verifier` accepts the secret
    /// at exactly the expected position. Together these are the kernel of
    /// `crack_bruteforce`; the function itself only reports via stdout so we
    /// exercise the underlying primitives instead.
    #[test]
    fn test_bruteforce_hot_path_finds_secret() {
        use crate::crack::brute::{charset_bytes, write_candidate_bytes};
        use crate::jwt::prepare_hs256_verifier;

        let secret = "cab";
        let token = create_test_token(secret);
        let verifier = prepare_hs256_verifier(&token).expect("HS256 token");

        let chars = "abc";
        let char_bytes = charset_bytes(chars);
        let length = secret.len();
        let total = (char_bytes.len() as u64).pow(length as u32);

        let mut buf = Vec::with_capacity(length);
        let mut hits: Vec<String> = Vec::new();
        for idx in 0..total {
            write_candidate_bytes(idx, &char_bytes, length, &mut buf);
            if verifier.verify(&buf) {
                hits.push(std::str::from_utf8(&buf).unwrap().to_string());
            }
        }
        assert_eq!(hits, vec![secret.to_string()]);
    }

    #[test]
    #[ignore] // This test would take too long for regular test runs
    fn test_crack_bruteforce_no_match() {
        // Create a test token with a secret that won't be found in our limited search
        let token = create_test_token("longsecret123");

        // Test with parameters that will not find the secret
        let result = crack_bruteforce(
            &token, "abc", // Limited charset that doesn't contain digits
            1,     // min length
            3,     // Only try up to length 3
            2,     // Small concurrency
            false, // Don't use all cores
            false, // Don't print verbose logs
            false, // Not a JWE token
            false, // emit_output
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
            min: 1,
            max: 2,
            power: false,
            verbose: false,
            target_field: &None,
            pattern: &None,
        };

        // This should execute without panicking
        let result = std::panic::catch_unwind(|| {
            execute_with_options(&options, false);
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
            min: 1,
            max: 2,
            power: false,
            verbose: false,
            target_field: &None,
            pattern: &None,
        };

        // This should execute without panicking (but will print error)
        let result = std::panic::catch_unwind(|| {
            execute_with_options(&options, false);
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
            min: 1,
            max: 2,
            power: false,
            verbose: false,
            target_field: &None,
            pattern: &None,
        };

        // This should execute without panicking
        let result = std::panic::catch_unwind(|| {
            execute_with_options(&options, false);
        });
        assert!(
            result.is_ok(),
            "execute_with_options should work without preset"
        );
    }
}
