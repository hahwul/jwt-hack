//! Downloadable, cacheable wordlist presets for dictionary cracking.
//!
//! `jwt-hack crack -p <id>` (a.k.a. `--wordlist-preset <id>`) resolves a numeric
//! preset to a well-known wordlist, downloading it into the tool's config
//! directory on first use. Subsequent runs reuse the cached copy: a checksum
//! sidecar is written alongside each download so an existing file with a
//! matching hash is served straight from disk instead of being re-downloaded.

use anyhow::{anyhow, Context, Result};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::Config;

/// A downloadable wordlist identified by a numeric preset id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WordlistPreset {
    /// Numeric id used on the command line (`-p <id>`).
    pub id: u32,
    /// Short, filesystem-friendly name (also the cached file stem).
    pub name: &'static str,
    /// Remote URL the wordlist is downloaded from.
    pub url: &'static str,
    /// Human-readable description shown in help/errors.
    pub description: &'static str,
}

/// Built-in wordlist presets. `jwt-hack crack -p <id>` downloads and caches these.
pub const PRESETS: &[WordlistPreset] = &[
    WordlistPreset {
        id: 1,
        name: "raft-medium-words",
        url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-words.txt",
        description: "SecLists raft-medium-words (medium web-content wordlist)",
    },
    WordlistPreset {
        id: 2,
        name: "raft-large-words",
        url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-words.txt",
        description: "SecLists raft-large-words (large web-content wordlist)",
    },
    WordlistPreset {
        id: 3,
        name: "jwt-secrets",
        url: "https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list",
        description: "Wallarm jwt-secrets (common JWT signing secrets)",
    },
];

/// Look up a preset by its numeric id.
pub fn get_preset(id: u32) -> Option<&'static WordlistPreset> {
    PRESETS.iter().find(|p| p.id == id)
}

/// Human-readable list of available presets for help/error messages.
pub fn preset_list_string() -> String {
    PRESETS
        .iter()
        .map(|p| format!("  {} = {} ({})", p.id, p.name, p.description))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Directory where downloaded preset wordlists are cached
/// (`<config dir>/wordlists`).
pub fn cache_dir() -> Option<PathBuf> {
    Config::default_config_dir().map(|d| d.join("wordlists"))
}

/// Lowercase hex SHA-256 digest of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = hmac_sha256::Hash::hash(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        // Writing to a String is infallible.
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Path of the cached wordlist file for a preset.
fn wordlist_file(dir: &Path, preset: &WordlistPreset) -> PathBuf {
    dir.join(format!("{}.txt", preset.name))
}

/// Path of the checksum sidecar for a preset's cached wordlist.
fn sha_sidecar(dir: &Path, preset: &WordlistPreset) -> PathBuf {
    dir.join(format!("{}.txt.sha256", preset.name))
}

/// True when a cached copy exists whose contents hash matches the stored sidecar.
///
/// This is what lets us "skip downloading a file with the same hash": the sidecar
/// records the hash of the bytes we last wrote, and we only trust the cache when
/// the file still hashes to that value (guarding against truncated/edited files).
fn cached_and_valid(dir: &Path, preset: &WordlistPreset) -> bool {
    let file = wordlist_file(dir, preset);
    let sidecar = sha_sidecar(dir, preset);
    let (Ok(content), Ok(expected)) = (fs::read(&file), fs::read_to_string(&sidecar)) else {
        return false;
    };
    !content.is_empty() && sha256_hex(&content) == expected.trim()
}

/// Resolve a preset wordlist into a local path, using `dir` as the cache and
/// `download` to fetch bytes when a valid cached copy is not present.
///
/// This is the testable core of [`ensure_wordlist`]: callers inject the cache
/// directory and the network fetch so the caching / integrity logic can be
/// exercised without touching the real config dir or the network.
pub fn ensure_wordlist_in<F>(preset: &WordlistPreset, dir: &Path, download: F) -> Result<PathBuf>
where
    F: FnOnce(&str) -> Result<Vec<u8>>,
{
    let file = wordlist_file(dir, preset);

    // A byte-identical cached copy already exists -> skip the download entirely.
    if cached_and_valid(dir, preset) {
        return Ok(file);
    }

    fs::create_dir_all(dir)
        .with_context(|| format!("Failed to create wordlist cache dir: {}", dir.display()))?;

    let bytes = download(preset.url)
        .with_context(|| format!("Failed to download preset wordlist from {}", preset.url))?;
    if bytes.is_empty() {
        return Err(anyhow!("downloaded wordlist '{}' is empty", preset.name));
    }

    fs::write(&file, &bytes)
        .with_context(|| format!("Failed to write wordlist file: {}", file.display()))?;
    fs::write(sha_sidecar(dir, preset), sha256_hex(&bytes))
        .context("Failed to write wordlist checksum sidecar")?;

    Ok(file)
}

/// Blocking HTTP(S) download used by the real [`ensure_wordlist`] path.
fn http_download(url: &str) -> Result<Vec<u8>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()?;
    let response = client
        .get(url)
        .header(
            "User-Agent",
            concat!("jwt-hack/", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .map_err(|e| anyhow!("request to {url} failed: {e}"))?;
    if !response.status().is_success() {
        return Err(anyhow!(
            "download from {url} returned status {}",
            response.status()
        ));
    }
    Ok(response.bytes()?.to_vec())
}

/// Resolve a numeric preset id into a local wordlist path, downloading and
/// caching it under the config directory on first use.
pub fn ensure_wordlist(id: u32) -> Result<PathBuf> {
    let preset = get_preset(id).ok_or_else(|| {
        anyhow!(
            "unknown wordlist preset '{id}'. Available presets:\n{}",
            preset_list_string()
        )
    })?;
    let dir = cache_dir()
        .ok_or_else(|| anyhow!("could not determine a config directory for the wordlist cache"))?;

    let file = wordlist_file(&dir, preset);
    if cached_and_valid(&dir, preset) {
        crate::utils::log_info(format!(
            "Using cached preset wordlist '{}' ({})",
            preset.name,
            file.display()
        ));
        return Ok(file);
    }

    crate::utils::log_info(format!(
        "Downloading preset wordlist '{}' from {}",
        preset.name, preset.url
    ));
    let path = ensure_wordlist_in(preset, &dir, http_download)?;
    crate::utils::log_success(format!(
        "Preset wordlist '{}' ready ({})",
        preset.name,
        path.display()
    ));
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use tempfile::TempDir;

    #[test]
    fn test_get_preset_known_and_unknown() {
        assert_eq!(get_preset(1).unwrap().name, "raft-medium-words");
        assert_eq!(get_preset(2).unwrap().name, "raft-large-words");
        assert_eq!(get_preset(3).unwrap().name, "jwt-secrets");
        assert!(get_preset(0).is_none());
        assert!(get_preset(999).is_none());
    }

    #[test]
    fn test_preset_ids_are_unique() {
        let mut ids: Vec<u32> = PRESETS.iter().map(|p| p.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), PRESETS.len(), "preset ids must be unique");
    }

    #[test]
    fn test_preset_list_string_mentions_all() {
        let list = preset_list_string();
        for p in PRESETS {
            assert!(list.contains(p.name), "list should mention {}", p.name);
        }
    }

    #[test]
    fn test_sha256_hex_known_vector() {
        // Empty input has a well-known SHA-256 digest.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_ensure_wordlist_downloads_then_caches() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("wordlists");
        let preset = get_preset(1).unwrap();

        let calls = Cell::new(0);
        let downloader = |_url: &str| -> Result<Vec<u8>> {
            calls.set(calls.get() + 1);
            Ok(b"secret\npassword\nletmein\n".to_vec())
        };

        // First call downloads and writes the cache + sidecar.
        let path = ensure_wordlist_in(preset, &dir, downloader).unwrap();
        assert!(path.exists());
        assert_eq!(calls.get(), 1);
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("letmein"));
        assert!(sha_sidecar(&dir, preset).exists());

        // Second call reuses the cache and does NOT invoke the downloader.
        let path2 = ensure_wordlist_in(preset, &dir, |_url| {
            calls.set(calls.get() + 1);
            Ok(b"SHOULD-NOT-BE-CALLED".to_vec())
        })
        .unwrap();
        assert_eq!(path, path2);
        assert_eq!(calls.get(), 1, "cached copy must skip re-download");
    }

    #[test]
    fn test_ensure_wordlist_redownloads_on_hash_mismatch() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("wordlists");
        let preset = get_preset(2).unwrap();

        // Seed a cache file whose contents do not match its sidecar hash.
        fs::create_dir_all(&dir).unwrap();
        fs::write(wordlist_file(&dir, preset), b"stale-content").unwrap();
        fs::write(sha_sidecar(&dir, preset), sha256_hex(b"different")).unwrap();
        assert!(!cached_and_valid(&dir, preset));

        let downloaded = Cell::new(false);
        let path = ensure_wordlist_in(preset, &dir, |_url| {
            downloaded.set(true);
            Ok(b"fresh\ncontent\n".to_vec())
        })
        .unwrap();

        assert!(downloaded.get(), "hash mismatch must force a re-download");
        assert_eq!(fs::read_to_string(&path).unwrap(), "fresh\ncontent\n");
        assert!(cached_and_valid(&dir, preset));
    }

    #[test]
    fn test_ensure_wordlist_rejects_empty_download() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("wordlists");
        let preset = get_preset(1).unwrap();

        let result = ensure_wordlist_in(preset, &dir, |_url| Ok(Vec::new()));
        assert!(result.is_err(), "empty downloads should be rejected");
    }

    #[test]
    fn test_ensure_wordlist_propagates_download_error() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("wordlists");
        let preset = get_preset(1).unwrap();

        let result = ensure_wordlist_in(preset, &dir, |_url| Err(anyhow!("network down")));
        assert!(result.is_err());
        // Nothing should have been cached.
        assert!(!wordlist_file(&dir, preset).exists());
    }

    #[test]
    fn test_ensure_wordlist_unknown_id_errors() {
        let err = ensure_wordlist(9999).unwrap_err().to_string();
        assert!(err.contains("unknown wordlist preset"));
    }
}
