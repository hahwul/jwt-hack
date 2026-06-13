use anyhow::{anyhow, Result};
use flate2::read::{DeflateDecoder, DeflateEncoder};
use flate2::Compression;
use std::io::Read;

/// Compresses data using DEFLATE compression algorithm
pub fn compress_deflate(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = DeflateEncoder::new(data, Compression::default());
    let mut compressed = Vec::new();
    encoder
        .read_to_end(&mut compressed)
        .map_err(|e| anyhow!("Failed to compress data: {}", e))?;
    Ok(compressed)
}

/// Maximum number of bytes produced when decompressing an untrusted DEFLATE stream.
///
/// DEFLATE can amplify input by more than 1000x, so an unbounded `read_to_end` on
/// attacker-controlled data is a decompression-bomb / memory-exhaustion vector. The
/// `zip:"DEF"` payload of any token reaching `jwt::decode` is fully attacker-controlled
/// (including over the REST server), so the decompressed size must be capped.
pub const MAX_DECOMPRESSED_SIZE: u64 = 10 * 1024 * 1024; // 10 MiB

/// Decompresses data using DEFLATE decompression algorithm.
///
/// The decompressed output is capped at [`MAX_DECOMPRESSED_SIZE`]; input that would
/// expand beyond that limit is rejected with an error instead of being buffered, to
/// prevent decompression-bomb denial of service from untrusted tokens.
pub fn decompress_deflate(compressed_data: &[u8]) -> Result<Vec<u8>> {
    let mut limited = DeflateDecoder::new(compressed_data).take(MAX_DECOMPRESSED_SIZE + 1);
    let mut decompressed = Vec::new();
    limited
        .read_to_end(&mut decompressed)
        .map_err(|e| anyhow!("Failed to decompress data: {}", e))?;
    if decompressed.len() as u64 > MAX_DECOMPRESSED_SIZE {
        return Err(anyhow!(
            "Decompressed payload exceeds maximum allowed size of {} bytes",
            MAX_DECOMPRESSED_SIZE
        ));
    }
    Ok(decompressed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress_round_trip() {
        let original_data = b"Hello, World! This is a test string for compression. This needs to be long enough to actually compress well. Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";

        // Compress the data
        let compressed = compress_deflate(original_data).expect("Failed to compress data");

        // Decompress the data
        let decompressed = decompress_deflate(&compressed).expect("Failed to decompress data");

        // Verify round-trip integrity
        assert_eq!(original_data, decompressed.as_slice());
    }

    #[test]
    fn test_compress_empty_data() {
        let empty_data = b"";
        let compressed = compress_deflate(empty_data).expect("Failed to compress empty data");
        let decompressed =
            decompress_deflate(&compressed).expect("Failed to decompress empty data");
        assert_eq!(empty_data, decompressed.as_slice());
    }

    #[test]
    fn test_compress_small_data() {
        let small_data = b"a";
        let compressed = compress_deflate(small_data).expect("Failed to compress small data");
        let decompressed =
            decompress_deflate(&compressed).expect("Failed to decompress small data");
        assert_eq!(small_data, decompressed.as_slice());
    }

    #[test]
    fn test_decompress_invalid_data() {
        let invalid_data = b"this is not compressed data";
        let result = decompress_deflate(invalid_data);
        assert!(result.is_err(), "Decompressing invalid data should fail");
    }

    #[test]
    fn test_decompress_bomb_is_capped() {
        // A highly compressible input that expands past the cap must be rejected
        // rather than buffered into memory.
        let bomb_size = (MAX_DECOMPRESSED_SIZE as usize) + 1024;
        let compressed = compress_deflate(&vec![0u8; bomb_size]).expect("compress");
        assert!(
            compressed.len() < bomb_size,
            "expected the bomb input to actually compress"
        );
        let result = decompress_deflate(&compressed);
        assert!(
            result.is_err(),
            "decompression past the cap must error, got {} bytes",
            result.map(|v| v.len()).unwrap_or(0)
        );
    }

    #[test]
    fn test_compress_json_payload() {
        let json_payload =
            br#"{"sub":"1234567890","name":"John Doe","iat":1516239022,"exp":1516239922}"#;

        let compressed = compress_deflate(json_payload).expect("Failed to compress JSON payload");
        let decompressed =
            decompress_deflate(&compressed).expect("Failed to decompress JSON payload");

        assert_eq!(json_payload, decompressed.as_slice());
    }
}
