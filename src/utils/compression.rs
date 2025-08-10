use anyhow::{anyhow, Result};
use flate2::read::{DeflateDecoder, DeflateEncoder};
use flate2::Compression;
use std::io::Read;

/// Compresses data using DEFLATE compression algorithm
pub fn compress_deflate(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = DeflateEncoder::new(data, Compression::default());
    let mut compressed = Vec::new();
    encoder.read_to_end(&mut compressed)
        .map_err(|e| anyhow!("Failed to compress data: {}", e))?;
    Ok(compressed)
}

/// Decompresses data using DEFLATE decompression algorithm
pub fn decompress_deflate(compressed_data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = DeflateDecoder::new(compressed_data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)
        .map_err(|e| anyhow!("Failed to decompress data: {}", e))?;
    Ok(decompressed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress_round_trip() {
        let original_data = b"Hello, World! This is a test string for compression. This needs to be long enough to actually compress well. Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";
        
        // Compress the data
        let compressed = compress_deflate(original_data)
            .expect("Failed to compress data");
        
        // Decompress the data
        let decompressed = decompress_deflate(&compressed)
            .expect("Failed to decompress data");
        
        // Verify round-trip integrity
        assert_eq!(original_data, decompressed.as_slice());
    }

    #[test]
    fn test_compress_empty_data() {
        let empty_data = b"";
        let compressed = compress_deflate(empty_data)
            .expect("Failed to compress empty data");
        let decompressed = decompress_deflate(&compressed)
            .expect("Failed to decompress empty data");
        assert_eq!(empty_data, decompressed.as_slice());
    }

    #[test]
    fn test_compress_small_data() {
        let small_data = b"a";
        let compressed = compress_deflate(small_data)
            .expect("Failed to compress small data");
        let decompressed = decompress_deflate(&compressed)
            .expect("Failed to decompress small data");
        assert_eq!(small_data, decompressed.as_slice());
    }

    #[test]
    fn test_decompress_invalid_data() {
        let invalid_data = b"this is not compressed data";
        let result = decompress_deflate(invalid_data);
        assert!(result.is_err(), "Decompressing invalid data should fail");
    }

    #[test]
    fn test_compress_json_payload() {
        let json_payload = br#"{"sub":"1234567890","name":"John Doe","iat":1516239022,"exp":1516239922}"#;
        
        let compressed = compress_deflate(json_payload)
            .expect("Failed to compress JSON payload");
        let decompressed = decompress_deflate(&compressed)
            .expect("Failed to decompress JSON payload");
        
        assert_eq!(json_payload, decompressed.as_slice());
    }
}