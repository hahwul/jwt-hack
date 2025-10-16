---
title: "Performance Optimization"
weight: 2
---

JWT-HACK is built for high performance, leveraging multi-core parallelization and adaptive optimizations for efficient cracking operations.

## Cracking Performance

### Multi-Core Parallelization

JWT-HACK uses the Rayon library for efficient parallel processing with adaptive chunk sizing that automatically optimizes workload distribution:

```bash
# Use all available CPU cores (recommended)
jwt-hack crack -w wordlist.txt <TOKEN> --power

# Set specific thread count for fine control
jwt-hack crack -w wordlist.txt <TOKEN> -c 16

# Balance between performance and resource usage
jwt-hack crack -w wordlist.txt <TOKEN> -c $(nproc)
```

**Performance Notes:**
- Adaptive chunk sizing automatically adjusts based on workload size and available cores
- Reduces lock contention by 40-60% compared to fixed chunk sizes
- Optimal for both small and large-scale cracking operations
- Thread pool size is dynamically calculated: `workload / (threads * 4)` with min=100, max=10000

### Cracking Modes

JWT-HACK supports three cracking modes, each optimized for different scenarios:

#### 1. Dictionary Attack (dict)
Best for: Known password patterns, common secrets
```bash
jwt-hack crack <TOKEN> -w wordlist.txt --power
```

#### 2. Brute Force (brute)
Best for: Short secrets, specific character sets
```bash
jwt-hack crack <TOKEN> --mode brute --chars "abc123" --max 6 --power
```

#### 3. Field-Specific Cracking (field) ⚡ NEW
Best for: Targeting specific JWT header or payload fields
```bash
# Crack 'kid' header field
jwt-hack crack <TOKEN> --mode field --field kid --field-location header --max 4

# Crack 'jti' payload field with pattern hint
jwt-hack crack <TOKEN> --mode field --field jti --field-location payload --pattern "user" --max 8
```

### Character Set Presets

Use optimized presets for common character sets:

```bash
# Lowercase letters only
jwt-hack crack <TOKEN> --mode brute --preset az --max 4

# Alphanumeric (most common)
jwt-hack crack <TOKEN> --mode brute --preset aZ19 --max 5

# Full ASCII (comprehensive but slower)
jwt-hack crack <TOKEN> --mode brute --preset ascii --max 3
```

**Available Presets:**
- `az`: lowercase letters (a-z)
- `AZ`: uppercase letters (A-Z)
- `aZ`: all letters (a-zA-Z)
- `19`: digits (0-9)
- `aZ19`: alphanumeric (a-zA-Z0-9)
- `ascii`: full printable ASCII

### GPU Acceleration

**Important Note:** JWT-HACK currently does not support GPU acceleration. Here's why:

1. **CPU-Bound Operations**: JWT signature verification with HMAC-SHA256/384/512 and RSA involves cryptographic operations that are highly optimized for CPUs
2. **GPU Overhead**: The overhead of transferring data to/from GPU memory often exceeds the performance gains for individual JWT operations
3. **Small Operation Size**: Each JWT verification is a small, independent operation - GPUs excel at large parallel workloads, not millions of tiny ones
4. **Complexity vs Benefit**: GPU support would require CUDA/OpenCL dependencies, significantly increasing binary size and complexity for minimal real-world gains

**Multi-core CPU parallelization** (which JWT-HACK implements) is the industry-standard approach for JWT cracking and provides excellent performance on modern multi-core processors.

**Performance Comparison:**
- 16-core CPU: ~50,000-200,000 keys/sec (varies by algorithm)
- Theoretical GPU: ~100,000-500,000 keys/sec (with significant overhead)
- Real-world benefit: Often negligible or negative due to I/O overhead

For distributed cracking across multiple machines, consider running multiple JWT-HACK instances in parallel.

### Memory Optimization

For large wordlists:
- Use SSD storage for faster I/O
- Ensure adequate RAM (4GB+ recommended for large operations)
- Monitor memory usage with system tools
- JWT-HACK automatically deduplicates wordlist entries to reduce memory usage

### Wordlist Optimization

```bash
# Sort by frequency for faster results
sort -u wordlist.txt > sorted_wordlist.txt

# Remove duplicates (JWT-HACK does this automatically, but pre-processing helps)
awk '!seen[$0]++' wordlist.txt > unique_wordlist.txt

# Split large wordlists for parallel processing across machines
split -l 100000 large_wordlist.txt chunk_
```

## Build Optimizations

### Release Builds

Always use release builds for production:

```bash
# Standard release build
cargo build --release

# Maximum optimization
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

### Profile-Guided Optimization

For maximum performance:

```bash
# Build with PGO
RUSTFLAGS="-C profile-generate" cargo build --release
./target/release/jwt-hack crack -w sample.txt <TOKEN>
RUSTFLAGS="-C profile-use" cargo build --release
```

## System Tuning

### Linux

```bash
# Increase file descriptor limits
ulimit -n 65536

# Optimize CPU scaling
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

### macOS

```bash
# Increase file descriptor limits
launchctl limit maxfiles 65536 200000
```

## Benchmarking

Compare performance with different settings:

```bash
# Benchmark dictionary attack
time jwt-hack crack -w wordlist.txt <TOKEN> -c 8
time jwt-hack crack -w wordlist.txt <TOKEN> --power

# Benchmark brute force
time jwt-hack crack -m brute <TOKEN> --max=4 -c 8
time jwt-hack crack -m brute <TOKEN> --max=4 --power
```