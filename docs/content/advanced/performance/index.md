---
title: "Performance Optimization"
weight: 2
---

JWT-HACK is built for high performance, but you can optimize it further for your specific use cases.

## Cracking Performance

### Thread Configuration

```bash
# Use all available CPU cores
jwt-hack crack -w wordlist.txt <TOKEN> --power

# Set specific thread count
jwt-hack crack -w wordlist.txt <TOKEN> -c 16

# Balance between performance and resource usage
jwt-hack crack -w wordlist.txt <TOKEN> -c $(nproc)
```

### Memory Optimization

For large wordlists:
- Use SSD storage for faster I/O
- Ensure adequate RAM (4GB+ recommended for large operations)
- Monitor memory usage with system tools

### Wordlist Optimization

```bash
# Sort by frequency for faster results
sort -u wordlist.txt > sorted_wordlist.txt

# Remove duplicates to reduce processing time
awk '!seen[$0]++' wordlist.txt > unique_wordlist.txt

# Split large wordlists for parallel processing
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