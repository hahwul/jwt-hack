# JWT-HACK Development Instructions

JWT-HACK is a high-performance Rust-based JSON Web Token security testing toolkit. It provides JWT encoding, decoding, verification, cracking, and attack payload generation capabilities.

Always reference these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.

## Working Effectively

### Prerequisites and Setup
- Install Rust and Cargo (latest stable version recommended):
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  source ~/.cargo/env
  ```
- Install Just task runner:
  ```bash
  cargo install just
  ```

### Build Commands
- **CRITICAL**: Set timeouts to 120+ seconds for all build commands. NEVER CANCEL builds.
- Development build: `just dev` or `cargo build` -- takes 75 seconds on first build with dependencies, 18 seconds on subsequent builds. NEVER CANCEL. Set timeout to 120+ seconds.
- Release build: `just build` or `cargo build --release` -- takes 47 seconds. NEVER CANCEL. Set timeout to 90+ seconds.
- Quick check (no build): `cargo check` -- takes 15 seconds. Good for fast compilation verification.
- Clean build: `cargo clean` followed by build commands.
- Quick recompile after changes: `cargo build` -- takes 3-5 seconds for incremental builds.

### Testing
- Run full test suite: `just test` -- takes 17 seconds. NEVER CANCEL. Set timeout to 60+ seconds.
- This runs: `cargo test`, `cargo clippy`, `cargo fmt --check`, and `cargo doc`
- Unit tests only: `cargo test` -- takes 3-5 seconds.
- Lint only: `cargo clippy -- --deny warnings`
- Format check: `cargo fmt --check`
- Format code: `just fix` or `cargo fmt`

### Development Tasks
- List available Just commands: `just --list`
- Format and fix linting: `just fix`
- Build documentation: `cargo doc --workspace --all-features --no-deps --document-private-items`

## Validation Scenarios

### CRITICAL: Always run these validation steps after making changes:

1. **Build and Test Validation**:
   ```bash
   just dev && just test
   ```

2. **Core Functionality Testing**:
   ```bash
   # Test decoding (should display header/payload breakdown with algorithm and timestamps)
   ./target/debug/jwt-hack decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA
   
   # Test encoding (should create valid JWT with spinner animation)
   ./target/debug/jwt-hack encode '{"sub":"1234", "name":"test"}' --secret=mysecret
   
   # Test verification (should show validation result)
   ./target/debug/jwt-hack verify eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA --secret=test
   
   # Test dictionary cracking (should process 16 words with progress bar)
   ./target/debug/jwt-hack crack -w samples/wordlist.txt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.CHANGED
   
   # Test brute force cracking (should generate combinations with progress)
   ./target/debug/jwt-hack crack -m brute eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.CHANGED --max=2
   
   # Test payload generation (should create none algorithm attack payloads)
   ./target/debug/jwt-hack payload eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.CHANGED --target none
   
   # Test all payload types (should generate multiple attack vectors)
   ./target/debug/jwt-hack payload eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.CHANGED --jwk-attack example.com
   ```

3. **Help System Validation**:
   ```bash
   # Verify help displays correctly with banner
   ./target/debug/jwt-hack --help
   ./target/debug/jwt-hack decode --help
   ./target/debug/jwt-hack encode --help
   ```

### Pre-commit Validation
Always run these before committing changes or the CI (.github/workflows/ci.yml) will fail:
```bash
cargo fmt
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

## Project Structure

### Key Directories and Files
```
├── src/
│   ├── main.rs              # Application entry point
│   ├── cmd/                 # Command implementations
│   │   ├── decode.rs        # JWT decoding functionality
│   │   ├── encode.rs        # JWT encoding functionality
│   │   ├── verify.rs        # JWT verification functionality
│   │   ├── crack.rs         # JWT cracking (dict/brute force)
│   │   ├── payload.rs       # Attack payload generation
│   │   └── version.rs       # Version display
│   ├── jwt/                 # Core JWT operations
│   ├── crack/               # Cracking algorithms and utilities
│   ├── payload/             # Payload generation logic
│   ├── printing/            # Output formatting and logging
│   └── utils/               # Shared utilities
├── samples/                 # Test data
│   ├── jwt.txt             # Sample JWT token
│   └── wordlist.txt        # Sample wordlist for cracking
├── Cargo.toml              # Rust project configuration
├── justfile                # Task automation scripts
├── Dockerfile              # Container build definition
└── .github/workflows/      # CI/CD pipelines
```

### Configuration Files
- `Cargo.toml`: Dependencies, build configuration, binary definition
- `justfile`: Task automation (build, test, dev, fix commands)
- `.github/workflows/ci.yml`: CI pipeline (builds on Ubuntu/macOS/Windows)

## Common Development Patterns

### Adding New Commands
1. Create new module in `src/cmd/`
2. Add command struct with `clap` derives
3. Implement execute function
4. Add to `src/cmd/mod.rs` and main command enum
5. Add comprehensive unit tests
6. Update help documentation

### Modifying JWT Operations
- Core JWT logic is in `src/jwt/`
- Uses `jsonwebtoken` crate for cryptographic operations
- Always add tests for new algorithms or validation logic
- Test with various JWT formats and edge cases

### Performance Considerations
- Uses `rayon` for parallel processing in cracking operations
- Uses `indicatif` for progress bars on long-running operations
- Built with release optimizations: LTO, single codegen unit, stripped binaries

## Troubleshooting

### Build Issues
- **"cargo command not found"**: Install Rust toolchain with rustup
- **"just command not found"**: Install with `cargo install just`
- **Dependency resolution errors**: Delete `Cargo.lock` and rebuild
- **Compilation errors**: Ensure using latest stable Rust version

### Test Failures
- **Clippy warnings**: Run `cargo clippy --fix --allow-dirty` then manually review changes
- **Format failures**: Run `cargo fmt` to auto-fix formatting
- **Unit test failures**: Check if tests depend on specific sample data in `samples/`

### Runtime Issues
- **JWT parsing errors**: Verify JWT format (header.payload.signature structure)
- **Missing wordlist files**: Use relative paths from project root or absolute paths
- **Performance issues**: Use release build for large-scale operations

### Docker Build (Note: May fail in restricted environments)
```bash
# Docker build may fail due to network restrictions in sandboxed environments
docker build -t jwt-hack .
# If build fails, use local cargo builds instead
```

## CI/CD Information

The project uses GitHub Actions with the following jobs:
- **Build & Test**: Runs on Ubuntu, macOS, Windows with stable Rust
- **Lint**: Runs `cargo fmt --check` and `cargo clippy` with strict warnings
- **Coverage**: Generates code coverage reports using `cargo-llvm-cov`

All CI checks must pass before merging. The pipeline takes approximately 5-10 minutes to complete.

## Quick Reference

### Most Common Commands
```bash
# Development workflow
just dev                    # Build for development (75s first build, 18s subsequent, timeout 120s)
just test                   # Run all tests (17s, timeout 60s)
just fix                    # Format and fix linting

# Manual commands
cargo check                 # Fast compilation check (15s, timeout 30s)
cargo build                 # Development build
cargo build --release      # Production build (47s, timeout 90s)
cargo test                  # Unit tests only
cargo clippy               # Linting
cargo fmt                  # Code formatting

# Application testing
./target/debug/jwt-hack --help                    # Show help with banner
./target/debug/jwt-hack decode TOKEN              # Decode JWT (shows header/payload)
./target/debug/jwt-hack encode JSON --secret=KEY  # Encode JWT (creates new token)
./target/debug/jwt-hack verify TOKEN --secret=KEY # Verify JWT signature
./target/debug/jwt-hack crack -w FILE TOKEN       # Crack JWT with wordlist
./target/debug/jwt-hack crack -m brute TOKEN --max=N  # Brute force crack
./target/debug/jwt-hack payload TOKEN --target=TYPE   # Generate attack payloads
```

### File Patterns to Know
- Test files: `src/**/*test*.rs` or `#[cfg(test)]` modules
- Sample data: `samples/*.txt`
- Build artifacts: `target/` (excluded from git)
- Binary location: `target/debug/jwt-hack` or `target/release/jwt-hack`