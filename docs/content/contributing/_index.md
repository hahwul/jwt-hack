+++
title = "Contributing"
weight = 10
+++

Thank you for your interest in contributing to JWT-HACK! This project welcomes contributions from the community.

## Getting Started

### Prerequisites

- Rust and Cargo installed (latest stable version recommended)
- Git
- Just task runner (optional but recommended)

### Development Setup

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/jwt-hack.git
   cd jwt-hack
   ```
3. Create a branch for your work:
   ```bash
   git checkout -b features/your-feature-name
   # or
   git checkout -b bugfix/issue-description
   ```

### Building and Testing

Install Just task runner for easier development:
```bash
cargo install just
```

Development workflow:
```bash
# Build for development (takes ~75s first time, ~18s subsequent)
just dev

# Run all tests (takes ~17s)
just test

# Format and fix linting issues
just fix

# Clean build
cargo clean && just dev
```

## Code Guidelines

### Rust Code Style

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `cargo fmt` to format your code before committing
- Run `cargo clippy` and address any warnings
- Write comprehensive tests for new functionality

### Commit Messages

- Use clear, concise commit messages
- Start with a verb in the present tense (e.g., "Add feature" not "Added feature")
- Reference issue numbers when applicable (e.g., "Fix #123: Memory leak in URL parser")

### Testing Requirements

All contributions must include appropriate tests:

```bash
# Unit tests
cargo test

# Integration tests
cargo test --test integration

# Linting
cargo clippy -- --deny warnings

# Formatting check
cargo fmt --check
```

## Pull Request Process

### Before Submitting

1. Ensure your code builds without errors:
   ```bash
   just dev
   ```

2. Run the full test suite:
   ```bash
   just test
   ```

3. Update documentation if needed

4. Verify functionality with manual testing:
   ```bash
   ./target/debug/jwt-hack --help
   ./target/debug/jwt-hack decode <test-token>
   ```

For more detailed contributing guidelines, please see the [full CONTRIBUTING.md](https://github.com/hahwul/jwt-hack/blob/main/CONTRIBUTING.md) in the repository.
