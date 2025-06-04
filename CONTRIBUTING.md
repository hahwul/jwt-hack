# Contributing to jwt-hack

Thank you for your interest in contributing to jwt-hack! This document provides guidelines and instructions for contributing to this project.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started

### Prerequisites

- Rust and Cargo installed (latest stable version recommended)
- Git

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

To build the project:
```bash
cargo build
```

To run tests:
```bash
cargo test
```

## Git Branch Strategy

We use a straightforward branching strategy where feature and bugfix branches are merged directly into the main branch:

- `features/feature-name` → `main`: For new features and enhancements
- `bugfix/issue-description` → `main`: For bug fixes

Please follow this naming convention for your branches to make the purpose of your contribution clear.

## Pull Request Process

1. **Create your pull request**:
   - Ensure your code builds without errors
   - Make sure all tests pass
   - Update documentation if needed
   - Include clear and concise commit messages
   - Reference any related issues with `#issue-number`

2. **PR Description**:
   - Provide a clear description of the changes
   - Include the motivation for the change
   - Describe any potential side effects or areas that might be affected
   - Add screenshots if your change affects the UI

3. **Code Review**:
   - The maintainers will review your code
   - Be responsive to feedback and make necessary changes
   - Your PR will be merged once it meets the project standards

## Style Guidelines

### Rust Code Style

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `cargo fmt` to format your code before committing
- Run `cargo clippy` and address any warnings

### Commit Messages

- Use clear, concise commit messages
- Start with a verb in the present tense (e.g., "Add feature" not "Added feature")
- Reference issue numbers when applicable (e.g., "Fix #123: Memory leak in URL parser")

## Documentation

- Update the README.md if you add or change functionality
- Add comments to your code where necessary
- Document any new public APIs

## Feature Requests and Bug Reports

- Use GitHub Issues to submit feature requests and bug reports
- Clearly describe the issue or feature
- For bugs, include steps to reproduce, expected behavior, and actual behavior
- If possible, provide a minimal code example that demonstrates the issue

## License

By contributing to jwt-hack, you agree that your contributions will be licensed under the same [MIT License](LICENSE) that covers the project.

---

Thank you for contributing to jwt-hack! Your efforts help make this tool better for everyone.
