# JWT-HACK Documentation

This directory contains the Zola-based documentation website for JWT-HACK.

## Structure

- `config.toml` - Zola site configuration
- `content/` - Documentation content in Markdown format
- `static/` - Static assets (images, etc.)
- `themes/goyo/` - Goyo theme (git submodule)

## Building the Documentation

### Prerequisites

Install Zola static site generator:

```bash
# On macOS
brew install zola

# On Ubuntu/Debian
sudo apt install zola

# From GitHub releases
wget https://github.com/getzola/zola/releases/latest/download/zola-...
```

### Local Development

```bash
# Start development server
cd docs
zola serve

# The site will be available at http://127.0.0.1:1111
```

### Building for Production

```bash
# Build static site
cd docs
zola build

# Output will be in the `public/` directory
```

## Content Organization

### Get Started
- Installation instructions
- Quick start guide  
- Features overview

### Usage
- Detailed command documentation
- Examples and use cases
- Best practices

### Advanced
- Configuration options
- Performance tuning
- Scripting and automation

### Contributing
- Development setup
- Contribution guidelines
- Code standards

## Theme

This documentation uses the [Goyo theme](https://github.com/hahwul/goyo) by @hahwul, which provides:

- Responsive design
- Dark/light mode support
- Search functionality
- Navigation sidebar
- Syntax highlighting
- Social media integration

## Updating Content

1. Edit Markdown files in `content/`
2. Use front matter for page metadata
3. Follow existing structure and naming conventions
4. Test locally with `zola serve`
5. Commit changes to the repository

## Deployment

The documentation can be deployed to:
- GitHub Pages
- Netlify
- Vercel
- Any static hosting service

Configure your hosting service to build with:
```bash
zola build
```

And serve from the `public/` directory.