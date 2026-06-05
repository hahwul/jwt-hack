# Reports the version string declared in each file jwt-hack keeps in lockstep
# (Cargo.toml, Cargo.lock, snap/snapcraft.yaml, aur/PKGBUILD).
# Exits non-zero when they disagree so it can gate a release.

CARGO_TOML   = "Cargo.toml"
CARGO_LOCK   = "Cargo.lock"
SNAP_YAML    = "snap/snapcraft.yaml"
AUR_PKGBUILD = "aur/PKGBUILD"

# Docs and README hardcode the version too: the site version badge, the
# landing-page hero badge, the docker pull examples, and the server
# health-response sample. Each entry is {path, pattern, prefix}; the bare
# version is capture group 2, and any leading `v` is matched by `v?` *outside*
# that group so version_update can restore the right `prefix` ("v" or "").
DOCS_TARGETS = [
  {path: "docs/templates/header.html",
   pattern: /(class="version-badge">)v?([^<]+)/, prefix: "v"},
  {path: "docs/content/index.md",
   pattern: /(hero_badge\s*=\s*")v?([^"]+)/, prefix: "v"},
  {path: "docs/content/get_started/installation.md",
   pattern: /(docker pull hahwul\/jwt-hack:)v?([0-9][^\s]*)/, prefix: "v"},
  {path: "README.md",
   pattern: /(docker pull hahwul\/jwt-hack:)v?([0-9][^\s]*)/, prefix: "v"},
  {path: "docs/content/usage/commands/server.md",
   pattern: /("version":\s*")v?([^"]+)/, prefix: ""},
]

# Cargo.toml: top-level `version = "X"` inside [package].
def cargo_toml_version : String?
  content = File.read(CARGO_TOML)
  pkg = content.match(/^\[package\][\s\S]*?(?=^\[|\z)/m)
  return nil unless pkg
  match = pkg[0].match(/^version\s*=\s*"([^"]+)"/m)
  match ? match[1] : nil
rescue
  nil
end

# Cargo.lock: the `name = "jwt-hack"` entry's version line.
def cargo_lock_version : String?
  content = File.read(CARGO_LOCK)
  match = content.match(/name\s*=\s*"jwt-hack"\s*\nversion\s*=\s*"([^"]+)"/)
  match ? match[1] : nil
rescue
  nil
end

# snap/snapcraft.yaml: `version: vX` — strip the `v` for comparison.
def snap_version : String?
  content = File.read(SNAP_YAML)
  match = content.match(/^version:\s*['"]?v?([^'"\s]+)['"]?\s*$/m)
  match ? match[1] : nil
rescue
  nil
end

# aur/PKGBUILD: `pkgver=X`. AUR forbids hyphens in pkgver, so pre-release
# versions are stored with `_` (e.g. 2.6.0_dev.1); normalize back to `-`
# so it compares equal to the other files.
def aur_version : String?
  content = File.read(AUR_PKGBUILD)
  match = content.match(/^pkgver=([^\s]+)/m)
  match ? match[1].gsub('_', '-') : nil
rescue
  nil
end

# Generic reader for the DOCS_TARGETS above: capture group 2 holds the bare
# version (the optional leading `v` is matched outside the group and dropped).
def docs_version(path : String, pattern : Regex) : String?
  match = File.read(path).match(pattern)
  match ? match[2] : nil
rescue
  nil
end

entries = [
  {CARGO_TOML, cargo_toml_version},
  {CARGO_LOCK, cargo_lock_version},
  {SNAP_YAML, snap_version},
  {AUR_PKGBUILD, aur_version},
] + DOCS_TARGETS.map { |t| {t[:path], docs_version(t[:path], t[:pattern])} }

width = entries.map { |path, _| path.size }.max
entries.each do |path, ver|
  puts "#{path.ljust(width)} #{ver || "Not found"}"
end
puts

versions = entries.map { |_, v| v }.compact

if versions.empty?
  puts "No versions found!"
  exit 1
end

unique = versions.uniq

if unique.size == 1
  puts "All versions match: #{unique.first}"
else
  puts "Versions disagree: #{unique.join(", ")}"
  exit 1
end
