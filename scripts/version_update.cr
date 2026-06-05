# Bumps the jwt-hack version across every file that hardcodes it
# (Cargo.toml, Cargo.lock, snap/snapcraft.yaml, aur/PKGBUILD).
# Prompts for the new version interactively and prints a per-file checkmark.
#
# Pre-release suffixes are allowed (e.g. 2.6.0-dev.1, 2.6.0-rc.1).

CARGO_TOML   = "Cargo.toml"
CARGO_LOCK   = "Cargo.lock"
SNAP_YAML    = "snap/snapcraft.yaml"
AUR_PKGBUILD = "aur/PKGBUILD"

# Docs and README hardcode the version too: the site version badge, the
# landing-page hero badge, the docker pull examples, and the server
# health-response sample. Each entry is {path, pattern, prefix}; the bare
# version is capture group 2, `v?` matches any leading `v` *outside* that group,
# and `prefix` ("v" or "") is what the writer re-attaches. Keep in lockstep
# with the identical list in version_check.cr.
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

# Read helpers (mirror version_check.cr).

def cargo_toml_version : String?
  content = File.read(CARGO_TOML)
  pkg = content.match(/^\[package\][\s\S]*?(?=^\[|\z)/m)
  return nil unless pkg
  match = pkg[0].match(/^version\s*=\s*"([^"]+)"/m)
  match ? match[1] : nil
rescue
  nil
end

def cargo_lock_version : String?
  content = File.read(CARGO_LOCK)
  match = content.match(/name\s*=\s*"jwt-hack"\s*\nversion\s*=\s*"([^"]+)"/)
  match ? match[1] : nil
rescue
  nil
end

def snap_version : String?
  content = File.read(SNAP_YAML)
  match = content.match(/^version:\s*['"]?v?([^'"\s]+)['"]?\s*$/m)
  match ? match[1] : nil
rescue
  nil
end

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

# Write helpers — surgical regex replace, only the package's own version
# line (Cargo.toml's [package] block, the jwt-hack entry in Cargo.lock).
# Other dependencies and lockfile entries are left alone.

def update_cargo_toml(new_version : String) : Bool
  content = File.read(CARGO_TOML)
  pkg_match = content.match(/^\[package\][\s\S]*?(?=^\[|\z)/m)
  return false unless pkg_match
  pkg_block = pkg_match[0]
  updated_pkg = pkg_block.sub(/^(version\s*=\s*")[^"]+(")/m, "\\1#{new_version}\\2")
  return false if updated_pkg == pkg_block
  File.write(CARGO_TOML, content.sub(pkg_block, updated_pkg))
  true
rescue ex
  puts "  error: #{ex.message}"
  false
end

def update_cargo_lock(new_version : String) : Bool
  content = File.read(CARGO_LOCK)
  updated = content.sub(
    /(name\s*=\s*"jwt-hack"\s*\nversion\s*=\s*")[^"]+(")/,
    "\\1#{new_version}\\2",
  )
  return false if updated == content
  File.write(CARGO_LOCK, updated)
  true
rescue ex
  puts "  error: #{ex.message}"
  false
end

# snap convention here keeps the `v` prefix (matches release tags).
# NOTE: Crystal's `/m` flag is MULTILINE *and* DOTALL, so `.` matches
# newlines. Match the value with `[^\n]*` to stay on a single line —
# `.*` would swallow the rest of the file.
def update_snap(new_version : String) : Bool
  content = File.read(SNAP_YAML)
  updated = content.sub(/^(version:[ \t]*)[^\n]*/m, "\\1v#{new_version}")
  return false if updated == content
  File.write(SNAP_YAML, updated)
  true
rescue ex
  puts "  error: #{ex.message}"
  false
end

# AUR pkgver disallows hyphens; rewrite `-` as `_` so dev/rc tags remain
# valid for `makepkg --printsrcinfo`. Also resets pkgrel=1 on bump.
# `[^\n]*` (not `.*`) — see the DOTALL note on update_snap above.
def update_aur(new_version : String) : Bool
  content = File.read(AUR_PKGBUILD)
  aur_ver = new_version.gsub('-', '_')
  updated = content.sub(/^pkgver=[^\n]*/m, "pkgver=#{aur_ver}")
                   .sub(/^pkgrel=[^\n]*/m, "pkgrel=1")
  return false if updated == content
  File.write(AUR_PKGBUILD, updated)
  true
rescue ex
  puts "  error: #{ex.message}"
  false
end

# Generic writer for the DOCS_TARGETS: replace the matched version with
# `prefix + new_version`, keeping the surrounding context (capture group 1).
# `sub` touches only the first match, and each pattern is unique per file.
def update_docs(path : String, pattern : Regex, prefix : String, new_version : String) : Bool
  content = File.read(path)
  updated = content.sub(pattern, "\\1#{prefix}#{new_version}")
  return false if updated == content
  File.write(path, updated)
  true
rescue ex
  puts "  error: #{ex.message}"
  false
end

# Loose semver — allow numeric pre-release suffix (`-dev.1`, `-rc.2`,
# `-alpha`).
def valid_version?(version : String) : Bool
  !!(version =~ /^\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?$/)
end

# Status report.

# Every version-bearing file as {path, current_version, writer}. The writer
# takes the new version as an argument (rather than closing over it) so the
# list can be built up front, before the prompt. `current` is nil for any file
# that doesn't carry a version, which the loop below skips.
targets = [
  {CARGO_TOML, cargo_toml_version, ->(v : String) { update_cargo_toml(v) }},
  {CARGO_LOCK, cargo_lock_version, ->(v : String) { update_cargo_lock(v) }},
  {SNAP_YAML, snap_version, ->(v : String) { update_snap(v) }},
  {AUR_PKGBUILD, aur_version, ->(v : String) { update_aur(v) }},
] of Tuple(String, String?, Proc(String, Bool))
DOCS_TARGETS.each do |t|
  path, pattern, prefix = t[:path], t[:pattern], t[:prefix]
  targets << {path, docs_version(path, pattern), ->(v : String) { update_docs(path, pattern, prefix, v) }}
end

width = targets.map { |path, _, _| path.size }.max

puts "Current versions:"
targets.each do |path, ver, _|
  puts "  #{path.ljust(width)} #{ver || "Not found"}"
end
puts

versions = targets.map { |_, ver, _| ver }.compact
unique = versions.uniq

if unique.size > 1
  puts "Warning: versions disagree (#{unique.join(", ")})"
  puts
end

current = versions.first? || "unknown"
puts "Current: #{current}"
print "New version (Enter to cancel): "
input = gets
new_version = input.try(&.strip) || ""

if new_version.empty?
  puts "Cancelled."
  exit 0
end

unless valid_version?(new_version)
  puts "Invalid version: #{new_version} (expected X.Y.Z or X.Y.Z-suffix)"
  exit 1
end

if unique == [new_version]
  puts "No change."
  exit 0
end

puts
puts "Updating to #{new_version}..."

ok = 0
total = 0
changed = 0

targets.each do |path, ver, fn|
  next if ver.nil? # file doesn't carry a version — nothing to update
  total += 1
  print "  #{path.ljust(width)} "
  if ver == new_version
    puts "unchanged"
    ok += 1
  elsif fn.call(new_version)
    puts "ok"
    ok += 1
    changed += 1
  else
    puts "FAIL"
  end
end

puts
if ok == total
  puts "#{changed} updated, #{total - changed} already at #{new_version}."
else
  puts "Updated #{ok}/#{total} files; #{total - ok} failed."
  exit 1
end
