# Reports the version string declared in each file jwt-hack keeps in lockstep
# (Cargo.toml, Cargo.lock, snap/snapcraft.yaml, aur/PKGBUILD).
# Exits non-zero when they disagree so it can gate a release.

CARGO_TOML   = "Cargo.toml"
CARGO_LOCK   = "Cargo.lock"
SNAP_YAML    = "snap/snapcraft.yaml"
AUR_PKGBUILD = "aur/PKGBUILD"

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

cargo_v = cargo_toml_version
lock_v  = cargo_lock_version
snap_v  = snap_version
aur_v   = aur_version

puts "#{CARGO_TOML.ljust(22)} #{cargo_v || "Not found"}"
puts "#{CARGO_LOCK.ljust(22)} #{lock_v || "Not found"}"
puts "#{SNAP_YAML.ljust(22)} #{snap_v || "Not found"}"
puts "#{AUR_PKGBUILD.ljust(22)} #{aur_v || "Not found"}"
puts

versions = [cargo_v, lock_v, snap_v, aur_v].compact

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
