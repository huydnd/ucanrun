#!/bin/sh
# Points the Homebrew formula and the Scoop manifest at a published release,
# with the checksums from its SHA256SUMS. Run after the release workflow:
#   sh scripts/update-packaging.sh 0.13.3
# then commit Formula/ucr.rb and bucket/ucr.json.
set -eu
V=${1:?usage: update-packaging.sh VERSION}
BASE=https://github.com/huydnd/ucanrun/releases/download/v$V
here=$(cd "$(dirname "$0")/.." && pwd)
sums=$(curl -fsSL "$BASE/SHA256SUMS")
sum() { echo "$sums" | awk -v f="$1" '$2 == f {print $1}' | grep . || { echo "no $1 in SHA256SUMS" >&2; exit 1; }; }
mkdir -p "$here/Formula" "$here/bucket"
cat > "$here/Formula/ucr.rb" <<RUBY
# Homebrew formula for ucr. Written by scripts/update-packaging.sh.
#   brew tap huydnd/ucanrun https://github.com/huydnd/ucanrun
#   brew install ucr
class Ucr < Formula
  desc "Client for ucanrun: AI agents ask, you approve, secrets stay hidden"
  homepage "https://github.com/huydnd/ucanrun"
  license "MIT"

  on_macos do
    on_arm do
      url "$BASE/ucr-darwin-arm64"
      sha256 "$(sum ucr-darwin-arm64)"
    end
    on_intel do
      url "$BASE/ucr-darwin-amd64"
      sha256 "$(sum ucr-darwin-amd64)"
    end
  end

  on_linux do
    on_arm do
      url "$BASE/ucr-linux-arm64"
      sha256 "$(sum ucr-linux-arm64)"
    end
    on_intel do
      url "$BASE/ucr-linux-amd64"
      sha256 "$(sum ucr-linux-amd64)"
    end
  end

  def install
    bin.install Dir["ucr-*"].first => "ucr"
  end

  # A runner under your own user, after: ucr runner enroll URL CODE
  service do
    run [opt_bin/"ucr", "runner", "serve"]
    keep_alive true
    log_path var/"log/ucr-runner.log"
    error_log_path var/"log/ucr-runner.log"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/ucr --version")
  end
end
RUBY
cat > "$here/bucket/ucr.json" <<JSON
{
    "version": "$V",
    "description": "Client for ucanrun: AI agents ask, you approve, secrets stay hidden",
    "homepage": "https://github.com/huydnd/ucanrun",
    "license": "MIT",
    "architecture": {
        "64bit": {
            "url": "$BASE/ucr-windows-amd64.exe#/ucr.exe",
            "hash": "$(sum ucr-windows-amd64.exe)"
        }
    },
    "bin": "ucr.exe",
    "checkver": {
        "github": "https://github.com/huydnd/ucanrun"
    },
    "autoupdate": {
        "architecture": {
            "64bit": {
                "url": "https://github.com/huydnd/ucanrun/releases/download/v\$version/ucr-windows-amd64.exe#/ucr.exe"
            }
        },
        "hash": {
            "url": "\$baseurl/SHA256SUMS"
        }
    }
}
JSON
echo "Formula/ucr.rb and bucket/ucr.json now point at v$V"
