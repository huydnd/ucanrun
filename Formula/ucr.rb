# Homebrew formula for ucr. Written by scripts/update-packaging.sh.
#   brew tap huydnd/ucanrun https://github.com/huydnd/ucanrun
#   brew install ucr
class Ucr < Formula
  desc "Client for ucanrun: AI agents ask, you approve, secrets stay hidden"
  homepage "https://github.com/huydnd/ucanrun"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/huydnd/ucanrun/releases/download/v0.13.3/ucr-darwin-arm64"
      sha256 "ba8e9cfcd5e89f3a89ac4e86798228f761e62cacb011deecccbd4718e40c1ae5"
    end
    on_intel do
      url "https://github.com/huydnd/ucanrun/releases/download/v0.13.3/ucr-darwin-amd64"
      sha256 "daee0b57b57d8e2f99750a9ea299c829d26f07f40e17c482d5bae7a504cbd6a3"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/huydnd/ucanrun/releases/download/v0.13.3/ucr-linux-arm64"
      sha256 "168bc84936f84348e2afb6e17e593d5a7d0d3d815bb2cba8dd52a9e7df38bea7"
    end
    on_intel do
      url "https://github.com/huydnd/ucanrun/releases/download/v0.13.3/ucr-linux-amd64"
      sha256 "f43b6b38b5db49b5b23c791b639b22e793f40e19058bc2365f3777a679214eb8"
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
