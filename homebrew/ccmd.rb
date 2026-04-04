# typed: false
# frozen_string_literal: true

# To use this formula, create a repo named juliensimon/homebrew-tap
# and place this file at Formula/ccmd.rb
#
# Users install with:
#   brew tap juliensimon/tap
#   brew install ccmd

class Ccmd < Formula
  desc "Cache Commander — a TUI for browsing and managing cache directories"
  homepage "https://github.com/juliensimon/cache-commander"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/juliensimon/cache-commander/releases/download/v#{version}/ccmd-aarch64-apple-darwin.tar.gz"
      sha256 "e506702faf3e910113e4332dc479457ff97d3dd029b06b8542b94783408be6cc"
    end
    on_intel do
      url "https://github.com/juliensimon/cache-commander/releases/download/v#{version}/ccmd-x86_64-apple-darwin.tar.gz"
      sha256 "2b6a3e8d6a660c94b5c4c41351eed440af1745a7b6ce0218f8ef8d972929bb5d"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/juliensimon/cache-commander/releases/download/v#{version}/ccmd-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "3800b9587315c81dd81c629f74a31db89795842c2c2cc2a8e06a2754eb88b6bc"
    end
    on_intel do
      url "https://github.com/juliensimon/cache-commander/releases/download/v#{version}/ccmd-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "1b2f434c15f35a12443dccba8cf12f7550788dc72474a60af297268d5939e621"
    end
  end

  def install
    bin.install "ccmd"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/ccmd --version")
  end
end
