class Onyx < Formula
  desc "Local-first WordPress vulnerability scanner"
  homepage "https://github.com/Boreas37/onyx"
  url "https://github.com/Boreas37/onyx/releases/download/vVERSION/onyx-darwin-arm64.tar.gz"
  sha256 "REPLACE_WITH_CHECKSUM"
  version "VERSION"
  def install
    bin.install "onyx"
  end
end