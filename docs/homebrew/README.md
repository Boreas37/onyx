# onyx Homebrew tap

`onyx` is distributed for macOS (and Linux) via a Homebrew tap. The tap
repository is **separate** from this repo — it lives at
[`Boreas37/homebrew-onyx`](https://github.com/Boreas37/homebrew-onyx) — and
simply contains this formula so that Homebrew knows how to install the
release binaries.

`docs/homebrew/onyx.rb` in this repository is the source template. When a new
version is tagged, the formula is copied into the tap with three
substitutions:

| Placeholder | Replace with |
|---|---|
| `vVERSION` | the tag, e.g. `v0.2.0` |
| `VERSION` | the version without the `v`, e.g. `0.2.0` |
| `REPLACE_WITH_CHECKSUM` | the `sha256sum` of `onyx-darwin-arm64.tar.gz` from the release's `checksums.txt` |

## Install

```bash
brew tap Boreas37/homebrew-onyx
brew install onyx
```

Confirm the installed binary:

```bash
onyx version
```

## Update

```bash
brew update && brew upgrade onyx
```

## Notes

- The formula ships the `darwin/arm64` build (Apple Silicon); a
  `darwin/amd64` (Intel) variant can be added later if needed.
- The tap repo is not created yet — this directory is the template it will
  be published from.