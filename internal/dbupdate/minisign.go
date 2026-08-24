package dbupdate

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Minisign/signify format constants. Both file types are two-or-more
// lines: an arbitrary "untrusted comment:" line, then a standard-base64
// binary blob.
//
//	public key blob (42 bytes): "Ed" [2] || keynum [8] || pubkey [32]
//	signature blob  (74 bytes): alg  [2] || keynum [8] || sig    [64]
//
// Two signature algorithms exist in the wild and both are accepted for
// verification:
//
//	"Ed" — legacy/unhashed: the signature covers the data directly.
//	       minisign's "-l" mode and every previously published onyx
//	       artifact use it.
//	"ED" — pre-hashed (minisign 0.12 default): the signature covers
//	       BLAKE2b-512(data) instead of the raw bytes.
//
// Public-key files always carry "Ed", matching real minisign output.
//
// keynum is an advisory 8-byte key identifier; verification relies on the
// embedded Ed25519 public key alone, so a mismatched keynum is not an
// error (matching minisign's lenient behaviour).
//
// Compatibility statement: PUBLIC KEYS and SIGNATURES produced here are
// wire-compatible with minisign 0.12 in both directions. Secret keys are
// NOT: real minisign stores scrypt-encrypted key boxes with a KDF/checksum
// header, while onyx writes plain (unencrypted) seed files — they cannot
// be read by minisign and vice versa.
const (
	minisignAlg         = "Ed"                          // legacy/unhashed signature algorithm
	minisignAlgHashed   = "ED"                          // pre-hashed (SHA-512) signature algorithm
	pubKeyBlobLen       = 2 + 8 + ed25519.PublicKeySize // 42
	sigBlobLen          = 2 + 8 + ed25519.SignatureSize // 74
	trustedCommentLine  = "trusted comment: "
	untrustedCommentPub = "untrusted comment: onyx minisign public key"
	untrustedCommentSig = "untrusted comment: onyx minisign signature"
	untrustedCommentSec = "untrusted comment: onyx minisign secret key"
)

// VerifyMinisign verifies a minisign 0.12-compatible Ed25519 signature at
// sigPath over the data at dataPath against the public key at pubKeyPath.
// A nil return means the signature is valid.
//
// Checks performed:
//
//  1. Main signature: for alg "ED" (minisign's default pre-hashed mode)
//     ed25519.Verify(pubkey, BLAKE2b-512(data), sig); for legacy "Ed" the
//     raw data itself is verified. Both algorithms are accepted.
//  2. Global/comment signature, when the file carries a trusted comment
//     (line 3) plus its global signature (line 4): the message is the
//     64-byte raw signature || trusted-comment text — exactly minisign
//     0.12's construction, which binds the trusted comment so it cannot
//     be silently rewritten. If that fails AND the algorithm is legacy
//     "Ed", verification falls back to the historical onyx construction
//     (full 74-byte blob || trusted comment) so previously published
//     artifacts keep verifying; success of either attempt is sufficient,
//     and both failing yields "trusted comment verification failed".
//
// A two-line signature file without a trusted comment is accepted and
// only check 1 runs. Any structural problem — wrong line count, bad
// base64, wrong blob length, unknown algorithm — fails with a descriptive
// error before any cryptographic work.
func VerifyMinisign(pubKeyPath, sigPath, dataPath string) error {
	pub, err := readPublicKeyFile(pubKeyPath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(dataPath)
	if err != nil {
		return fmt.Errorf("reading signed data: %w", err)
	}
	return verifyMinisignBytes(pub, sigPath, data)
}

// verifyMinisignBytes is the shared verification core: it checks the
// signature blob at sigPath over the in-memory data against pub. Both
// VerifyMinisign (data read from a file) and VerifyManifest (raw manifest
// bytes) delegate here, so every artifact type rides the exact same
// parsing, algorithm and comment-binding pipeline. See VerifyMinisign for
// the full semantics.
func verifyMinisignBytes(pub ed25519.PublicKey, sigPath string, data []byte) error {
	sigBlob, trustedComment, globalSig, hasGlobal, err := readSignatureFile(sigPath)
	if err != nil {
		return err
	}

	alg := string(sigBlob[:2])
	mainMsg := data
	if alg == minisignAlgHashed {
		// minisign 0.12 pre-hashes with BLAKE2b (libsodium's
		// crypto_generichash, outlen=64) before signing.
		mainMsg = blake2b512(data)
	}
	if !ed25519.Verify(pub, mainMsg, sigBlob[2+8:]) {
		return errors.New("minisign: signature verification failed")
	}
	if hasGlobal {
		// Minisign 0.12 binds only the raw 64-byte signature to the
		// trusted comment.
		msg := make([]byte, 0, sigBlobLen+len(trustedComment))
		msg = append(msg, sigBlob[2+8:]...)
		msg = append(msg, trustedComment...)
		ok := ed25519.Verify(pub, msg, globalSig)
		if !ok && alg == minisignAlg {
			// Legacy fallback: artifacts signed by older onyx releases
			// covered the full alg||keynum||sig blob instead.
			msg = append(msg[:0], sigBlob...)
			msg = append(msg, trustedComment...)
			ok = ed25519.Verify(pub, msg, globalSig)
		}
		if !ok {
			return errors.New("minisign: trusted comment verification failed")
		}
	}
	return nil
}

// VerifyManifest verifies a minisign 0.12-compatible Ed25519 signature at
// sigPath over in-memory manifest bytes against the public key at
// pubKeyPath. It is the bytes-in counterpart of VerifyMinisign (which
// reads the signed data from a file): callers that already hold the
// manifest body — e.g. from FetchManifestRaw — can verify it directly
// without writing it to a temp file. All parsing, algorithm and
// comment-binding rules are identical to VerifyMinisign, including the
// two-line comment-less main-sig-only acceptance.
func VerifyManifest(pubKeyPath string, rawManifest []byte, sigPath string) error {
	pub, err := readPublicKeyFile(pubKeyPath)
	if err != nil {
		return err
	}
	return verifyMinisignBytes(pub, sigPath, rawManifest)
}

// readPublicKeyFile parses a minisign public key file into its 32-byte
// Ed25519 public key. Real minisign always writes "Ed" here, even for
// keys used to produce pre-hashed "ED" signatures.
func readPublicKeyFile(path string) (ed25519.PublicKey, error) {
	lines, err := readMinisignLines(path)
	if err != nil {
		return nil, err
	}
	if len(lines) < 2 {
		return nil, fmt.Errorf("malformed public key %s: want comment + base64 key, got %d line(s)", path, len(lines))
	}
	blob, err := decodeBlob(lines[1])
	if err != nil {
		return nil, fmt.Errorf("malformed public key %s: %w", path, err)
	}
	if len(blob) != pubKeyBlobLen {
		return nil, fmt.Errorf("malformed public key %s: bad length %d (want %d)", path, len(blob), pubKeyBlobLen)
	}
	if string(blob[:2]) != minisignAlg {
		return nil, fmt.Errorf("unsupported public key algorithm %q in %s (want %q)", blob[:2], path, minisignAlg)
	}
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(pub, blob[10:])
	return pub, nil
}

// readSignatureFile parses a minisign signature file. It returns the full
// decoded signature blob (alg||keynum||sig) — with alg being either "Ed"
// or "ED" — the trusted-comment payload (empty if absent), the decoded
// global signature, and whether a global signature was present.
func readSignatureFile(path string) (sigBlob, trustedComment, globalSig []byte, hasGlobal bool, err error) {
	lines, err := readMinisignLines(path)
	if err != nil {
		return nil, nil, nil, false, err
	}
	if len(lines) < 2 {
		return nil, nil, nil, false, fmt.Errorf("malformed signature %s: want comment + base64 signature, got %d line(s)", path, len(lines))
	}
	sigBlob, err = decodeBlob(lines[1])
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("malformed signature %s: %w", path, err)
	}
	if len(sigBlob) != sigBlobLen {
		return nil, nil, nil, false, fmt.Errorf("malformed signature %s: bad length %d (want %d)", path, len(sigBlob), sigBlobLen)
	}
	switch string(sigBlob[:2]) {
	case minisignAlg, minisignAlgHashed:
	default:
		return nil, nil, nil, false, fmt.Errorf("unsupported signature algorithm %q in %s (want %q or %q)", sigBlob[:2], path, minisignAlg, minisignAlgHashed)
	}
	if len(lines) == 2 {
		return sigBlob, nil, nil, false, nil // comment-less variant: main sig only
	}
	if !strings.HasPrefix(lines[2], trustedCommentLine) {
		return nil, nil, nil, false, fmt.Errorf("malformed signature %s: line 3 must start with %q", path, trustedCommentLine)
	}
	trustedComment = []byte(strings.TrimRight(lines[2][len(trustedCommentLine):], "\r"))
	if len(lines) < 4 {
		return nil, nil, nil, false, fmt.Errorf("malformed signature %s: trusted comment present but global signature line missing", path)
	}
	globalSig, err = decodeBlob(lines[3])
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("malformed signature %s: global signature: %w", path, err)
	}
	if len(globalSig) != ed25519.SignatureSize {
		return nil, nil, nil, false, fmt.Errorf("malformed signature %s: global signature bad length %d (want %d)", path, len(globalSig), ed25519.SignatureSize)
	}
	return sigBlob, trustedComment, globalSig, true, nil
}

// readMinisignLines reads a key/signature file and splits it into
// non-empty-trailing lines, tolerating CRLF.
func readMinisignLines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	lines := strings.Split(s, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	return lines, nil
}

// decodeBlob base64-decodes one minisign binary field.
func decodeBlob(s string) ([]byte, error) {
	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	return blob, nil
}
