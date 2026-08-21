package dbupdate

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Minisign/signify format constants. Both file types are two-or-more
// lines: an arbitrary "untrusted comment:" line, then a standard-base64
// binary blob.
//
//	public key blob (42 bytes): "Ed" [2] || keynum [8] || pubkey [32]
//	signature blob  (74 bytes): "Ed" [2] || keynum [8] || sig    [64]
//
// keynum is an advisory 8-byte key identifier; verification relies on the
// embedded Ed25519 public key alone, so a mismatched keynum is not an
// error (matching minisign's lenient behaviour).
const (
	minisignAlg         = "Ed"
	pubKeyBlobLen       = 2 + 8 + ed25519.PublicKeySize // 42
	sigBlobLen          = 2 + 8 + ed25519.SignatureSize // 74
	trustedCommentLine  = "trusted comment: "
	untrustedCommentPub = "untrusted comment: onyx minisign public key"
	untrustedCommentSig = "untrusted comment: onyx minisign signature"
	untrustedCommentSec = "untrusted comment: onyx minisign secret key"
)

// VerifyMinisign verifies the minisign/signify Ed25519 signature at
// sigPath over the data at dataPath against the public key at
// pubKeyPath. A nil return means the signature is valid.
//
// Checks performed:
//
//  1. ed25519.Verify(pubkey, data, sig) for the main signature blob; and
//  2. when the signature file carries a trusted comment (line 3) plus its
//     global signature (line 4): ed25519.Verify(pubkey,
//     sigBlob||trustedComment, globalSig), where sigBlob is the full
//     decoded line-2 blob (alg||keynum||sig) and trustedComment is the
//     text after the "trusted comment: " prefix, without trailing
//     newline. This mirrors minisign's second detached signature, which
//     binds the trusted comment so it cannot be silently rewritten.
//
// A two-line signature file without a trusted comment is accepted and
// only check 1 runs. Any structural problem — wrong line count, bad
// base64, wrong blob length, unknown algorithm ("Ed" is the only one this
// package implements; pre-hashed "ED" signatures are rejected) — fails
// with a descriptive error before any cryptographic work.
func VerifyMinisign(pubKeyPath, sigPath, dataPath string) error {
	pub, err := readPublicKeyFile(pubKeyPath)
	if err != nil {
		return err
	}
	sigBlob, trustedComment, globalSig, hasGlobal, err := readSignatureFile(sigPath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(dataPath)
	if err != nil {
		return fmt.Errorf("reading signed data: %w", err)
	}

	if !ed25519.Verify(pub, data, sigBlob[2+8:]) {
		return errors.New("minisign: signature verification failed")
	}
	if hasGlobal {
		msg := make([]byte, 0, len(sigBlob)+len(trustedComment))
		msg = append(msg, sigBlob...)
		msg = append(msg, trustedComment...)
		if !ed25519.Verify(pub, msg, globalSig) {
			return errors.New("minisign: trusted comment verification failed")
		}
	}
	return nil
}

// GenerateTestKeypair writes a fresh minisign-format keypair into dir and
// returns the public and secret key paths. It exists so tests (and only
// tests) can exercise VerifyMinisign end-to-end without an external
// minisign binary.
//
// Secret-key blob layout (74 bytes): "Ed" [2] || keynum [8] || seed [32]
// || checksum-sk [32], where seed derives the full private key via
// ed25519.NewKeyFromSeed and the final 32 bytes store the derived public
// half, matching minisign's on-disk secret format.
func GenerateTestKeypair(t testing.TB, dir string) (pubPath, privPath string) {
	t.Helper()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("creating key directory: %v", err)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("generating seed: %v", err)
	}
	keynum := make([]byte, 8)
	if _, err := rand.Read(keynum); err != nil {
		t.Fatalf("generating keynum: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	pubBlob := make([]byte, 0, pubKeyBlobLen)
	pubBlob = append(pubBlob, minisignAlg...)
	pubBlob = append(pubBlob, keynum...)
	pubBlob = append(pubBlob, pub...)

	secBlob := make([]byte, 0, 2+8+ed25519.SeedSize+ed25519.PublicKeySize)
	secBlob = append(secBlob, minisignAlg...)
	secBlob = append(secBlob, keynum...)
	secBlob = append(secBlob, seed...)
	secBlob = append(secBlob, pub...) // sign-sk half: the derived public key

	pubPath = filepath.Join(dir, "onyx_test.pub")
	privPath = filepath.Join(dir, "onyx_test.sec")
	writeKeyFile(t, pubPath, untrustedCommentPub, pubBlob, 0o644)
	writeKeyFile(t, privPath, untrustedCommentSec, secBlob, 0o600)
	return pubPath, privPath
}

// writeKeyFile writes a two-line minisign-style key file.
func writeKeyFile(t testing.TB, path, comment string, blob []byte, mode os.FileMode) {
	t.Helper()
	body := comment + "\n" + base64.StdEncoding.EncodeToString(blob) + "\n"
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// readPublicKeyFile parses a minisign public key file into its 32-byte
// Ed25519 public key.
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
// decoded signature blob (alg||keynum||sig), the trusted-comment payload
// (empty if absent), the decoded global signature, and whether a global
// signature was present.
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
	if string(sigBlob[:2]) != minisignAlg {
		return nil, nil, nil, false, fmt.Errorf("unsupported signature algorithm %q in %s (want %q)", sigBlob[:2], path, minisignAlg)
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
