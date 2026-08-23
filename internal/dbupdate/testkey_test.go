package dbupdate

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

// GenerateTestKeypair writes a fresh minisign-format keypair into dir and
// returns the public and secret key paths. It lives in a _test.go file so
// the testing dependency never reaches the built binary; production code
// uses GenerateKeypair instead, which writes identical on-disk formats.
//
// Secret-key blob layout (74 bytes): "Ed" [2] || keynum [8] || seed [32]
// || pub [32], where seed derives the full private key via
// ed25519.NewKeyFromSeed and the final 32 bytes store the derived public
// half. This is onyx's plain format — real minisign secret keys are
// scrypt-encrypted boxes and are NOT interchangeable.
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
