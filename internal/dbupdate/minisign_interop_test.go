package dbupdate

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The tests here encode the interop matrix against real minisign 0.12
// using in-test ed25519 fixtures (no external binary dependency): the
// fixtures replicate exactly what /opt/homebrew/bin/minisign writes, and
// the same matrix is exercised end-to-end by CI against the real binary.

// interopKeypair writes a minisign-format public key file for a fresh
// Ed25519 keypair (minisign -G shape: "Ed" || keynum || pubkey) and
// returns the pub path plus the private key.
func interopKeypair(t *testing.T, dir string) (pubPath string, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keynum := make([]byte, 8)
	if _, err := rand.Read(keynum); err != nil {
		t.Fatal(err)
	}
	blob := append(append(append([]byte{}, minisignAlg...), keynum...), pub...)
	pubPath = filepath.Join(dir, "interop.pub")
	writeKeyFile(t, pubPath, "untrusted comment: minisign public key", blob, 0o644)
	return pubPath, priv
}

// writeInteropSig writes a signature file replicating real minisign 0.12
// output. alg selects "ED" (default, pre-hashed over BLAKE2b-512(data))
// or "Ed" (legacy "-l" mode, unhashed). binding selects the global/comment
// signature message: "raw64" is minisign's construction — raw 64-byte
// signature || trusted comment — while "blob74" is the historical onyx
// signer construction over the full alg||keynum||sig blob.
func writeInteropSig(t *testing.T, priv ed25519.PrivateKey, dataPath, dir, trustedComment, alg, binding string) string {
	t.Helper()
	data, err := os.ReadFile(dataPath)
	if err != nil {
		t.Fatal(err)
	}
	mainMsg := data
	if alg == minisignAlgHashed {
		mainMsg = blake2b512(data)
	}
	sig := ed25519.Sign(priv, mainMsg)

	keynum := make([]byte, 8)
	copy(keynum, priv.Seed()[:8]) // any stable keynum; verification ignores it
	sigBlob := append(append(append([]byte{}, alg...), keynum...), sig...)

	bound := sigBlob[2+8:]
	if binding == "blob74" {
		bound = sigBlob
	}
	globalSig := ed25519.Sign(priv, append(append([]byte{}, bound...), trustedComment...))

	body := fmt.Sprintf("%s\n%s\n%s%s\n%s\n",
		untrustedCommentSig,
		base64.StdEncoding.EncodeToString(sigBlob),
		trustedCommentLine, trustedComment,
		base64.StdEncoding.EncodeToString(globalSig))
	sigPath := filepath.Join(dir, "interop.minisig")
	if err := os.WriteFile(sigPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return sigPath
}

func TestMinisignInteropRealMinisignShapes(t *testing.T) {
	dir := t.TempDir()
	dataPath := filepath.Join(dir, "artifact.bin")
	writeFile(t, dataPath, []byte("published artifact bytes"))

	tests := []struct {
		name    string
		alg     string
		binding string
		tamper  bool   // rewrite the data AFTER signing
		wantErr string // empty = must verify
	}{
		{
			// minisign -G && minisign -S (default pre-hashed ED).
			name:    "real minisign default ED with raw64 comment binding",
			alg:     minisignAlgHashed,
			binding: "raw64",
		},
		{
			// minisign -S -l: legacy unhashed alg, still raw64 binding.
			name:    "real minisign legacy Ed with raw64 comment binding",
			alg:     minisignAlg,
			binding: "raw64",
		},
		{
			// Artifacts signed by OLD onyx-minisign releases: legacy alg
			// with the full-74-byte-blob comment binding.
			name:    "old onyx signer legacy Ed with blob74 binding",
			alg:     minisignAlg,
			binding: "blob74",
		},
		{
			// Tampered payload under the default ED algorithm must fail.
			name:    "tampered data fails ED verification",
			alg:     minisignAlgHashed,
			binding: "raw64",
			tamper:  true,
			wantErr: "signature verification failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, priv := interopKeypair(t, t.TempDir())
			sigPath := writeInteropSig(t, priv, dataPath, t.TempDir(),
				"timestamp:1724227200\tfile:artifact.bin", tt.alg, tt.binding)
			if tt.tamper {
				writeFile(t, dataPath, []byte("TAMPERED artifact bytes"))
			}

			err := VerifyMinisign(pub, sigPath, dataPath)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("VerifyMinisign: %v, want valid", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestMinisignInteropTamperedTrustedCommentFails flips a byte of the
// trusted comment; neither binding construction can verify it.
func TestMinisignInteropTamperedTrustedCommentFails(t *testing.T) {
	dir := t.TempDir()
	pub, priv := interopKeypair(t, dir)
	dataPath := filepath.Join(dir, "data.bin")
	writeFile(t, dataPath, []byte("payload"))
	sigPath := writeInteropSig(t, priv, dataPath, dir, "timestamp:1\tfile:data.bin",
		minisignAlgHashed, "raw64")

	lines, err := readMinisignLines(sigPath)
	if err != nil {
		t.Fatal(err)
	}
	lines[2] = strings.Replace(lines[2], "timestamp:1", "timestamp:9", 1)
	p := filepath.Join(dir, "edited.minisig")
	writeFile(t, p, []byte(strings.Join(lines, "\n")+"\n"))

	if err := VerifyMinisign(pub, p, dataPath); err == nil ||
		!strings.Contains(err.Error(), "trusted comment verification failed") {
		t.Fatalf("err = %v, want trusted comment verification failed", err)
	}
}

// TestMinisignInteropEDNeverUsesBlob74Fallback pins that the legacy
// fallback is gated on the "Ed" algorithm: an ED signature whose comment
// binding uses the old full-blob construction must be rejected, not
// rescued.
func TestMinisignInteropEDNeverUsesBlob74Fallback(t *testing.T) {
	dir := t.TempDir()
	pub, priv := interopKeypair(t, dir)
	dataPath := filepath.Join(dir, "data.bin")
	writeFile(t, dataPath, []byte("payload"))
	sigPath := writeInteropSig(t, priv, dataPath, dir, "ts", minisignAlgHashed, "blob74")

	if err := VerifyMinisign(pub, sigPath, dataPath); err == nil ||
		!strings.Contains(err.Error(), "trusted comment verification failed") {
		t.Fatalf("err = %v, want trusted comment verification failed", err)
	}
}

// TestMinisignInteropRealMinisign012Fixture embeds a signature produced
// by the real minisign 0.12 binary (brew minisign 0.12: `minisign -G -W`,
// then `minisign -S -W`, i.e. the default pre-hashed "ED" algorithm with
// the raw64 comment binding). Unlike the generated fixtures above, this
// pins VerifyMinisign against genuine upstream output, so a regression in
// the BLAKE2b pre-hash or comment binding cannot pass silently.
func TestMinisignInteropRealMinisign012Fixture(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "rm.pub")
	writeFile(t, pubPath, []byte(
		"untrusted comment: minisign public key 84C822C5738A77E2\n"+
			"RWTid4pzxSLIhANCL50lT87WOWAe5xJd8de1ej2s8POti+hjDs+3gl8K\n"))
	dataPath := filepath.Join(dir, "msg.bin")
	writeFile(t, dataPath, []byte("hello interop from onyx\n"))
	sigPath := filepath.Join(dir, "msg.bin.minisig")
	writeFile(t, sigPath, []byte(
		"untrusted comment: signature from minisign secret key\n"+
			"RUTid4pzxSLIhCzn1Sd2WkEtFpOjY8iudODSDkNnjTvDtoah8+P3oREsc8eJLnv2PG/ijvEq/qOF6MpGXFQe7FxK3b5moN0h+AU=\n"+
			"trusted comment: timestamp:1787503523\tfile:msg.bin\thashed\n"+
			"sp6MIcu009hVB9wrt6h8QL+3/zv6wM8uvUga/rBbD/rObhyYkhDEqDnrN9SGrggHrcoaORr0pdDu5e45j0zBDA==\n"))

	if err := VerifyMinisign(pubPath, sigPath, dataPath); err != nil {
		t.Fatalf("real minisign 0.12 ED signature rejected: %v", err)
	}

	// The same fixture over tampered data must fail.
	writeFile(t, dataPath, []byte("tampered interop from onyx\n"))
	if err := VerifyMinisign(pubPath, sigPath, dataPath); err == nil ||
		!strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("err = %v, want main signature verification failed", err)
	}
}
