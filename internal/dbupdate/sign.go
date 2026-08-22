package dbupdate

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// GenerateKeypair writes a fresh minisign-format keypair into dir using
// the given comment for the public-key header. Returns the public and
// secret key paths. This is the non-test counterpart of
// GenerateTestKeypair; the on-disk formats are identical.
func GenerateKeypair(dir, comment string) (pubPath, secPath string, err error) {
	if comment == "" {
		comment = untrustedCommentPub
	} else {
		comment = "untrusted comment: " + comment
	}
	if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
		return "", "", fmt.Errorf("creating key directory: %w", mkErr)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, randErr := rand.Read(seed); randErr != nil {
		return "", "", fmt.Errorf("generating seed: %w", randErr)
	}
	keynum := make([]byte, 8)
	if _, randErr := rand.Read(keynum); randErr != nil {
		return "", "", fmt.Errorf("generating keynum: %w", randErr)
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

	pubPath = filepath.Join(dir, "onyx.pub")
	secPath = filepath.Join(dir, "onyx.sec")
	if wErr := writeKeyFilePlain(pubPath, comment, pubBlob, 0o644); wErr != nil {
		return "", "", wErr
	}
	if wErr := writeKeyFilePlain(secPath, untrustedCommentSec, secBlob, 0o600); wErr != nil {
		return "", "", wErr
	}
	return pubPath, secPath, nil
}

// Sign creates a minisign signature over the data at dataPath using the
// secret key at secPath and writes it next to the data as
// filepath.Ext(dataPath)+".minisig" (e.g. feed.json.gz → feed.json.minisig).
//
// The trusted comment binds a timestamp and the file name into the global
// signature so signatures cannot be replayed across files undetected.
func Sign(secPath, dataPath string) (sigPath string, err error) {
	seed, keynum, err := readSecretKeyFile(secPath)
	if err != nil {
		return "", err
	}
	priv := ed25519.NewKeyFromSeed(seed)

	data, err := os.ReadFile(dataPath)
	if err != nil {
		return "", fmt.Errorf("reading data: %w", err)
	}

	sigBlob := make([]byte, 0, sigBlobLen)
	sigBlob = append(sigBlob, minisignAlg...)
	sigBlob = append(sigBlob, keynum...)
	sigBlob = append(sigBlob, ed25519.Sign(priv, data)...)

	trustedComment := fmt.Sprintf("timestamp:%d\tfile:%s", time.Now().Unix(), filepath.Base(dataPath))
	globalSig := ed25519.Sign(priv, append(append([]byte{}, sigBlob...), trustedComment...))

	sigPath = dataPath[:len(dataPath)-len(filepath.Ext(dataPath))] + ".minisig"
	body := untrustedCommentSig + "\n" +
		base64.StdEncoding.EncodeToString(sigBlob) + "\n" +
		trustedCommentLine + trustedComment + "\n" +
		base64.StdEncoding.EncodeToString(globalSig) + "\n"
	if wErr := os.WriteFile(sigPath, []byte(body), 0o644); wErr != nil {
		return "", fmt.Errorf("writing signature: %w", wErr)
	}
	return sigPath, nil
}

// readSecretKeyFile parses an onyx minisign secret key file into its seed
// and key identifier. Layout: "Ed" [2] || keynum [8] || seed [32] || pub [32].
func readSecretKeyFile(path string) (seed, keynum []byte, err error) {
	lines, lErr := readMinisignLines(path)
	if lErr != nil {
		return nil, nil, lErr
	}
	if len(lines) < 2 {
		return nil, nil, fmt.Errorf("malformed secret key %s: want comment + base64 key", path)
	}
	blob, dErr := decodeBlob(lines[1])
	if dErr != nil {
		return nil, nil, fmt.Errorf("malformed secret key %s: %w", path, dErr)
	}
	const wantLen = 2 + 8 + ed25519.SeedSize + ed25519.PublicKeySize
	if len(blob) != wantLen || string(blob[:2]) != minisignAlg {
		return nil, nil, fmt.Errorf("malformed secret key %s: bad length or algorithm", path)
	}
	return blob[10 : 10+ed25519.SeedSize], blob[2:10], nil
}

// writeKeyFilePlain writes a two-line minisign-style key file without a
// testing handle.
func writeKeyFilePlain(path, comment string, blob []byte, mode os.FileMode) error {
	body := comment + "\n" + base64.StdEncoding.EncodeToString(blob) + "\n"
	return os.WriteFile(path, []byte(body), mode)
}
