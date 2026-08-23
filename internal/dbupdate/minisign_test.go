package dbupdate

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// signTestFile produces a minisign-format signature file over dataPath
// using the secret key at privPath, exercising the same format rules
// VerifyMinisign parses: base64(alg||keynum||sig), trusted comment line,
// base64 global signature. It reproduces the HISTORICAL onyx signer
// construction — global signature over the full 74-byte blob — so every
// test using it now exercises VerifyMinisign's legacy-comment-binding
// fallback path; current Sign() emits minisign's raw-64-byte binding.
func signTestFile(t testing.TB, privPath, dataPath, dir, trustedComment string) string {
	t.Helper()

	lines, err := readMinisignLines(privPath)
	if err != nil {
		t.Fatalf("reading secret key: %v", err)
	}
	blob, err := decodeBlob(lines[1])
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) != 2+8+ed25519.SeedSize+ed25519.PublicKeySize {
		t.Fatalf("bad secret blob length %d", len(blob))
	}
	if string(blob[:2]) != minisignAlg {
		t.Fatalf("bad alg %q", blob[:2])
	}
	keynum := blob[2:10]
	priv := ed25519.NewKeyFromSeed(blob[10:42])
	if pub := priv.Public().(ed25519.PublicKey); string(pub) != string(blob[42:]) {
		t.Fatalf("secret key checksum half does not match derived public key")
	}

	data, err := os.ReadFile(dataPath)
	if err != nil {
		t.Fatalf("reading data: %v", err)
	}
	sig := ed25519.Sign(priv, data)

	sigBlob := make([]byte, 0, sigBlobLen)
	sigBlob = append(sigBlob, minisignAlg...)
	sigBlob = append(sigBlob, keynum...)
	sigBlob = append(sigBlob, sig...)

	msg := make([]byte, 0, len(sigBlob)+len(trustedComment))
	msg = append(msg, sigBlob...)
	msg = append(msg, trustedComment...)
	globalSig := ed25519.Sign(priv, msg)

	body := fmt.Sprintf("%s\n%s\n%s%s\n%s\n",
		untrustedCommentSig,
		base64.StdEncoding.EncodeToString(sigBlob),
		trustedCommentLine, trustedComment,
		base64.StdEncoding.EncodeToString(globalSig))
	sigPath := filepath.Join(dir, "data.minisig")
	if err := os.WriteFile(sigPath, []byte(body), 0o644); err != nil {
		t.Fatalf("writing signature: %v", err)
	}
	return sigPath
}

func TestMinisignVerify(t *testing.T) {
	dir := t.TempDir()
	pubA, secA := GenerateTestKeypair(t, dir)
	pubB, _ := GenerateTestKeypair(t, filepath.Join(dir, "other"))

	tests := []struct {
		name      string
		pubPath   string
		signWith  string // secret key to sign with
		mutate    func(t *testing.T, dataPath, sigPath string) (string, string)
		wantErr   string
		wantValid bool
	}{
		{
			name:      "valid signature passes",
			pubPath:   pubA,
			signWith:  secA,
			wantValid: true,
		},
		{
			name:     "tampered data fails main signature",
			pubPath:  pubA,
			signWith: secA,
			mutate: func(t *testing.T, dataPath, sigPath string) (string, string) {
				writeFile(t, dataPath, []byte(`{"uuid-1":{"id":"uuid-1","title":"EVIL < 1.0"}}`))
				return dataPath, sigPath
			},
			wantErr: "signature verification failed",
		},
		{
			name:     "tampered trusted comment fails",
			pubPath:  pubA,
			signWith: secA,
			mutate: func(t *testing.T, dataPath, sigPath string) (string, string) {
				blob, err := os.ReadFile(sigPath)
				if err != nil {
					t.Fatal(err)
				}
				s := strings.Replace(string(blob), "timestamp=2026-08-21", "timestamp=2026-08-22", 1)
				p := filepath.Join(t.TempDir(), "edited.minisig")
				writeFile(t, p, []byte(s))
				return dataPath, p
			},
			wantErr: "trusted comment verification failed",
		},
		{
			name:     "tampered global signature fails",
			pubPath:  pubA,
			signWith: secA,
			mutate: func(t *testing.T, dataPath, sigPath string) (string, string) {
				lines, err := readMinisignLines(sigPath)
				if err != nil {
					t.Fatal(err)
				}
				gs, err := base64.StdEncoding.DecodeString(lines[3])
				if err != nil {
					t.Fatal(err)
				}
				gs[0] ^= 0x01
				lines[3] = base64.StdEncoding.EncodeToString(gs)
				p := filepath.Join(t.TempDir(), "edited.minisig")
				writeFile(t, p, []byte(strings.Join(lines, "\n")+"\n"))
				return dataPath, p
			},
			wantErr: "trusted comment verification failed",
		},
		{
			name:     "wrong key fails",
			pubPath:  pubB,
			signWith: secA,
			wantErr:  "signature verification failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataPath := filepath.Join(t.TempDir(), "feed.json")
			data := []byte(`{"uuid-1":{"id":"uuid-1","title":"Plugin < 1.0"}}`)
			writeFile(t, dataPath, data)

			comment := "timestamp=2026-08-21T04:00:00Z\tfile:feed.json"
			sigPath := signTestFile(t, tt.signWith, dataPath, t.TempDir(), comment)
			if tt.mutate != nil {
				dataPath, sigPath = tt.mutate(t, dataPath, sigPath)
			}
			err := VerifyMinisign(tt.pubPath, sigPath, dataPath)
			if tt.wantValid {
				if err != nil {
					t.Fatalf("VerifyMinisign: %v, want valid", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("VerifyMinisign succeeded, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestMinisignCommentlessSignatureAccepted(t *testing.T) {
	dir := t.TempDir()
	pub, sec := GenerateTestKeypair(t, dir)
	dataPath := filepath.Join(dir, "data.bin")
	writeFile(t, dataPath, []byte("hello onyx"))

	lines, err := readMinisignLines(signTestFile(t, sec, dataPath, dir, "c"))
	if err != nil {
		t.Fatal(err)
	}
	// Keep only the untrusted comment + signature blob lines.
	bare := filepath.Join(dir, "bare.minisig")
	writeFile(t, bare, []byte(lines[0]+"\n"+lines[1]+"\n"))

	if err := VerifyMinisign(pub, bare, dataPath); err != nil {
		t.Fatalf("comment-less signature should verify: %v", err)
	}
}

func TestMinisignMalformedFiles(t *testing.T) {
	dir := t.TempDir()
	pub, sec := GenerateTestKeypair(t, dir)
	dataPath := filepath.Join(dir, "data.bin")
	writeFile(t, dataPath, []byte("payload"))
	goodSig := signTestFile(t, sec, dataPath, dir, "ts")

	tests := []struct {
		name    string
		pub     string
		sig     string
		data    string
		wantErr string
	}{
		{
			name:    "missing public key file",
			pub:     filepath.Join(dir, "nope.pub"),
			sig:     goodSig,
			data:    dataPath,
			wantErr: "no such file",
		},
		{
			name:    "missing signature file",
			pub:     pub,
			sig:     filepath.Join(dir, "nope.sig"),
			data:    dataPath,
			wantErr: "no such file",
		},
		{
			name:    "missing data file",
			pub:     pub,
			sig:     goodSig,
			data:    filepath.Join(dir, "nope.json"),
			wantErr: "reading signed data",
		},
		{
			name: "public key not base64",
			pub: func() string {
				p := filepath.Join(dir, "junk.pub")
				writeFile(t, p, []byte("untrusted comment: x\n!!!not base64!!!\n"))
				return p
			}(),
			sig:     goodSig,
			data:    dataPath,
			wantErr: "invalid base64",
		},
		{
			name: "public key too short",
			pub: func() string {
				p := filepath.Join(dir, "short.pub")
				writeFile(t, p, []byte("untrusted comment: x\n"+base64.StdEncoding.EncodeToString(make([]byte, 20))+"\n"))
				return p
			}(),
			sig:     goodSig,
			data:    dataPath,
			wantErr: "bad length 20 (want 42)",
		},
		{
			name: "public key wrong algorithm",
			pub: func() string {
				blob := make([]byte, pubKeyBlobLen)
				copy(blob, "ES") // plausible-looking but unknown algorithm
				p := filepath.Join(dir, "alg.pub")
				writeFile(t, p, []byte("untrusted comment: x\n"+base64.StdEncoding.EncodeToString(blob)+"\n"))
				return p
			}(),
			sig:     goodSig,
			data:    dataPath,
			wantErr: `unsupported public key algorithm "ES"`,
		},
		{
			name: "public key one line only",
			pub: func() string {
				p := filepath.Join(dir, "one.pub")
				writeFile(t, p, []byte("untrusted comment: x\n"))
				return p
			}(),
			sig:     goodSig,
			data:    dataPath,
			wantErr: "want comment + base64 key, got 1 line(s)",
		},
		{
			name: "signature bad base64",
			sig: func() string {
				p := filepath.Join(dir, "badsig.minisig")
				writeFile(t, p, []byte("untrusted comment: s\n@@@\n"))
				return p
			}(),
			pub:     pub,
			data:    dataPath,
			wantErr: "invalid base64",
		},
		{
			name: "signature blob too short",
			sig: func() string {
				p := filepath.Join(dir, "shortsig.minisig")
				writeFile(t, p, []byte("untrusted comment: s\n"+base64.StdEncoding.EncodeToString(make([]byte, 30))+"\n"))
				return p
			}(),
			pub:     pub,
			data:    dataPath,
			wantErr: "bad length 30 (want 74)",
		},
		{
			name: "signature wrong algorithm",
			sig: func() string {
				blob := make([]byte, sigBlobLen)
				copy(blob, "ES") // plausible-looking but unknown algorithm
				p := filepath.Join(dir, "algsig.minisig")
				writeFile(t, p, []byte("untrusted comment: s\n"+base64.StdEncoding.EncodeToString(blob)+"\n"))
				return p
			}(),
			pub:     pub,
			data:    dataPath,
			wantErr: `unsupported signature algorithm "ES"`,
		},
		{
			name: "pre-hashed ED blob with garbage sig fails",
			sig: func() string {
				blob := make([]byte, sigBlobLen)
				copy(blob, "ED") // pre-hashed alg accepted, but sig bytes are zeros
				p := filepath.Join(dir, "edzerosig.minisig")
				writeFile(t, p, []byte("untrusted comment: s\n"+base64.StdEncoding.EncodeToString(blob)+"\n"))
				return p
			}(),
			pub:     pub,
			data:    dataPath,
			wantErr: "signature verification failed",
		},
		{
			name: "trusted comment without global signature line",
			sig: func() string {
				lines, err := readMinisignLines(goodSig)
				if err != nil {
					t.Fatal(err)
				}
				p := filepath.Join(dir, "noglobal.minisig")
				writeFile(t, p, []byte(strings.Join(lines[:3], "\n")+"\n"))
				return p
			}(),
			pub:     pub,
			data:    dataPath,
			wantErr: "global signature line missing",
		},
		{
			name: "third line is not a trusted comment",
			sig: func() string {
				lines, err := readMinisignLines(goodSig)
				if err != nil {
					t.Fatal(err)
				}
				lines[2] = "some other comment: nope"
				p := filepath.Join(dir, "wrongprefix.minisig")
				writeFile(t, p, []byte(strings.Join(lines, "\n")+"\n"))
				return p
			}(),
			pub:     pub,
			data:    dataPath,
			wantErr: `line 3 must start with "trusted comment: "`,
		},
		{
			name: "global signature too short",
			sig: func() string {
				lines, err := readMinisignLines(goodSig)
				if err != nil {
					t.Fatal(err)
				}
				lines[3] = base64.StdEncoding.EncodeToString(make([]byte, 10))
				p := filepath.Join(dir, "shortglobal.minisig")
				writeFile(t, p, []byte(strings.Join(lines, "\n")+"\n"))
				return p
			}(),
			pub:     pub,
			data:    dataPath,
			wantErr: "global signature bad length 10 (want 64)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyMinisign(tt.pub, tt.sig, tt.data)
			if err == nil {
				t.Fatalf("VerifyMinisign succeeded, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestGenerateTestKeypairFormat pins the documented blob layouts.
func TestGenerateTestKeypairFormat(t *testing.T) {
	dir := t.TempDir()
	pubPath, privPath := GenerateTestKeypair(t, dir)

	pubLines, err := readMinisignLines(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(pubLines) != 2 || !strings.HasPrefix(pubLines[0], "untrusted comment:") {
		t.Fatalf("public key file shape wrong: %q", pubLines)
	}
	pubBlob, err := decodeBlob(pubLines[1])
	if err != nil {
		t.Fatal(err)
	}
	if len(pubBlob) != pubKeyBlobLen || string(pubBlob[:2]) != minisignAlg {
		t.Fatalf("public blob malformed: len=%d alg=%q", len(pubBlob), pubBlob[:2])
	}

	secLines, err := readMinisignLines(privPath)
	if err != nil {
		t.Fatal(err)
	}
	secBlob, err := decodeBlob(secLines[1])
	if err != nil {
		t.Fatal(err)
	}
	if len(secBlob) != 74 || string(secBlob[:2]) != minisignAlg {
		t.Fatalf("secret blob malformed: len=%d", len(secBlob))
	}
	// seed-derived public half must equal the stored public key
	priv := ed25519.NewKeyFromSeed(secBlob[10:42])
	if string(priv.Public().(ed25519.PublicKey)) != string(secBlob[42:]) {
		t.Error("secret key second half is not the derived public key")
	}
	if string(secBlob[42:]) != string(pubBlob[10:]) {
		t.Error("keypair halves do not share the same public key")
	}
	if string(secBlob[2:10]) != string(pubBlob[2:10]) {
		t.Error("keynum differs between public and secret files")
	}
}
