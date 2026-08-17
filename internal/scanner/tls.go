package scanner

import (
	"crypto/tls"
	"math/rand/v2"
)

// tlsFingerprint is one hand-rolled TLSClientConfig variation used by
// --tls-fingerprint. These are not real JA3 fingerprints (that would
// require a full TLS stack such as uTLS), but the cipher ordering and curve
// preference differences are enough to trip naive WAF TLS checks.
type tlsFingerprint struct {
	name string
	cfg  *tls.Config
}

// tlsFingerprints are the combinations --tls-fingerprint rotates between.
// The chrome and firefox sets mirror each browser's cipher/curve priority;
// generic is a neutral third set.
var tlsFingerprints = []tlsFingerprint{
	{
		name: "chrome",
		cfg: &tls.Config{
			MinVersion:       tls.VersionTLS12,
			MaxVersion:       tls.VersionTLS13,
			CipherSuites:     []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256},
			CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
			NextProtos:       []string{"h2", "http/1.1"},
		},
	},
	{
		name: "firefox",
		cfg: &tls.Config{
			MinVersion:       tls.VersionTLS12,
			MaxVersion:       tls.VersionTLS13,
			CipherSuites:     []uint16{tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_AES_128_GCM_SHA256},
			CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
			NextProtos:       []string{"h2", "http/1.1"},
		},
	},
	{
		name: "generic",
		cfg: &tls.Config{
			MinVersion:       tls.VersionTLS12,
			MaxVersion:       tls.VersionTLS13,
			CipherSuites:     []uint16{tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384},
			CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP384, tls.CurveP256},
			NextProtos:       []string{"http/1.1", "h2"},
		},
	},
}

// tlsFingerprintConfig returns the hand-rolled TLSClientConfig variation for
// name ("chrome", "firefox" or "generic"), or nil for an unknown name.
func tlsFingerprintConfig(name string) *tls.Config {
	for _, fp := range tlsFingerprints {
		if fp.name == name {
			return fp.cfg
		}
	}
	return nil
}

// randomTLSFingerprint picks one of the fingerprint combinations at random
// (--tls-fingerprint random).
func randomTLSFingerprint() *tls.Config {
	return tlsFingerprints[rand.IntN(len(tlsFingerprints))].cfg
}
