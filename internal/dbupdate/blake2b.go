package dbupdate

import (
	"encoding/binary"
	"math/bits"
)

// Unkeyed BLAKE2b-512 (RFC 7693), implemented in-package because the Go
// standard library ships no BLAKE2b and this package is stdlib-only.
// It exists solely so VerifyMinisign can check minisign's default
// ("ED"/pre-hashed) signatures, which cover crypto_generichash(BLAKE2b,
// outlen=64) of the message instead of the raw bytes.
//
// Scope: one-shot hashing of in-memory buffers, no key, no salt or
// personalisation, digest length fixed at 64 bytes — exactly the
// configuration minisign 0.12 uses via libsodium's crypto_generichash.

const (
	blake2bBlockSize = 128
	blake2bSize      = 64
)

// blake2bIV is the BLAKE2b initialisation vector (identical to SHA-512's).
var blake2bIV = [8]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
}

// blake2bSigma is the per-round message-word permutation schedule.
var blake2bSigma = [12][16]byte{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	// Rounds 10 and 11 reuse rounds 0 and 1 (RFC 7693, Appendix A).
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
}

// blake2b512 returns the 64-byte unkeyed BLAKE2b digest of data.
func blake2b512(data []byte) []byte {
	return blake2bDigest(data, nil, 64)
}

// blake2bDigest computes the BLAKE2b digest of data for any supported
// output length (1..64), optionally keyed (RFC 7693 §3.3: a secret key is
// zero-padded into its own first block). The digest length and key length
// participate in the parameter block, so shorter digests are not
// truncations of longer ones.
func blake2bDigest(data, key []byte, outlen int) []byte {
	var h [8]uint64
	copy(h[:], blake2bIV[:])
	// Parameter block: digest_length=outlen, key_length=len(key),
	// fanout=1, depth=1; every other field zero, so only h[0] is mixed.
	h[0] ^= 0x01010000 ^ uint64(len(key))<<8 ^ uint64(outlen)

	var (
		buf    [blake2bBlockSize]byte
		buflen int
		t      uint64
	)
	compress := func(block *[blake2bBlockSize]byte, last bool) {
		blake2bCompress(&h, block, t, last)
	}

	// Keyed hashing: the zero-padded key forms the entire first block,
	// left pending exactly like the reference implementation sets c=128.
	if len(key) > 0 {
		copy(buf[:], key)
		buflen = blake2bBlockSize
	}

	for len(data) > 0 {
		if buflen == blake2bBlockSize {
			t += blake2bBlockSize
			compress(&buf, false)
			buflen = 0
		}
		n := copy(buf[buflen:], data)
		buflen += n
		data = data[n:]
	}

	// Final block: zero-pad and set the last-block flag.
	for i := buflen; i < blake2bBlockSize; i++ {
		buf[i] = 0
	}
	t += uint64(buflen)
	compress(&buf, true)

	out := make([]byte, 0, outlen)
	w := 0
	for len(out) < outlen {
		out = binary.LittleEndian.AppendUint64(out, h[w])
		w++
	}
	return out[:outlen]
}

// blake2bCompress mixes one 128-byte block into h; off is the number of
// bytes absorbed before this block (including it), last selects the
// final-block flag.
func blake2bCompress(h *[8]uint64, block *[blake2bBlockSize]byte, off uint64, last bool) {
	var m [16]uint64
	for i := range m {
		m[i] = binary.LittleEndian.Uint64(block[i*8:])
	}
	var v [16]uint64
	copy(v[:8], h[:])
	copy(v[8:], blake2bIV[:])
	v[12] ^= off
	if last {
		v[14] = ^v[14]
	}
	for r := 0; r < 12; r++ {
		s := &blake2bSigma[r]
		blake2bG(&v, 0, 4, 8, 12, m[s[0]], m[s[1]])
		blake2bG(&v, 1, 5, 9, 13, m[s[2]], m[s[3]])
		blake2bG(&v, 2, 6, 10, 14, m[s[4]], m[s[5]])
		blake2bG(&v, 3, 7, 11, 15, m[s[6]], m[s[7]])
		blake2bG(&v, 0, 5, 10, 15, m[s[8]], m[s[9]])
		blake2bG(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
		blake2bG(&v, 2, 7, 8, 13, m[s[12]], m[s[13]])
		blake2bG(&v, 3, 4, 9, 14, m[s[14]], m[s[15]])
	}
	for i := range h {
		h[i] ^= v[i] ^ v[i+8]
	}
}

// blake2bG is one mixing step of the BLAKE2b compression function.
func blake2bG(v *[16]uint64, a, b, c, d int, x, y uint64) {
	v[a] += v[b] + x
	v[d] = bits.RotateLeft64(v[d]^v[a], -32)
	v[c] += v[d]
	v[b] = bits.RotateLeft64(v[b]^v[c], -24)
	v[a] += v[b] + y
	v[d] = bits.RotateLeft64(v[d]^v[a], -16)
	v[c] += v[d]
	v[b] = bits.RotateLeft64(v[b]^v[c], -63)
}
