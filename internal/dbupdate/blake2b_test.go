package dbupdate

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestBlake2b512KnownAnswers pins the in-package BLAKE2b-512 against the
// official RFC 7693 / blake2.net reference vectors, including block
// boundaries (127/128/129 bytes) that exercise the final-block padding.
func TestBlake2b512KnownAnswers(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "empty input",
			in:   "",
			want: "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
		},
		{
			name: "abc",
			in:   "abc",
			want: "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
		},
		{
			name: "one byte 00",
			in:   "\x00",
			want: "2fa3f686df876995167e7c2e5d74c4c7b6e48f8068fe0e44208344d480f7904c36963e44115fe3eb2a3ac8694c28bcb4f5a0f3276f2e79487d8219057a506e4b",
		},
		{
			name: "block minus one (127 bytes of 0x00)",
			in:   string(make([]byte, 127)),
			want: "93cac6a4bedd751e1c145f8e76fec88fec246675898475585603bd228f883bcf4ebcc68ead8fa5f27890a243fa938bd7323ad41f9f06048a732cce2070b212c3",
		},
		{
			name: "exactly one block (128 bytes of 0xff)",
			in:   string(bytes.Repeat([]byte{0xff}, 128)),
			want: "1cf53ba0c775df6463807a82087a4c213cabf70c818933a077c2299d6485c326fd0aaac658ed518610adb459c3593f6b810bd4a43416dab98946ac67c2e8c8b7",
		},
		{
			name: "two blocks minus one (255 bytes of 0xaa)",
			in:   string(bytes.Repeat([]byte{0xaa}, 255)),
			want: "dec249dce2118686ee253d5c790053700805f1613e3e1d0db8566cdfd06ca6117400e87ea0e72f5a54797f2b3908f2ab8189e504bc2c099afb8bc607ffbc7040",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hex.EncodeToString(blake2b512([]byte(tt.in)))
			if got != tt.want {
				t.Fatalf("blake2b512 = %s, want %s", got, tt.want)
			}
		})
	}
}

// TestBlake2bRFCSelfTest implements the exhaustive validation procedure
// from RFC 7693, Appendix E: it hashes deterministically generated
// sequences across the parameter grid (in-len x out-len) and compares a
// grand hash of all results against the constant from the RFC. Unlike
// short fixed KATs, this catches schedule/permutation errors that stay
// hidden while high-index message words are zero.
func TestBlake2bRFCSelfTest(t *testing.T) {
	// selftest_seq: Fibonacci-style deterministic byte generator (RFC 7693).
	seq := func(len int, seed uint32) []byte {
		out := make([]byte, len)
		a, b := uint32(0xDEAD4BAD)*seed, uint32(1)
		for i := range out {
			t := a + b
			a, b = b, t
			out[i] = byte(t >> 24)
		}
		return out
	}
	mdLens := []int{20, 32, 48, 64}
	inLens := []int{0, 3, 128, 129, 255, 1024}
	var grand []byte
	for _, outlen := range mdLens {
		for _, inlen := range inLens {
			in := seq(inlen, uint32(inlen))
			key := seq(outlen, uint32(outlen))
			grand = append(grand, blake2bDigest(in, nil, outlen)...) // unkeyed
			grand = append(grand, blake2bDigest(in, key, outlen)...) // keyed
		}
	}
	final := blake2bDigest(grand, nil, 32)
	const want = "c23a7800d98123bd10f506c61e29da5603d763b8bbad2e737f5e765a7bccd475"
	if got := hex.EncodeToString(final); got != want {
		t.Fatalf("RFC 7693 grand hash mismatch:\n got %s\nwant %s", got, want)
	}
}
