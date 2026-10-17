package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// Digest is a lowercase hex SHA-256, the same value the AXLR console keeps
// for every forged-tool file.
type Digest string

// NewDigest validates a digest.
func NewDigest(s string) (Digest, error) {
	if len(s) != 64 {
		return "", errors.New("invalid SHA-256 digest")
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return "", errors.New("invalid SHA-256 digest")
		}
	}
	return Digest(s), nil
}

// DigestOf hashes bytes.
func DigestOf(b []byte) Digest {
	sum := sha256.Sum256(b)
	return Digest(hex.EncodeToString(sum[:]))
}
