package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// tokenBytes is the entropy of a generated lease token. 256 bits is why the
// stored form is a plain SHA-256 and not a password-hashing function: a KDF
// exists to make guessing expensive, and there is nothing here to guess. A KDF
// would instead add tens of milliseconds to every client connection.
const tokenBytes = 32

// tokenHashBytes is the width of a SHA-256 digest. The schema enforces it.
const tokenHashBytes = sha256.Size

// dummyHash is what Authenticate compares against when a lease key has no
// row, so that the comparison's cost does not depend on whether the lease
// exists. It is the hash of a random token generated at startup, so nothing
// can verify against it.
var dummyHash = hashToken(NewToken())

// NewToken returns a fresh random lease token.
//
// crypto/rand.Read is documented never to return an error: it crashes the
// process irrecoverably if the operating system's entropy source fails. So
// this cannot fail and returns no error.
func NewToken() Token {
	b := make([]byte, tokenBytes)
	_, _ = rand.Read(b)
	return Token(base64.RawURLEncoding.EncodeToString(b))
}

// hashToken returns the SHA-256 of t. This is the only form of a token that is
// ever stored.
func hashToken(t Token) []byte {
	sum := sha256.Sum256([]byte(t))
	return sum[:]
}

// verifyToken reports whether t hashes to want, comparing in constant time.
// A want of the wrong length never matches.
func verifyToken(t Token, want []byte) bool {
	return subtle.ConstantTimeCompare(hashToken(t), want) == 1
}
