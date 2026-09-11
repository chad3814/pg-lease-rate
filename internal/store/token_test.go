package store

import (
	"bytes"
	"testing"
)

func TestNewTokenShape(t *testing.T) {
	const want = 43 // base64url of 32 bytes, unpadded

	seen := make(map[Token]bool, 100)
	for range 100 {
		tok := NewToken()
		if len(tok) != want {
			t.Fatalf("NewToken() length = %d, want %d", len(tok), want)
		}
		if seen[tok] {
			t.Fatalf("NewToken() returned a duplicate: %s", string(tok))
		}
		seen[tok] = true
	}
}

func TestHashToken(t *testing.T) {
	tok := NewToken()

	first := hashToken(tok)
	if len(first) != tokenHashBytes {
		t.Fatalf("hashToken() length = %d, want %d", len(first), tokenHashBytes)
	}
	if !bytes.Equal(first, hashToken(tok)) {
		t.Error("hashToken() is not deterministic")
	}
	if bytes.Equal(first, hashToken(NewToken())) {
		t.Error("hashToken() collided across two different tokens")
	}
	if bytes.Contains(first, []byte(tok)) {
		t.Error("the hash contains the plaintext token")
	}
}

func TestVerifyToken(t *testing.T) {
	tok := NewToken()
	other := NewToken()
	want := hashToken(tok)

	tests := []struct {
		name    string
		present Token
		against []byte
		want    bool
	}{
		{name: "correct token", present: tok, against: want, want: true},
		{name: "different token", present: other, against: want},
		{name: "empty token", present: "", against: want},
		{name: "against the dummy hash", present: tok, against: dummyHash},
		{name: "against a wrong-length hash", present: tok, against: want[:16]},
		{name: "against a nil hash", present: tok, against: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := verifyToken(tc.present, tc.against); got != tc.want {
				t.Errorf("verifyToken() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDummyHashIsUnmatchable(t *testing.T) {
	if len(dummyHash) != tokenHashBytes {
		t.Fatalf("dummyHash length = %d, want %d", len(dummyHash), tokenHashBytes)
	}
	// A fresh random token must not verify against it. This is a sanity check
	// on the not-found path of Authenticate, which compares against dummyHash
	// so that its cost does not depend on whether the lease exists.
	for range 100 {
		if verifyToken(NewToken(), dummyHash) {
			t.Fatal("a token verified against dummyHash")
		}
	}
}
