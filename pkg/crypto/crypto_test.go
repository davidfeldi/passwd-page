package crypto

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	plaintext := []byte("hello, passwd.page!")
	encoded, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := Decrypt(encoded, key)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestKeyExportImportRoundTrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	encoded := KeyToBase64url(key)
	decoded, err := Base64urlToKey(encoded)
	if err != nil {
		t.Fatalf("Base64urlToKey: %v", err)
	}

	if !bytes.Equal(key, decoded) {
		t.Errorf("key round-trip mismatch")
	}
}

func TestWrongKeyFails(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()

	encoded, err := Encrypt([]byte("secret"), key1)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = Decrypt(encoded, key2)
	if err == nil {
		t.Error("expected decryption with wrong key to fail")
	}
}

func TestEmptyPlaintext(t *testing.T) {
	key, _ := GenerateKey()

	encoded, err := Encrypt([]byte{}, key)
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}

	got, err := Decrypt(encoded, key)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}

	if len(got) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(got))
	}
}

func TestLargePlaintext(t *testing.T) {
	key, _ := GenerateKey()

	// 1 MB of data.
	plaintext := make([]byte, 1<<20)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	encoded, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt large: %v", err)
	}

	got, err := Decrypt(encoded, key)
	if err != nil {
		t.Fatalf("Decrypt large: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Error("large plaintext round-trip mismatch")
	}
}

func TestInvalidKeySize(t *testing.T) {
	shortKey := make([]byte, 16)

	_, err := Encrypt([]byte("test"), shortKey)
	if err == nil {
		t.Error("expected error for short key on Encrypt")
	}

	_, err = Decrypt("dGVzdA", shortKey)
	if err == nil {
		t.Error("expected error for short key on Decrypt")
	}
}

func TestBase64urlToKeyInvalidSize(t *testing.T) {
	// Encode 16 bytes instead of 32.
	short := KeyToBase64url(make([]byte, 16))
	_, err := Base64urlToKey(short)
	if err == nil {
		t.Error("expected error for 16-byte key")
	}
}
