// Package crypto provides AES-256-GCM encryption utilities compatible with
// the passwd.page frontend crypto.ts implementation.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	keySize = 32 // AES-256
	ivSize  = 12 // 96-bit nonce for GCM
)

// GenerateKey returns 32 cryptographically random bytes suitable for AES-256.
func GenerateKey() ([]byte, error) {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("crypto: generating key: %w", err)
	}
	return key, nil
}

// Encrypt encrypts plaintext with AES-256-GCM using the given key and returns
// the result as base64url(IV + ciphertext). The format matches the frontend
// crypto.ts implementation.
func Encrypt(plaintext, key []byte) (string, error) {
	if len(key) != keySize {
		return "", fmt.Errorf("crypto: key must be %d bytes, got %d", keySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("crypto: creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("crypto: creating GCM: %w", err)
	}

	iv := make([]byte, ivSize)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("crypto: generating IV: %w", err)
	}

	ciphertext := gcm.Seal(nil, iv, plaintext, nil)

	// Concatenate IV + ciphertext and encode as base64url (no padding).
	combined := make([]byte, ivSize+len(ciphertext))
	copy(combined, iv)
	copy(combined[ivSize:], ciphertext)

	return base64.RawURLEncoding.EncodeToString(combined), nil
}

// Decrypt decodes a base64url(IV + ciphertext) string and decrypts it with
// the given AES-256-GCM key.
func Decrypt(encoded string, key []byte) ([]byte, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("crypto: key must be %d bytes, got %d", keySize, len(key))
	}

	combined, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("crypto: decoding base64url: %w", err)
	}

	if len(combined) < ivSize {
		return nil, errors.New("crypto: ciphertext too short")
	}

	iv := combined[:ivSize]
	ciphertext := combined[ivSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: creating GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: decryption failed: %w", err)
	}

	return plaintext, nil
}

// KeyToBase64url encodes a key as a base64url string (no padding).
func KeyToBase64url(key []byte) string {
	return base64.RawURLEncoding.EncodeToString(key)
}

// Base64urlToKey decodes a base64url string back to a key and validates its length.
func Base64urlToKey(s string) ([]byte, error) {
	key, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("crypto: decoding key: %w", err)
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("crypto: decoded key must be %d bytes, got %d", keySize, len(key))
	}
	return key, nil
}
