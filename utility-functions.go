package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

// Utility Functions

// authMiddleware verifies the authentication token
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := getTokenFromRequest(r)

		if token == "" {
			sendErrorResponse(w, "Authentication required", http.StatusUnauthorized)
			return
		}

		session, found := sessions[token]
		if !found {
			sendErrorResponse(w, "Invalid or expired session", http.StatusUnauthorized)
			return
		}

		// Check for token expiration
		if time.Now().After(session.ExpiresAt) {
			delete(sessions, token)
			sendErrorResponse(w, "Session expired", http.StatusUnauthorized)
			return
		}

		// Update session expiration time
		session.ExpiresAt = time.Now().Add(time.Duration(config.Timeout) * time.Minute)
		sessions[token] = session

		// Check if vault is still unlocked
		if !isUnlocked || masterKey == nil {
			sendErrorResponse(w, "Vault is locked", http.StatusUnauthorized)
			return
		}

		// Update access time
		config.LastAccessTime = time.Now()
		saveConfig()

		next.ServeHTTP(w, r)
	})
}

// getTokenFromRequest extracts the token from Authorization header
func getTokenFromRequest(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}

	return parts[1]
}

// generateSecureToken creates a secure random token for sessions
func generateSecureToken() string {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		// Fallback to less secure but functional
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base64.URLEncoding.EncodeToString(b)
}

// cleanExpiredSessions removes expired sessions
func cleanExpiredSessions() {
	now := time.Now()
	for token, session := range sessions {
		if now.After(session.ExpiresAt) {
			delete(sessions, token)
		}
	}
}

// sendJSONResponse sends a JSON response with the given status code
func sendJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

// sendErrorResponse sends an error response with the given message and status code
func sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	response := APIResponse{
		Success: false,
		Message: message,
	}
	sendJSONResponse(w, response, statusCode)
}

// / parseInt parses a string to int with a default value
func parseInt(s string, defaultValue int) (int, error) {
	if s == "" {
		return defaultValue, nil
	}

	var val int
	_, err := fmt.Sscanf(s, "%d", &val)
	if err != nil {
		return defaultValue, err
	}

	return val, nil
}

// parseBool parses a string to bool with a default value
func parseBool(s string, defaultValue bool) (bool, error) {
	if s == "" {
		return defaultValue, nil
	}

	return strings.ToLower(s) == "true" || s == "1", nil
}

// encryptVault encrypts the secrets data with the master key
func encryptVault(secrets []SecretEntry, key []byte, nonce []byte) (string, error) {
	// Convert secrets to JSON
	plaintext, err := json.Marshal(secrets)
	if err != nil {
		return "", err
	}

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// GCM mode provides authenticated encryption
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Encrypt and authenticate plaintext
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	// Encode as base64
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptVault decrypts the vault data with the master key
func decryptVault(encryptedData string, key []byte, nonce []byte) ([]SecretEntry, error) {
	// Decode from base64
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// GCM mode for authenticated decryption
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decrypt and verify
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	// Parse decrypted data
	var decryptedSecrets []SecretEntry
	if err := json.Unmarshal(plaintext, &decryptedSecrets); err != nil {
		return nil, err
	}

	return decryptedSecrets, nil
}

// saveVault encrypts and saves the current secrets to disk
func saveVault() error {
	// Read current vault to get encryption parameters
	vaultData, err := os.ReadFile(config.VaultPath)
	if err != nil {
		return err
	}

	var vault Vault
	if err := json.Unmarshal(vaultData, &vault); err != nil {
		return err
	}

	// Decode nonce
	nonce, err := base64.StdEncoding.DecodeString(vault.Nonce)
	if err != nil {
		return err
	}

	// Encrypt updated secrets
	encryptedData, err := encryptVault(secrets, masterKey, nonce)
	if err != nil {
		return err
	}

	// Update vault
	vault.Data = encryptedData

	// Save updated vault
	updatedVaultData, err := json.MarshalIndent(vault, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(config.VaultPath, updatedVaultData, 0600)
}

// generateID creates a unique ID for a new secret
func generateID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}

// generatePasswordWithOptions creates a strong random password
func generatePasswordWithOptions(length int, useUpper, useLower, useDigits, useSpecial bool) string {
	const (
		uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		lowercaseChars = "abcdefghijklmnopqrstuvwxyz"
		digitChars     = "0123456789"
		specialChars   = "!@#$%^&*()-_=+[]{}|;:,.<>?"
	)

	// Build character set
	var charSet string
	if useUpper {
		charSet += uppercaseChars
	}
	if useLower {
		charSet += lowercaseChars
	}
	if useDigits {
		charSet += digitChars
	}
	if useSpecial {
		charSet += specialChars
	}

	// Generate password
	password := make([]byte, length)
	for i := 0; i < length; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charSet))))
		if err != nil {
			// Fallback to less secure method if crypto/rand fails
			password[i] = charSet[time.Now().Nanosecond()%len(charSet)]
		} else {
			password[i] = charSet[idx.Int64()]
		}
	}

	// Ensure password includes at least one of each selected character type
	password = ensurePasswordStrength(password, useUpper, useLower, useDigits, useSpecial)

	return string(password)
}

// ensurePasswordStrength makes sure a password has at least one of each required character type
func ensurePasswordStrength(password []byte, useUpper, useLower, useDigits, useSpecial bool) []byte {
	const (
		uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		lowercaseChars = "abcdefghijklmnopqrstuvwxyz"
		digitChars     = "0123456789"
		specialChars   = "!@#$%^&*()-_=+[]{}|;:,.<>?"
	)

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, c := range password {
		if strings.ContainsRune(uppercaseChars, rune(c)) {
			hasUpper = true
		} else if strings.ContainsRune(lowercaseChars, rune(c)) {
			hasLower = true
		} else if strings.ContainsRune(digitChars, rune(c)) {
			hasDigit = true
		} else if strings.ContainsRune(specialChars, rune(c)) {
			hasSpecial = true
		}
	}

	// Helper function for secure random int
	getRandomIndex := func(max int) int {
		if max <= 0 {
			return 0
		}
		n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
		if err != nil {
			// Fallback to a less secure but functional option in case of error
			return int(time.Now().UnixNano() % int64(max))
		}
		return int(n.Int64())
	}

	// Copy password for modifications
	result := make([]byte, len(password))
	copy(result, password)

	// Replace some characters if needed
	if useUpper && !hasUpper {
		idx := getRandomIndex(len(result))
		charIdx := getRandomIndex(len(uppercaseChars))
		result[idx] = uppercaseChars[charIdx]
	}

	if useLower && !hasLower {
		idx := getRandomIndex(len(result))
		charIdx := getRandomIndex(len(lowercaseChars))
		result[idx] = lowercaseChars[charIdx]
	}

	if useDigits && !hasDigit {
		idx := getRandomIndex(len(result))
		charIdx := getRandomIndex(len(digitChars))
		result[idx] = digitChars[charIdx]
	}

	if useSpecial && !hasSpecial {
		idx := getRandomIndex(len(result))
		charIdx := getRandomIndex(len(specialChars))
		result[idx] = specialChars[charIdx]
	}

	return result
}
