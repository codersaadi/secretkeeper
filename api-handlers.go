package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// API Handlers
// handleAuth handles user authentication and returns a session token
func handleAuth(w http.ResponseWriter, r *http.Request) {
	var authReq AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&authReq); err != nil {
		sendErrorResponse(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Check if vault exists
	if _, err := os.Stat(config.VaultPath); os.IsNotExist(err) {
		sendErrorResponse(w, "No vault found. Create a vault first.", http.StatusNotFound)
		return
	}

	// Read vault file
	vaultData, err := os.ReadFile(config.VaultPath)
	if err != nil {
		sendErrorResponse(w, "Error reading vault", http.StatusInternalServerError)
		return
	}

	var vault Vault
	if err := json.Unmarshal(vaultData, &vault); err != nil {
		sendErrorResponse(w, "Error parsing vault data", http.StatusInternalServerError)
		return
	}

	// Decode salt
	salt, err := base64.StdEncoding.DecodeString(vault.Salt)
	if err != nil {
		sendErrorResponse(w, "Error decoding salt", http.StatusInternalServerError)
		return
	}

	// Derive key from password using the stored KDF
	var key []byte
	if vault.KDFType == "argon2id" {
		time := vault.KDFParams["time"]
		memory := vault.KDFParams["memory"]
		threads := vault.KDFParams["threads"]
		key = argon2.IDKey([]byte(authReq.Password), salt, uint32(time), uint32(memory), uint8(threads), 32)
	} else {
		// Fallback to PBKDF2
		iterations := vault.KDFParams["iterations"]
		key = pbkdf2.Key([]byte(authReq.Password), salt, iterations, 32, sha256.New)
	}

	// Decode nonce
	nonce, err := base64.StdEncoding.DecodeString(vault.Nonce)
	if err != nil {
		sendErrorResponse(w, "Error decoding nonce", http.StatusInternalServerError)
		return
	}

	// Decrypt vault
	decryptedSecrets, err := decryptVault(vault.Data, key, nonce)
	if err != nil {
		sendErrorResponse(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	// Authentication successful
	secrets = decryptedSecrets
	masterKey = key
	isUnlocked = true
	config.LastAccessTime = time.Now()
	saveConfig()

	// Create a new session
	token := generateSecureToken()
	expiry := time.Now().Add(time.Duration(config.Timeout) * time.Minute)

	session := Session{
		Token:     token,
		CreatedAt: time.Now(),
		ExpiresAt: expiry,
	}

	sessions[token] = session

	// Return session token
	response := APIResponse{
		Success: true,
		Message: "Authentication successful",
		Data: map[string]interface{}{
			"token":       token,
			"expiry":      expiry,
			"timeout_min": config.Timeout,
		},
	}

	sendJSONResponse(w, response, http.StatusOK)
}

// handleInitVault initializes a new vault
func handleInitVault(w http.ResponseWriter, r *http.Request) {
	var authReq AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&authReq); err != nil {
		sendErrorResponse(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Check if vault already exists
	if _, err := os.Stat(config.VaultPath); !os.IsNotExist(err) {
		sendErrorResponse(w, "Vault already exists", http.StatusConflict)
		return
	}

	// Validate password
	if len(authReq.Password) < 8 {
		sendErrorResponse(w, "Password too short (minimum 8 characters)", http.StatusBadRequest)
		return
	}

	// Generate salt
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		sendErrorResponse(w, "Error generating salt", http.StatusInternalServerError)
		return
	}

	// Derive key from password
	var kdfParams map[string]int
	if config.KeyDerivation == "argon2id" {
		time := 1
		memory := 64 * 1024
		threads := 4
		kdfParams = map[string]int{
			"time":    time,
			"memory":  memory,
			"threads": threads,
		}
		masterKey = argon2.IDKey([]byte(authReq.Password), salt, uint32(time), uint32(memory), uint8(threads), 32)
	} else {
		iterations := 600000 // High iteration count for security
		kdfParams = map[string]int{
			"iterations": iterations,
		}
		masterKey = pbkdf2.Key([]byte(authReq.Password), salt, iterations, 32, sha256.New)
	}

	// Create empty vault
	secrets = []SecretEntry{}

	// Initialize vault with empty encrypted data
	nonce := make([]byte, 12) // GCM standard nonce size
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		sendErrorResponse(w, "Error generating nonce", http.StatusInternalServerError)
		return
	}

	vault := Vault{
		Salt:      base64.StdEncoding.EncodeToString(salt),
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		KDFType:   config.KeyDerivation,
		KDFParams: kdfParams,
		Version:   Version,
	}

	// Encrypt empty data
	encryptedData, err := encryptVault(secrets, masterKey, nonce)
	if err != nil {
		sendErrorResponse(w, "Error encrypting vault", http.StatusInternalServerError)
		return
	}
	vault.Data = encryptedData

	// Save vault to file
	vaultData, err := json.MarshalIndent(vault, "", "  ")
	if err != nil {
		sendErrorResponse(w, "Error serializing vault", http.StatusInternalServerError)
		return
	}

	if err := os.WriteFile(config.VaultPath, vaultData, 0600); err != nil {
		sendErrorResponse(w, "Error writing vault file", http.StatusInternalServerError)
		return
	}

	isUnlocked = true

	// Create a new session
	token := generateSecureToken()
	expiry := time.Now().Add(time.Duration(config.Timeout) * time.Minute)

	session := Session{
		Token:     token,
		CreatedAt: time.Now(),
		ExpiresAt: expiry,
	}

	sessions[token] = session

	// Return success
	response := APIResponse{
		Success: true,
		Message: "Vault created successfully",
		Data: map[string]interface{}{
			"token":       token,
			"expiry":      expiry,
			"timeout_min": config.Timeout,
		},
	}

	sendJSONResponse(w, response, http.StatusCreated)
}

// handleHealthCheck returns basic system status
func handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	vaultExists := false
	if _, err := os.Stat(config.VaultPath); !os.IsNotExist(err) {
		vaultExists = true
	}

	response := APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"version":     Version,
			"vaultExists": vaultExists,
			"status":      "operational",
		},
	}

	sendJSONResponse(w, response, http.StatusOK)
}

// handleGetSecrets returns all secrets
func handleGetSecrets(w http.ResponseWriter, r *http.Request) {
	// Option to exclude password field for list view
	hidePasswords := r.URL.Query().Get("hidePasswords") == "true"

	secretsResponse := make([]map[string]interface{}, len(secrets))

	for i, secret := range secrets {
		secretMap := map[string]interface{}{
			"id":            secret.ID,
			"title":         secret.Title,
			"username":      secret.Username,
			"url":           secret.URL,
			"created_at":    secret.CreatedAt,
			"modified_at":   secret.ModifiedAt,
			"last_accessed": secret.LastAccessed,
		}

		if !hidePasswords {
			secretMap["password"] = secret.Password
			secretMap["notes"] = secret.Notes
		}

		secretsResponse[i] = secretMap
	}

	response := APIResponse{
		Success: true,
		Data:    secretsResponse,
	}

	sendJSONResponse(w, response, http.StatusOK)
}

// handleGetSecret returns a specific secret by ID
func handleGetSecret(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	for i, secret := range secrets {
		if secret.ID == id {
			// Update last accessed time
			secrets[i].LastAccessed = time.Now()
			if err := saveVault(); err != nil {
				sendErrorResponse(w, "Error updating access time", http.StatusInternalServerError)
				return
			}

			response := APIResponse{
				Success: true,
				Data:    secrets[i],
			}
			sendJSONResponse(w, response, http.StatusOK)
			return
		}
	}

	sendErrorResponse(w, "Secret not found", http.StatusNotFound)
}

// handleAddSecret adds a new secret
func handleAddSecret(w http.ResponseWriter, r *http.Request) {
	var newSecret SecretEntry
	if err := json.NewDecoder(r.Body).Decode(&newSecret); err != nil {
		sendErrorResponse(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if newSecret.Title == "" {
		sendErrorResponse(w, "Title is required", http.StatusBadRequest)
		return
	}

	// Generate ID and set timestamps
	newSecret.ID = generateID()
	now := time.Now()
	newSecret.CreatedAt = now
	newSecret.ModifiedAt = now
	newSecret.LastAccessed = now

	// Generate password if not provided
	if newSecret.Password == "" && r.URL.Query().Get("generatePassword") == "true" {
		newSecret.Password = generatePasswordWithOptions(16, true, true, true, true)
	}

	secrets = append(secrets, newSecret)

	if err := saveVault(); err != nil {
		sendErrorResponse(w, "Error saving vault", http.StatusInternalServerError)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Secret added successfully",
		Data:    newSecret,
	}

	sendJSONResponse(w, response, http.StatusCreated)
}

// handleUpdateSecret updates an existing secret
func handleUpdateSecret(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var updatedSecret SecretEntry
	if err := json.NewDecoder(r.Body).Decode(&updatedSecret); err != nil {
		sendErrorResponse(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	found := false
	for i, secret := range secrets {
		if secret.ID == id {
			// Preserve original values for fields not provided
			if updatedSecret.Title != "" {
				secrets[i].Title = updatedSecret.Title
			}
			if updatedSecret.Username != "" {
				secrets[i].Username = updatedSecret.Username
			}
			if updatedSecret.Password != "" {
				secrets[i].Password = updatedSecret.Password
			}
			if updatedSecret.URL != "" {
				secrets[i].URL = updatedSecret.URL
			}
			if updatedSecret.Notes != "" {
				secrets[i].Notes = updatedSecret.Notes
			}

			secrets[i].ModifiedAt = time.Now()
			found = true

			if err := saveVault(); err != nil {
				sendErrorResponse(w, "Error saving vault", http.StatusInternalServerError)
				return
			}

			response := APIResponse{
				Success: true,
				Message: "Secret updated successfully",
				Data:    secrets[i],
			}
			sendJSONResponse(w, response, http.StatusOK)
			return
		}
	}

	if !found {
		sendErrorResponse(w, "Secret not found", http.StatusNotFound)
	}
}

// handleDeleteSecret deletes a secret
func handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	for i, secret := range secrets {
		if secret.ID == id {
			// Remove the secret
			secrets = append(secrets[:i], secrets[i+1:]...)

			if err := saveVault(); err != nil {
				sendErrorResponse(w, "Error saving vault", http.StatusInternalServerError)
				return
			}

			response := APIResponse{
				Success: true,
				Message: "Secret deleted successfully",
			}
			sendJSONResponse(w, response, http.StatusOK)
			return
		}
	}

	sendErrorResponse(w, "Secret not found", http.StatusNotFound)
}

// handleGeneratePassword generates a random password
func handleGeneratePassword(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	// Get parameters with default values
	length, _ := parseInt(query.Get("length"), 16)
	useUpper, _ := parseBool(query.Get("upper"), true)
	useLower, _ := parseBool(query.Get("lower"), true)
	useDigits, _ := parseBool(query.Get("digits"), true)
	useSpecial, _ := parseBool(query.Get("special"), true)

	// Validate parameters
	if length < 8 {
		length = 8 // Minimum secure length
	}
	if length > 128 {
		length = 128 // Reasonable maximum
	}

	// Ensure at least one character type is selected
	if !useUpper && !useLower && !useDigits && !useSpecial {
		useLower = true // Default to lowercase letters
	}

	password := generatePasswordWithOptions(length, useUpper, useLower, useDigits, useSpecial)

	response := APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"password": password,
			"length":   length,
		},
	}

	sendJSONResponse(w, response, http.StatusOK)
}

// handleVaultHealth checks the vault for security issues
func handleVaultHealth(w http.ResponseWriter, r *http.Request) {
	if len(secrets) == 0 {
		response := APIResponse{
			Success: true,
			Message: "No secrets stored",
			Data: map[string]interface{}{
				"issues":   []string{},
				"warnings": []string{},
				"status":   "empty",
			},
		}
		sendJSONResponse(w, response, http.StatusOK)
		return
	}

	issues := []string{}
	warnings := []string{}

	// Check for duplicate passwords
	passwordMap := make(map[string][]string)
	for _, s := range secrets {
		if s.Password != "" {
			passwordMap[s.Password] = append(passwordMap[s.Password], s.Title)
		}
	}

	for _, titles := range passwordMap {
		if len(titles) > 1 {
			issues = append(issues, fmt.Sprintf("Duplicate password used in %d entries: %s",
				len(titles), strings.Join(titles, ", ")))
		}
	}

	// Check for weak passwords
	for _, s := range secrets {
		if len(s.Password) < 8 {
			issues = append(issues, fmt.Sprintf("Weak password (too short) in entry: %s", s.Title))
		}

		// Check password strength (basic check)
		hasUpper := false
		hasLower := false
		hasDigit := false
		hasSpecial := false

		for _, c := range s.Password {
			if unicode.IsUpper(c) {
				hasUpper = true
			} else if unicode.IsLower(c) {
				hasLower = true
			} else if unicode.IsDigit(c) {
				hasDigit = true
			} else {
				hasSpecial = true
			}
		}

		if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
			warnings = append(warnings, fmt.Sprintf("Password could be stronger in entry: %s", s.Title))
		}
	}

	// Check for old entries
	now := time.Now()
	for _, s := range secrets {
		if now.Sub(s.ModifiedAt) > 180*24*time.Hour {
			warnings = append(warnings, fmt.Sprintf("Password not updated in over 6 months: %s", s.Title))
		}
	}

	// Determine overall status
	status := "good"
	if len(issues) > 0 {
		status = "critical"
	} else if len(warnings) > 0 {
		status = "warning"
	}

	response := APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"total_entries": len(secrets),
			"issues":        issues,
			"warnings":      warnings,
			"status":        status,
		},
	}

	sendJSONResponse(w, response, http.StatusOK)
}

// handleBackupVault creates a backup of the vault
func handleBackupVault(w http.ResponseWriter, r *http.Request) {
	if _, err := os.Stat(config.VaultPath); os.IsNotExist(err) {
		sendErrorResponse(w, "No vault found to backup", http.StatusNotFound)
		return
	}

	// Create backup directory if it doesn't exist
	backupDir := filepath.Join(defaultPath, "backups")
	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
		if err := os.MkdirAll(backupDir, 0700); err != nil {
			sendErrorResponse(w, "Error creating backup directory", http.StatusInternalServerError)
			return
		}
	}

	// Create backup filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	backupPath := filepath.Join(backupDir, fmt.Sprintf("vault_backup_%s.json", timestamp))

	// Read vault file
	vaultData, err := os.ReadFile(config.VaultPath)
	if err != nil {
		sendErrorResponse(w, "Error reading vault file", http.StatusInternalServerError)
		return
	}

	// Write backup file
	if err := os.WriteFile(backupPath, vaultData, 0600); err != nil {
		sendErrorResponse(w, "Error writing backup file", http.StatusInternalServerError)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Vault backed up successfully",
		Data: map[string]interface{}{
			"backup_file": filepath.Base(backupPath),
			"backup_time": time.Now(),
			"backup_path": backupPath,
		},
	}

	sendJSONResponse(w, response, http.StatusOK)
}

// handleRestoreVault restores the vault from a backup
func handleRestoreVault(w http.ResponseWriter, r *http.Request) {
	var restoreReq struct {
		BackupFile string `json:"backup_file"`
	}

	if err := json.NewDecoder(r.Body).Decode(&restoreReq); err != nil {
		sendErrorResponse(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	backupDir := filepath.Join(defaultPath, "backups")
	backupPath := filepath.Join(backupDir, restoreReq.BackupFile)

	// Check if backup file exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		sendErrorResponse(w, "Backup file not found", http.StatusNotFound)
		return
	}

	// Read backup file
	backupData, err := os.ReadFile(backupPath)
	if err != nil {
		sendErrorResponse(w, "Error reading backup file", http.StatusInternalServerError)
		return
	}

	// Validate backup data structure
	var vault Vault
	if err := json.Unmarshal(backupData, &vault); err != nil {
		sendErrorResponse(w, "Invalid backup file format", http.StatusBadRequest)
		return
	}

	// Write to vault file
	if err := os.WriteFile(config.VaultPath, backupData, 0600); err != nil {
		sendErrorResponse(w, "Error writing vault file", http.StatusInternalServerError)
		return
	}

	// Reset vault state
	isUnlocked = false
	masterKey = nil
	secrets = nil

	response := APIResponse{
		Success: true,
		Message: "Vault restored successfully",
		Data: map[string]interface{}{
			"backup_file":  restoreReq.BackupFile,
			"restore_time": time.Now(),
		},
	}

	sendJSONResponse(w, response, http.StatusOK)
}

// handleChangeMasterPassword changes the vault's master password
func handleChangeMasterPassword(w http.ResponseWriter, r *http.Request) {
	var passwordReq struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&passwordReq); err != nil {
		sendErrorResponse(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Read current vault
	vaultData, err := os.ReadFile(config.VaultPath)
	if err != nil {
		sendErrorResponse(w, "Error reading vault file", http.StatusInternalServerError)
		return
	}

	var vault Vault
	if err := json.Unmarshal(vaultData, &vault); err != nil {
		sendErrorResponse(w, "Error parsing vault file", http.StatusInternalServerError)
		return
	}

	// Verify current password
	salt, err := base64.StdEncoding.DecodeString(vault.Salt)
	if err != nil {
		sendErrorResponse(w, "Error decoding salt", http.StatusInternalServerError)
		return
	}

	// Derive key from current password
	var currentKey []byte
	if vault.KDFType == "argon2id" {
		time := vault.KDFParams["time"]
		memory := vault.KDFParams["memory"]
		threads := vault.KDFParams["threads"]
		currentKey = argon2.IDKey([]byte(passwordReq.CurrentPassword), salt, uint32(time), uint32(memory), uint8(threads), 32)
	} else {
		iterations := vault.KDFParams["iterations"]
		currentKey = pbkdf2.Key([]byte(passwordReq.CurrentPassword), salt, iterations, 32, sha256.New)
	}

	// Verify current password by trying to decrypt
	nonce, err := base64.StdEncoding.DecodeString(vault.Nonce)
	if err != nil {
		sendErrorResponse(w, "Error decoding nonce", http.StatusInternalServerError)
		return
	}

	_, err = decryptVault(vault.Data, currentKey, nonce)
	if err != nil {
		sendErrorResponse(w, "Current password is incorrect", http.StatusUnauthorized)
		return
	}

	// Validate new password
	if len(passwordReq.NewPassword) < 8 {
		sendErrorResponse(w, "New password is too short (minimum 8 characters)", http.StatusBadRequest)
		return
	}

	// Generate new salt
	newSalt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, newSalt); err != nil {
		sendErrorResponse(w, "Error generating salt", http.StatusInternalServerError)
		return
	}

	// Generate new nonce
	newNonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, newNonce); err != nil {
		sendErrorResponse(w, "Error generating nonce", http.StatusInternalServerError)
		return
	}

	// Derive new key
	var newKey []byte
	var kdfParams map[string]int
	if config.KeyDerivation == "argon2id" {
		time := 1
		memory := 64 * 1024
		threads := 4
		kdfParams = map[string]int{
			"time":    time,
			"memory":  memory,
			"threads": threads,
		}
		newKey = argon2.IDKey([]byte(passwordReq.NewPassword), newSalt, uint32(time), uint32(memory), uint8(threads), 32)
	} else {
		iterations := 600000
		kdfParams = map[string]int{
			"iterations": iterations,
		}
		newKey = pbkdf2.Key([]byte(passwordReq.NewPassword), newSalt, iterations, 32, sha256.New)
	}

	// Encrypt with new key
	encryptedData, err := encryptVault(secrets, newKey, newNonce)
	if err != nil {
		sendErrorResponse(w, "Error encrypting vault", http.StatusInternalServerError)
		return
	}

	// Update vault
	vault.Salt = base64.StdEncoding.EncodeToString(newSalt)
	vault.Nonce = base64.StdEncoding.EncodeToString(newNonce)
	vault.Data = encryptedData
	vault.KDFType = config.KeyDerivation
	vault.KDFParams = kdfParams

	// Save updated vault
	updatedVaultData, err := json.MarshalIndent(vault, "", "  ")
	if err != nil {
		sendErrorResponse(w, "Error serializing vault", http.StatusInternalServerError)
		return
	}

	if err := os.WriteFile(config.VaultPath, updatedVaultData, 0600); err != nil {
		sendErrorResponse(w, "Error writing vault file", http.StatusInternalServerError)
		return
	}

	// Update master key
	masterKey = newKey

	response := APIResponse{
		Success: true,
		Message: "Master password changed successfully",
	}

	sendJSONResponse(w, response, http.StatusOK)
}

// handleLogout invalidates the session token
func handleLogout(w http.ResponseWriter, r *http.Request) {
	token := getTokenFromRequest(r)
	delete(sessions, token)

	response := APIResponse{
		Success: true,
		Message: "Logged out successfully",
	}

	sendJSONResponse(w, response, http.StatusOK)
}

// handleGetConfig returns current configuration
func handleGetConfig(w http.ResponseWriter, r *http.Request) {
	// Create a copy of config without sensitive information
	safeConfig := map[string]interface{}{
		"timeout":        config.Timeout,
		"key_derivation": config.KeyDerivation,
		"api_port":       config.APIPort,
		"enable_tls":     config.EnableTLS,
	}

	response := APIResponse{
		Success: true,
		Data:    safeConfig,
	}

	sendJSONResponse(w, response, http.StatusOK)
}

// handleUpdateConfig updates configuration settings
func handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	var configUpdate struct {
		Timeout       *int    `json:"timeout,omitempty"`
		KeyDerivation *string `json:"key_derivation,omitempty"`
		APIPort       *int    `json:"api_port,omitempty"`
		EnableTLS     *bool   `json:"enable_tls,omitempty"`
		CertFile      *string `json:"cert_file,omitempty"`
		KeyFile       *string `json:"key_file,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&configUpdate); err != nil {
		sendErrorResponse(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Update only provided fields
	if configUpdate.Timeout != nil {
		if *configUpdate.Timeout < 0 {
			sendErrorResponse(w, "Timeout must be non-negative", http.StatusBadRequest)
			return
		}
		config.Timeout = *configUpdate.Timeout
	}

	if configUpdate.KeyDerivation != nil {
		kdf := *configUpdate.KeyDerivation
		if kdf != "argon2id" && kdf != "pbkdf2" {
			sendErrorResponse(w, "Invalid key derivation function", http.StatusBadRequest)
			return
		}
		config.KeyDerivation = kdf
	}

	if configUpdate.APIPort != nil {
		if *configUpdate.APIPort < 1024 || *configUpdate.APIPort > 65535 {
			sendErrorResponse(w, "Invalid port number", http.StatusBadRequest)
			return
		}
		config.APIPort = *configUpdate.APIPort
	}

	if configUpdate.EnableTLS != nil {
		config.EnableTLS = *configUpdate.EnableTLS
	}

	if configUpdate.CertFile != nil {
		config.CertFile = *configUpdate.CertFile
	}

	if configUpdate.KeyFile != nil {
		config.KeyFile = *configUpdate.KeyFile
	}

	// Save updated config
	saveConfig()

	response := APIResponse{
		Success: true,
		Message: "Configuration updated successfully",
	}

	sendJSONResponse(w, response, http.StatusOK)
}
