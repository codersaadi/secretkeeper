package main

// import (
// 	"bufio"
// 	"crypto/aes"
// 	"crypto/cipher"
// 	"crypto/rand"
// 	"crypto/sha256"
// 	"encoding/base64"
// 	"encoding/json"
// 	"errors"
// 	"fmt"
// 	"io"
// 	"math/big"
// 	"os"
// 	"path/filepath"
// 	"strings"
// 	"syscall"
// 	"time"
// 	"unicode"

// 	"golang.org/x/crypto/argon2"
// 	"golang.org/x/crypto/pbkdf2"
// 	"golang.org/x/term"
// )

// // SecretEntry represents a stored credential
// type SecretEntry struct {
// 	ID           string    `json:"id"`
// 	Title        string    `json:"title"`
// 	Username     string    `json:"username"`
// 	Password     string    `json:"password"`
// 	URL          string    `json:"url"`
// 	Notes        string    `json:"notes"`
// 	CreatedAt    time.Time `json:"created_at"`
// 	ModifiedAt   time.Time `json:"modified_at"`
// 	LastAccessed time.Time `json:"last_accessed"`
// }

// // Vault represents the encrypted password vault
// type Vault struct {
// 	Salt       string         `json:"salt"`
// 	Nonce      string         `json:"nonce"`
// 	Data       string         `json:"data"`
// 	KDFType    string         `json:"kdf_type"` // "argon2id" or "pbkdf2"
// 	KDFParams  map[string]int `json:"kdf_params"`
// 	Iterations int            `json:"iterations"`
// 	Version    string         `json:"version"`
// }

// // Config represents application configuration
// type Config struct {
// 	VaultPath      string    `json:"vault_path"`
// 	Timeout        int       `json:"timeout"`        // Auto logout time in minutes
// 	KeyDerivation  string    `json:"key_derivation"` // "argon2id" or "pbkdf2"
// 	LastAccessTime time.Time `json:"last_access_time"`
// }

// // Global variables
// var (
// 	config      Config
// 	secrets     []SecretEntry
// 	masterKey   []byte
// 	isUnlocked  bool
// 	configPath  string
// 	defaultPath string
// )

// const (
// 	AppName    = "SecretKeeper"
// 	Version    = "1.0.0"
// 	ConfigFile = "config.json"
// )

// func init() {
// 	homeDir, err := os.UserHomeDir()
// 	if err != nil {
// 		fmt.Println("Error getting home directory:", err)
// 		os.Exit(1)
// 	}

// 	defaultPath = filepath.Join(homeDir, "."+strings.ToLower(AppName))
// 	configPath = filepath.Join(defaultPath, ConfigFile)

// 	// Create app directory if it doesn't exist
// 	if _, err := os.Stat(defaultPath); os.IsNotExist(err) {
// 		if err := os.MkdirAll(defaultPath, 0700); err != nil {
// 			fmt.Println("Error creating app directory:", err)
// 			os.Exit(1)
// 		}
// 	}

// 	// Load or create config
// 	if _, err := os.Stat(configPath); os.IsNotExist(err) {
// 		config = Config{
// 			VaultPath:     filepath.Join(defaultPath, "vault.json"),
// 			Timeout:       15,
// 			KeyDerivation: "argon2id", // Default to Argon2id
// 		}
// 		saveConfig()
// 	} else {
// 		loadConfig()
// 	}
// }

// func main() {
// 	fmt.Printf("\n%s Password Manager v%s\n", AppName, Version)
// 	fmt.Println(strings.Repeat("=", 40))

// 	// Main program loop
// 	for {
// 		if !isUnlocked {
// 			fmt.Println("\n1. Create new vault")
// 			fmt.Println("2. Unlock vault")
// 			fmt.Println("3. Change configuration")
// 			fmt.Println("4. Exit")
// 			fmt.Print("\nChoice: ")
// 		} else {
// 			// Reset timeout timer
// 			config.LastAccessTime = time.Now()
// 			saveConfig()

// 			fmt.Println("\n1. List all secrets")
// 			fmt.Println("2. Add new secret")
// 			fmt.Println("3. View secret")
// 			fmt.Println("4. Edit secret")
// 			fmt.Println("5. Delete secret")
// 			fmt.Println("6. Generate password")
// 			fmt.Println("7. Lock vault")
// 			fmt.Println("8. Change master password")
// 			fmt.Println("9. Exit")
// 			fmt.Print("\nChoice: ")
// 		}

// 		// Check for timeout
// 		if isUnlocked && config.Timeout > 0 {
// 			if time.Since(config.LastAccessTime).Minutes() > float64(config.Timeout) {
// 				fmt.Println("\nSession timed out. Vault locked.")
// 				isUnlocked = false
// 				masterKey = nil
// 				continue
// 			}
// 		}

// 		var choice int
// 		_, err := fmt.Scanln(&choice)
// 		if err != nil {
// 			// Clear input buffer
// 			scanner := bufio.NewScanner(os.Stdin)
// 			scanner.Scan()
// 		}

// 		if !isUnlocked {
// 			switch choice {
// 			case 1:
// 				createNewVault()
// 			case 2:
// 				unlockVault()
// 			case 3:
// 				changeConfiguration()
// 			case 4:
// 				fmt.Println("Exiting. Goodbye!")
// 				return
// 			default:
// 				fmt.Println("Invalid choice, please try again.")
// 			}
// 		} else {
// 			switch choice {
// 			case 1:
// 				listSecrets()
// 			case 2:
// 				addSecret()
// 			case 3:
// 				viewSecret()
// 			case 4:
// 				editSecret()
// 			case 5:
// 				deleteSecret()
// 			case 6:
// 				password := generatePassword()
// 				fmt.Println("Generated password:", password)
// 				fmt.Println("Press Enter to continue...")
// 				bufio.NewReader(os.Stdin).ReadString('\n')
// 			case 7:
// 				isUnlocked = false
// 				masterKey = nil
// 				secrets = nil
// 				fmt.Println("Vault locked.")
// 			case 8:
// 				changeMasterPassword()
// 			case 9:
// 				fmt.Println("Exiting. Goodbye!")
// 				return
// 			default:
// 				fmt.Println("Invalid choice, please try again.")
// 			}
// 		}
// 	}
// }

// // loadConfig loads application configuration from file
// func loadConfig() {
// 	data, err := os.ReadFile(configPath)
// 	if err != nil {
// 		fmt.Println("Error reading config file:", err)
// 		return
// 	}

// 	if err := json.Unmarshal(data, &config); err != nil {
// 		fmt.Println("Error parsing config file:", err)
// 		return
// 	}
// }

// // saveConfig saves application configuration to file
// func saveConfig() {
// 	data, err := json.MarshalIndent(config, "", "  ")
// 	if err != nil {
// 		fmt.Println("Error serializing config:", err)
// 		return
// 	}

// 	if err := os.WriteFile(configPath, data, 0600); err != nil {
// 		fmt.Println("Error writing config file:", err)
// 		return
// 	}
// }

// // createNewVault initializes a new encrypted vault
// func createNewVault() {
// 	// Check if vault already exists
// 	if _, err := os.Stat(config.VaultPath); !os.IsNotExist(err) {
// 		fmt.Println("Vault already exists. This will overwrite the existing vault.")
// 		fmt.Print("Are you sure? (y/n): ")
// 		var confirm string
// 		fmt.Scanln(&confirm)
// 		if strings.ToLower(confirm) != "y" {
// 			fmt.Println("Operation cancelled.")
// 			return
// 		}
// 	}

// 	// Get master password
// 	password, err := getNewPassword()
// 	if err != nil {
// 		fmt.Println("Error:", err)
// 		return
// 	}

// 	// Generate salt
// 	salt := make([]byte, 16)
// 	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
// 		fmt.Println("Error generating salt:", err)
// 		return
// 	}

// 	// Derive key from password
// 	var kdfParams map[string]int
// 	if config.KeyDerivation == "argon2id" {
// 		time := 1
// 		memory := 64 * 1024
// 		threads := 4
// 		kdfParams = map[string]int{
// 			"time":    time,
// 			"memory":  memory,
// 			"threads": threads,
// 		}
// 		masterKey = argon2.IDKey([]byte(password), salt, uint32(time), uint32(memory), uint8(threads), 32)
// 	} else {
// 		iterations := 600000 // High iteration count for security
// 		kdfParams = map[string]int{
// 			"iterations": iterations,
// 		}
// 		masterKey = pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)
// 	}

// 	// Create empty vault
// 	secrets = []SecretEntry{}

// 	// Initialize vault with empty encrypted data
// 	nonce := make([]byte, 12) // GCM standard nonce size
// 	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
// 		fmt.Println("Error generating nonce:", err)
// 		return
// 	}

// 	vault := Vault{
// 		Salt:      base64.StdEncoding.EncodeToString(salt),
// 		Nonce:     base64.StdEncoding.EncodeToString(nonce),
// 		KDFType:   config.KeyDerivation,
// 		KDFParams: kdfParams,
// 		Version:   Version,
// 	}

// 	// Encrypt empty data
// 	encryptedData, err := encryptVault(secrets, masterKey, nonce)
// 	if err != nil {
// 		fmt.Println("Error encrypting vault:", err)
// 		return
// 	}
// 	vault.Data = encryptedData

// 	// Save vault to file
// 	vaultData, err := json.MarshalIndent(vault, "", "  ")
// 	if err != nil {
// 		fmt.Println("Error serializing vault:", err)
// 		return
// 	}

// 	if err := os.WriteFile(config.VaultPath, vaultData, 0600); err != nil {
// 		fmt.Println("Error writing vault file:", err)
// 		return
// 	}

// 	isUnlocked = true
// 	fmt.Println("New vault created and unlocked successfully!")
// }

// // unlockVault attempts to unlock the vault with the provided master password
// func unlockVault() {
// 	// Check if vault exists
// 	if _, err := os.Stat(config.VaultPath); os.IsNotExist(err) {
// 		fmt.Println("No vault found. Please create a new vault first.")
// 		return
// 	}

// 	// Read vault file
// 	vaultData, err := os.ReadFile(config.VaultPath)
// 	if err != nil {
// 		fmt.Println("Error reading vault file:", err)
// 		return
// 	}

// 	var vault Vault
// 	if err := json.Unmarshal(vaultData, &vault); err != nil {
// 		fmt.Println("Error parsing vault file:", err)
// 		return
// 	}

// 	// Get master password
// 	fmt.Print("Enter master password: ")
// 	password, err := term.ReadPassword(int(syscall.Stdin))
// 	fmt.Println()
// 	if err != nil {
// 		fmt.Println("Error reading password:", err)
// 		return
// 	}

// 	// Decode salt
// 	salt, err := base64.StdEncoding.DecodeString(vault.Salt)
// 	if err != nil {
// 		fmt.Println("Error decoding salt:", err)
// 		return
// 	}

// 	// Derive key from password using the stored KDF
// 	if vault.KDFType == "argon2id" {
// 		time := vault.KDFParams["time"]
// 		memory := vault.KDFParams["memory"]
// 		threads := vault.KDFParams["threads"]
// 		masterKey = argon2.IDKey(password, salt, uint32(time), uint32(memory), uint8(threads), 32)
// 	} else {
// 		// Fallback to PBKDF2
// 		iterations := vault.KDFParams["iterations"]
// 		masterKey = pbkdf2.Key(password, salt, iterations, 32, sha256.New)
// 	}

// 	// Decode nonce
// 	nonce, err := base64.StdEncoding.DecodeString(vault.Nonce)
// 	if err != nil {
// 		fmt.Println("Error decoding nonce:", err)
// 		return
// 	}

// 	// Decrypt vault
// 	decryptedSecrets, err := decryptVault(vault.Data, masterKey, nonce)
// 	if err != nil {
// 		fmt.Println("Invalid password or corrupt vault. Please try again.")
// 		return
// 	}

// 	secrets = decryptedSecrets
// 	isUnlocked = true
// 	config.LastAccessTime = time.Now()
// 	saveConfig()
// 	fmt.Println("Vault unlocked successfully!")
// }

// // encryptVault encrypts the secrets data with the master key
// func encryptVault(secrets []SecretEntry, key []byte, nonce []byte) (string, error) {
// 	// Convert secrets to JSON
// 	plaintext, err := json.Marshal(secrets)
// 	if err != nil {
// 		return "", err
// 	}

// 	// Create cipher
// 	block, err := aes.NewCipher(key)
// 	if err != nil {
// 		return "", err
// 	}

// 	// GCM mode provides authenticated encryption
// 	aesgcm, err := cipher.NewGCM(block)
// 	if err != nil {
// 		return "", err
// 	}

// 	// Encrypt and authenticate plaintext
// 	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

// 	// Encode as base64
// 	return base64.StdEncoding.EncodeToString(ciphertext), nil
// }

// // decryptVault decrypts the vault data with the master key
// func decryptVault(encryptedData string, key []byte, nonce []byte) ([]SecretEntry, error) {
// 	// Decode from base64
// 	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Create cipher
// 	block, err := aes.NewCipher(key)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// GCM mode for authenticated decryption
// 	aesgcm, err := cipher.NewGCM(block)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Decrypt and verify
// 	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Parse decrypted data
// 	var decryptedSecrets []SecretEntry
// 	if err := json.Unmarshal(plaintext, &decryptedSecrets); err != nil {
// 		return nil, err
// 	}

// 	return decryptedSecrets, nil
// }

// // saveVault encrypts and saves the current secrets to disk
// func saveVault() error {
// 	// Read current vault to get encryption parameters
// 	vaultData, err := os.ReadFile(config.VaultPath)
// 	if err != nil {
// 		return err
// 	}

// 	var vault Vault
// 	if err := json.Unmarshal(vaultData, &vault); err != nil {
// 		return err
// 	}

// 	// Decode nonce
// 	nonce, err := base64.StdEncoding.DecodeString(vault.Nonce)
// 	if err != nil {
// 		return err
// 	}

// 	// Encrypt updated secrets
// 	encryptedData, err := encryptVault(secrets, masterKey, nonce)
// 	if err != nil {
// 		return err
// 	}

// 	// Update vault
// 	vault.Data = encryptedData

// 	// Save updated vault
// 	updatedVaultData, err := json.MarshalIndent(vault, "", "  ")
// 	if err != nil {
// 		return err
// 	}

// 	return os.WriteFile(config.VaultPath, updatedVaultData, 0600)
// }

// // generateID creates a unique ID for a new secret
// func generateID() string {
// 	b := make([]byte, 16)
// 	_, err := rand.Read(b)
// 	if err != nil {
// 		return fmt.Sprintf("%d", time.Now().UnixNano())
// 	}
// 	return fmt.Sprintf("%x", b)
// }

// // listSecrets displays all stored secrets
// func listSecrets() {
// 	if len(secrets) == 0 {
// 		fmt.Println("No secrets stored.")
// 		return
// 	}

// 	fmt.Printf("\n%-20s %-30s %-20s\n", "ID", "TITLE", "USERNAME")
// 	fmt.Println(strings.Repeat("-", 70))

// 	for i, s := range secrets {
// 		fmt.Printf("%-20s %-30s %-20s\n", fmt.Sprintf("%d", i+1), s.Title, s.Username)
// 	}

// 	fmt.Println("\nPress Enter to continue...")
// 	bufio.NewReader(os.Stdin).ReadString('\n')
// }

// // addSecret creates and adds a new secret to the vault
// func addSecret() {
// 	secret := SecretEntry{
// 		ID:           generateID(),
// 		CreatedAt:    time.Now(),
// 		ModifiedAt:   time.Now(),
// 		LastAccessed: time.Now(),
// 	}

// 	reader := bufio.NewReader(os.Stdin)

// 	fmt.Print("Title: ")
// 	title, _ := reader.ReadString('\n')
// 	secret.Title = strings.TrimSpace(title)

// 	fmt.Print("Username: ")
// 	username, _ := reader.ReadString('\n')
// 	secret.Username = strings.TrimSpace(username)

// 	fmt.Print("Password (leave empty to generate): ")
// 	password, _ := reader.ReadString('\n')
// 	password = strings.TrimSpace(password)
// 	if password == "" {
// 		secret.Password = generatePassword()
// 		fmt.Println("Generated password:", secret.Password)
// 	} else {
// 		secret.Password = password
// 	}

// 	fmt.Print("URL: ")
// 	url, _ := reader.ReadString('\n')
// 	secret.URL = strings.TrimSpace(url)

// 	fmt.Print("Notes: ")
// 	notes, _ := reader.ReadString('\n')
// 	secret.Notes = strings.TrimSpace(notes)

// 	secrets = append(secrets, secret)

// 	if err := saveVault(); err != nil {
// 		fmt.Println("Error saving vault:", err)
// 		return
// 	}

// 	fmt.Println("Secret added successfully!")
// }

// // viewSecret displays a specific secret
// func viewSecret() {
// 	if len(secrets) == 0 {
// 		fmt.Println("No secrets stored.")
// 		return
// 	}

// 	fmt.Print("Enter secret number: ")
// 	var index int
// 	if _, err := fmt.Scanln(&index); err != nil {
// 		fmt.Println("Invalid input")
// 		return
// 	}

// 	if index < 1 || index > len(secrets) {
// 		fmt.Println("Invalid secret number")
// 		return
// 	}

// 	secret := secrets[index-1]
// 	secret.LastAccessed = time.Now()
// 	secrets[index-1] = secret

// 	if err := saveVault(); err != nil {
// 		fmt.Println("Error updating access time:", err)
// 	}

// 	fmt.Println("\nSecret Details:")
// 	fmt.Println("Title:", secret.Title)
// 	fmt.Println("Username:", secret.Username)
// 	fmt.Println("Password:", secret.Password)
// 	fmt.Println("URL:", secret.URL)
// 	fmt.Println("Notes:", secret.Notes)
// 	fmt.Println("Created:", secret.CreatedAt.Format(time.RFC1123))
// 	fmt.Println("Last Modified:", secret.ModifiedAt.Format(time.RFC1123))
// 	fmt.Println("Last Accessed:", secret.LastAccessed.Format(time.RFC1123))

// 	fmt.Println("\nPress Enter to continue...")
// 	bufio.NewReader(os.Stdin).ReadString('\n')
// }

// // editSecret modifies an existing secret
// func editSecret() {
// 	if len(secrets) == 0 {
// 		fmt.Println("No secrets stored.")
// 		return
// 	}

// 	fmt.Print("Enter secret number to edit: ")
// 	var index int
// 	if _, err := fmt.Scanln(&index); err != nil {
// 		fmt.Println("Invalid input")
// 		return
// 	}

// 	if index < 1 || index > len(secrets) {
// 		fmt.Println("Invalid secret number")
// 		return
// 	}

// 	secret := secrets[index-1]
// 	reader := bufio.NewReader(os.Stdin)

// 	fmt.Printf("Title [%s]: ", secret.Title)
// 	title, _ := reader.ReadString('\n')
// 	title = strings.TrimSpace(title)
// 	if title != "" {
// 		secret.Title = title
// 	}

// 	fmt.Printf("Username [%s]: ", secret.Username)
// 	username, _ := reader.ReadString('\n')
// 	username = strings.TrimSpace(username)
// 	if username != "" {
// 		secret.Username = username
// 	}

// 	fmt.Print("Password (leave empty to keep current, type 'generate' for new): ")
// 	password, _ := reader.ReadString('\n')
// 	password = strings.TrimSpace(password)
// 	if password == "generate" {
// 		secret.Password = generatePassword()
// 		fmt.Println("Generated password:", secret.Password)
// 	} else if password != "" {
// 		secret.Password = password
// 	}

// 	fmt.Printf("URL [%s]: ", secret.URL)
// 	url, _ := reader.ReadString('\n')
// 	url = strings.TrimSpace(url)
// 	if url != "" {
// 		secret.URL = url
// 	}

// 	fmt.Printf("Notes [%s]: ", secret.Notes)
// 	notes, _ := reader.ReadString('\n')
// 	notes = strings.TrimSpace(notes)
// 	if notes != "" {
// 		secret.Notes = notes
// 	}

// 	secret.ModifiedAt = time.Now()
// 	secrets[index-1] = secret

// 	if err := saveVault(); err != nil {
// 		fmt.Println("Error saving vault:", err)
// 		return
// 	}

// 	fmt.Println("Secret updated successfully!")
// }

// // deleteSecret removes a secret from the vault
// func deleteSecret() {
// 	if len(secrets) == 0 {
// 		fmt.Println("No secrets stored.")
// 		return
// 	}

// 	fmt.Print("Enter secret number to delete: ")
// 	var index int
// 	if _, err := fmt.Scanln(&index); err != nil {
// 		fmt.Println("Invalid input")
// 		return
// 	}

// 	if index < 1 || index > len(secrets) {
// 		fmt.Println("Invalid secret number")
// 		return
// 	}

// 	fmt.Printf("Are you sure you want to delete '%s'? (y/n): ", secrets[index-1].Title)
// 	var confirm string
// 	fmt.Scanln(&confirm)
// 	if strings.ToLower(confirm) != "y" {
// 		fmt.Println("Deletion cancelled.")
// 		return
// 	}

// 	// Remove the secret
// 	secrets = append(secrets[:index-1], secrets[index:]...)

// 	if err := saveVault(); err != nil {
// 		fmt.Println("Error saving vault:", err)
// 		return
// 	}

// 	fmt.Println("Secret deleted successfully!")
// }

// // generatePassword creates a strong random password
// func generatePassword() string {
// 	const (
// 		uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
// 		lowercaseChars = "abcdefghijklmnopqrstuvwxyz"
// 		digitChars     = "0123456789"
// 		specialChars   = "!@#$%^&*()-_=+[]{}|;:,.<>?"
// 	)

// 	// Default settings for a strong password
// 	length := 16
// 	useUppercase := true
// 	useLowercase := true
// 	useDigits := true
// 	useSpecial := true

// 	// Get user preferences
// 	fmt.Println("\nPassword Generator:")
// 	fmt.Printf("Length [%d]: ", length)
// 	var input string
// 	fmt.Scanln(&input)
// 	if input != "" {
// 		if val, err := fmt.Sscanf(input, "%d", &length); err != nil || val != 1 {
// 			fmt.Println("Invalid input, using default length")
// 			length = 16
// 		}
// 	}

// 	if length < 8 {
// 		fmt.Println("Warning: Short passwords are insecure. Using minimum length of 8.")
// 		length = 8
// 	}

// 	fmt.Print("Include uppercase letters? (Y/n): ")
// 	fmt.Scanln(&input)
// 	useUppercase = input == "" || strings.ToLower(input) == "y"

// 	fmt.Print("Include lowercase letters? (Y/n): ")
// 	fmt.Scanln(&input)
// 	useLowercase = input == "" || strings.ToLower(input) == "y"

// 	fmt.Print("Include digits? (Y/n): ")
// 	fmt.Scanln(&input)
// 	useDigits = input == "" || strings.ToLower(input) == "y"

// 	fmt.Print("Include special characters? (Y/n): ")
// 	fmt.Scanln(&input)
// 	useSpecial = input == "" || strings.ToLower(input) == "y"

// 	// Ensure at least one character type is selected
// 	if !useUppercase && !useLowercase && !useDigits && !useSpecial {
// 		fmt.Println("At least one character type must be selected. Using lowercase letters.")
// 		useLowercase = true
// 	}

// 	// Build character set
// 	var charSet string
// 	if useUppercase {
// 		charSet += uppercaseChars
// 	}
// 	if useLowercase {
// 		charSet += lowercaseChars
// 	}
// 	if useDigits {
// 		charSet += digitChars
// 	}
// 	if useSpecial {
// 		charSet += specialChars
// 	}

// 	// Generate password
// 	password := make([]byte, length)
// 	for i := 0; i < length; i++ {
// 		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charSet))))
// 		if err != nil {
// 			// Fallback to less secure method if crypto/rand fails
// 			password[i] = charSet[time.Now().Nanosecond()%len(charSet)]
// 		} else {
// 			password[i] = charSet[idx.Int64()]
// 		}
// 	}

// 	// Ensure password includes at least one of each selected character type
// 	ensurePasswordStrength(password, useUppercase, useLowercase, useDigits, useSpecial)

// 	return string(password)
// }

// // ensurePasswordStrength makes sure a password has at least one of each required character type
// func ensurePasswordStrength(password []byte, useUpper, useLower, useDigits, useSpecial bool) {
// 	const (
// 		uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
// 		lowercaseChars = "abcdefghijklmnopqrstuvwxyz"
// 		digitChars     = "0123456789"
// 		specialChars   = "!@#$%^&*()-_=+[]{}|;:,.<>?"
// 	)

// 	hasUpper := false
// 	hasLower := false
// 	hasDigit := false
// 	hasSpecial := false

// 	for _, c := range password {
// 		if strings.ContainsRune(uppercaseChars, rune(c)) {
// 			hasUpper = true
// 		} else if strings.ContainsRune(lowercaseChars, rune(c)) {
// 			hasLower = true
// 		} else if strings.ContainsRune(digitChars, rune(c)) {
// 			hasDigit = true
// 		} else if strings.ContainsRune(specialChars, rune(c)) {
// 			hasSpecial = true
// 		}
// 	}

// 	// Helper function for secure random int
// 	getRandomIndex := func(max int) int {
// 		if max <= 0 {
// 			return 0
// 		}
// 		n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
// 		if err != nil {
// 			// Fallback to a less secure but functional option in case of error
// 			return int(time.Now().UnixNano() % int64(max))
// 		}
// 		return int(n.Int64())
// 	}

// 	// Replace some characters if needed
// 	if useUpper && !hasUpper {
// 		idx := getRandomIndex(len(password))
// 		charIdx := getRandomIndex(len(uppercaseChars))
// 		password[idx] = uppercaseChars[charIdx]
// 	}
// 	if useLower && !hasLower {
// 		idx := getRandomIndex(len(password))
// 		charIdx := getRandomIndex(len(lowercaseChars))
// 		password[idx] = lowercaseChars[charIdx]
// 	}
// 	if useDigits && !hasDigit {
// 		idx := getRandomIndex(len(password))
// 		charIdx := getRandomIndex(len(digitChars))
// 		password[idx] = digitChars[charIdx]
// 	}
// 	if useSpecial && !hasSpecial {
// 		idx := getRandomIndex(len(password))
// 		charIdx := getRandomIndex(len(specialChars))
// 		password[idx] = specialChars[charIdx]
// 	}
// }

// // getNewPassword securely gets a new password from user input
// func getNewPassword() (string, error) {
// 	fmt.Print("Enter new master password: ")
// 	password1, err := term.ReadPassword(int(syscall.Stdin))
// 	fmt.Println()
// 	if err != nil {
// 		return "", err
// 	}

// 	if len(password1) < 8 {
// 		return "", errors.New("password too short (minimum 8 characters)")
// 	}

// 	fmt.Print("Confirm password: ")
// 	password2, err := term.ReadPassword(int(syscall.Stdin))
// 	fmt.Println()
// 	if err != nil {
// 		return "", err
// 	}

// 	if string(password1) != string(password2) {
// 		return "", errors.New("passwords do not match")
// 	}

// 	return string(password1), nil
// }

// // changeConfiguration allows the user to modify app settings
// func changeConfiguration() {
// 	fmt.Println("\nConfiguration Settings:")

// 	fmt.Printf("1. Vault Path [%s]\n", config.VaultPath)
// 	fmt.Printf("2. Auto-lock Timeout [%d minutes]\n", config.Timeout)
// 	fmt.Printf("3. Key Derivation Function [%s]\n", config.KeyDerivation)
// 	fmt.Print("\nSelect setting to change (0 to cancel): ")

// 	var choice int
// 	fmt.Scanln(&choice)

// 	switch choice {
// 	case 0:
// 		return
// 	case 1:
// 		fmt.Printf("Current vault path: %s\n", config.VaultPath)
// 		fmt.Print("Enter new path (or leave empty to cancel): ")
// 		reader := bufio.NewReader(os.Stdin)
// 		path, _ := reader.ReadString('\n')
// 		path = strings.TrimSpace(path)
// 		if path != "" {
// 			// Expand home directory if needed
// 			if strings.HasPrefix(path, "~/") {
// 				homeDir, err := os.UserHomeDir()
// 				if err == nil {
// 					path = filepath.Join(homeDir, path[2:])
// 				}
// 			}
// 			config.VaultPath = path
// 			saveConfig()
// 			fmt.Println("Vault path updated.")
// 		}
// 	case 2:
// 		fmt.Printf("Current timeout: %d minutes\n", config.Timeout)
// 		fmt.Print("Enter new timeout in minutes (0 to disable): ")
// 		var timeout int
// 		if _, err := fmt.Scanln(&timeout); err == nil && timeout >= 0 {
// 			config.Timeout = timeout
// 			saveConfig()
// 			fmt.Println("Timeout updated.")
// 		} else {
// 			fmt.Println("Invalid input.")
// 		}
// 	case 3:
// 		fmt.Printf("Current KDF: %s\n", config.KeyDerivation)
// 		fmt.Println("Available options:")
// 		fmt.Println("1. argon2id (recommended)")
// 		fmt.Println("2. pbkdf2")
// 		fmt.Print("Select KDF (or 0 to cancel): ")
// 		var kdfChoice int
// 		if _, err := fmt.Scanln(&kdfChoice); err == nil {
// 			switch kdfChoice {
// 			case 1:
// 				config.KeyDerivation = "argon2id"
// 				saveConfig()
// 				fmt.Println("KDF updated to argon2id.")
// 			case 2:
// 				config.KeyDerivation = "pbkdf2"
// 				saveConfig()
// 				fmt.Println("KDF updated to pbkdf2.")
// 			case 0:
// 				return
// 			default:
// 				fmt.Println("Invalid choice.")
// 			}
// 		} else {
// 			fmt.Println("Invalid input.")
// 		}
// 	default:
// 		fmt.Println("Invalid choice.")
// 	}
// }

// // changeMasterPassword changes the master password of the vault
// func changeMasterPassword() {
// 	// Get new password
// 	newPassword, err := getNewPassword()
// 	if err != nil {
// 		fmt.Println("Error:", err)
// 		return
// 	}

// 	// Read current vault
// 	vaultData, err := os.ReadFile(config.VaultPath)
// 	if err != nil {
// 		fmt.Println("Error reading vault file:", err)
// 		return
// 	}

// 	var vault Vault
// 	if err := json.Unmarshal(vaultData, &vault); err != nil {
// 		fmt.Println("Error parsing vault file:", err)
// 		return
// 	}

// 	// Generate new salt
// 	salt := make([]byte, 16)
// 	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
// 		fmt.Println("Error generating salt:", err)
// 		return
// 	}

// 	// Generate new nonce
// 	nonce := make([]byte, 12)
// 	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
// 		fmt.Println("Error generating nonce:", err)
// 		return
// 	}

// 	// Derive new key from password
// 	var newKey []byte
// 	var kdfParams map[string]int

// 	if config.KeyDerivation == "argon2id" {
// 		time := 1
// 		memory := 64 * 1024
// 		threads := 4
// 		kdfParams = map[string]int{
// 			"time":    time,
// 			"memory":  memory,
// 			"threads": threads,
// 		}
// 		newKey = argon2.IDKey([]byte(newPassword), salt, uint32(time), uint32(memory), uint8(threads), 32)
// 	} else {
// 		iterations := 600000
// 		kdfParams = map[string]int{
// 			"iterations": iterations,
// 		}
// 		newKey = pbkdf2.Key([]byte(newPassword), salt, iterations, 32, sha256.New)
// 	}

// 	// Encrypt secrets with new key
// 	encryptedData, err := encryptVault(secrets, newKey, nonce)
// 	if err != nil {
// 		fmt.Println("Error encrypting vault:", err)
// 		return
// 	}

// 	// Update vault
// 	vault.Salt = base64.StdEncoding.EncodeToString(salt)
// 	vault.Nonce = base64.StdEncoding.EncodeToString(nonce)
// 	vault.Data = encryptedData
// 	vault.KDFType = config.KeyDerivation
// 	vault.KDFParams = kdfParams

// 	// Save updated vault
// 	updatedVaultData, err := json.MarshalIndent(vault, "", "  ")
// 	if err != nil {
// 		fmt.Println("Error serializing vault:", err)
// 		return
// 	}

// 	if err := os.WriteFile(config.VaultPath, updatedVaultData, 0600); err != nil {
// 		fmt.Println("Error writing vault file:", err)
// 		return
// 	}

// 	// Update master key
// 	masterKey = newKey
// 	fmt.Println("Master password changed successfully!")
// }

// // exportSecrets exports vault contents in a readable format
// func exportSecrets() {
// 	if !isUnlocked {
// 		fmt.Println("Vault must be unlocked to export secrets.")
// 		return
// 	}

// 	fmt.Println("WARNING: Exporting secrets will create an unencrypted file.")
// 	fmt.Print("Are you sure you want to continue? (y/n): ")
// 	var confirm string
// 	fmt.Scanln(&confirm)
// 	if strings.ToLower(confirm) != "y" {
// 		fmt.Println("Export cancelled.")
// 		return
// 	}

// 	fmt.Print("Enter export filename: ")
// 	reader := bufio.NewReader(os.Stdin)
// 	filename, _ := reader.ReadString('\n')
// 	filename = strings.TrimSpace(filename)
// 	if filename == "" {
// 		filename = "secretkeeper_export.json"
// 	}

// 	// Convert to JSON
// 	data, err := json.MarshalIndent(secrets, "", "  ")
// 	if err != nil {
// 		fmt.Println("Error serializing secrets:", err)
// 		return
// 	}

// 	// Write to file
// 	if err := os.WriteFile(filename, data, 0600); err != nil {
// 		fmt.Println("Error writing export file:", err)
// 		return
// 	}

// 	fmt.Printf("Secrets exported to %s\n", filename)
// }

// // importSecrets imports secrets from a JSON file
// func importSecrets() {
// 	if !isUnlocked {
// 		fmt.Println("Vault must be unlocked to import secrets.")
// 		return
// 	}

// 	fmt.Print("Enter import filename: ")
// 	reader := bufio.NewReader(os.Stdin)
// 	filename, _ := reader.ReadString('\n')
// 	filename = strings.TrimSpace(filename)

// 	// Read file
// 	data, err := os.ReadFile(filename)
// 	if err != nil {
// 		fmt.Println("Error reading import file:", err)
// 		return
// 	}

// 	// Parse JSON
// 	var importedSecrets []SecretEntry
// 	if err := json.Unmarshal(data, &importedSecrets); err != nil {
// 		fmt.Println("Error parsing import file:", err)
// 		return
// 	}

// 	fmt.Printf("Found %d secrets. Import mode:\n", len(importedSecrets))
// 	fmt.Println("1. Replace all existing secrets")
// 	fmt.Println("2. Merge (skip duplicates)")
// 	fmt.Println("3. Merge (overwrite duplicates)")
// 	fmt.Print("Select mode: ")

// 	var mode int
// 	if _, err := fmt.Scanln(&mode); err != nil {
// 		fmt.Println("Invalid input, cancelling import.")
// 		return
// 	}

// 	switch mode {
// 	case 1:
// 		secrets = importedSecrets
// 	case 2, 3:
// 		// Create map of existing secrets by ID
// 		existingMap := make(map[string]int)
// 		for i, s := range secrets {
// 			existingMap[s.ID] = i
// 		}

// 		// Process imported secrets
// 		for _, s := range importedSecrets {
// 			if idx, exists := existingMap[s.ID]; exists {
// 				if mode == 3 {
// 					// Overwrite with imported
// 					secrets[idx] = s
// 				}
// 				// Mode 2: Skip duplicates (do nothing)
// 			} else {
// 				// Add new secret
// 				secrets = append(secrets, s)
// 			}
// 		}
// 	default:
// 		fmt.Println("Invalid mode, cancelling import.")
// 		return
// 	}

// 	// Save updated vault
// 	if err := saveVault(); err != nil {
// 		fmt.Println("Error saving vault:", err)
// 		return
// 	}

// 	fmt.Println("Secrets imported successfully!")
// }

// // searchSecrets searches for secrets by keyword
// func searchSecrets() {
// 	if len(secrets) == 0 {
// 		fmt.Println("No secrets stored.")
// 		return
// 	}

// 	fmt.Print("Enter search term: ")
// 	reader := bufio.NewReader(os.Stdin)
// 	term, _ := reader.ReadString('\n')
// 	term = strings.ToLower(strings.TrimSpace(term))

// 	if term == "" {
// 		fmt.Println("Empty search term, cancelling search.")
// 		return
// 	}

// 	results := []SecretEntry{}
// 	for _, s := range secrets {
// 		if strings.Contains(strings.ToLower(s.Title), term) ||
// 			strings.Contains(strings.ToLower(s.Username), term) ||
// 			strings.Contains(strings.ToLower(s.URL), term) ||
// 			strings.Contains(strings.ToLower(s.Notes), term) {
// 			results = append(results, s)
// 		}
// 	}

// 	if len(results) == 0 {
// 		fmt.Println("No matching secrets found.")
// 		return
// 	}

// 	fmt.Printf("\nFound %d matching secrets:\n", len(results))
// 	fmt.Printf("%-5s %-30s %-20s\n", "ID", "TITLE", "USERNAME")
// 	fmt.Println(strings.Repeat("-", 60))

// 	for i, s := range results {
// 		fmt.Printf("%-5d %-30s %-20s\n", i+1, s.Title, s.Username)
// 	}

// 	// Allow viewing a result
// 	fmt.Print("\nEnter number to view (0 to cancel): ")
// 	var choice int
// 	if _, err := fmt.Scanln(&choice); err != nil || choice < 1 || choice > len(results) {
// 		return
// 	}

// 	// Display the selected secret
// 	secret := results[choice-1]
// 	fmt.Println("\nSecret Details:")
// 	fmt.Println("Title:", secret.Title)
// 	fmt.Println("Username:", secret.Username)
// 	fmt.Println("Password:", secret.Password)
// 	fmt.Println("URL:", secret.URL)
// 	fmt.Println("Notes:", secret.Notes)

// 	fmt.Println("\nPress Enter to continue...")
// 	bufio.NewReader(os.Stdin).ReadString('\n')
// }

// // checkVaultHealth analyzes the vault for security issues
// func checkVaultHealth() {
// 	if len(secrets) == 0 {
// 		fmt.Println("No secrets stored. Health check skipped.")
// 		return
// 	}

// 	issues := []string{}
// 	warnings := []string{}

// 	// Check for duplicate passwords
// 	passwordMap := make(map[string][]string)
// 	for _, s := range secrets {
// 		if s.Password != "" {
// 			passwordMap[s.Password] = append(passwordMap[s.Password], s.Title)
// 		}
// 	}

// 	for _, titles := range passwordMap {
// 		if len(titles) > 1 {
// 			issues = append(issues, fmt.Sprintf("Duplicate password used in %d entries: %s",
// 				len(titles), strings.Join(titles, ", ")))
// 		}
// 	}

// 	// Check for weak passwords
// 	for _, s := range secrets {
// 		if len(s.Password) < 8 {
// 			issues = append(issues, fmt.Sprintf("Weak password (too short) in entry: %s", s.Title))
// 		}

// 		// Check password strength (very basic check)
// 		hasUpper := false
// 		hasLower := false
// 		hasDigit := false
// 		hasSpecial := false

// 		for _, c := range s.Password {
// 			if unicode.IsUpper(c) {
// 				hasUpper = true
// 			} else if unicode.IsLower(c) {
// 				hasLower = true
// 			} else if unicode.IsDigit(c) {
// 				hasDigit = true
// 			} else {
// 				hasSpecial = true
// 			}
// 		}

// 		if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
// 			warnings = append(warnings, fmt.Sprintf("Password could be stronger in entry: %s", s.Title))
// 		}
// 	}

// 	// Check for old entries
// 	now := time.Now()
// 	for _, s := range secrets {
// 		if now.Sub(s.ModifiedAt) > 180*24*time.Hour {
// 			warnings = append(warnings, fmt.Sprintf("Password not updated in over 6 months: %s", s.Title))
// 		}
// 	}

// 	// Print report
// 	fmt.Println("\nVault Health Check")
// 	fmt.Println("=================")
// 	fmt.Printf("Total entries: %d\n\n", len(secrets))

// 	if len(issues) == 0 {
// 		fmt.Println("No critical issues found! 🎉")
// 	} else {
// 		fmt.Printf("Critical Issues (%d):\n", len(issues))
// 		for i, issue := range issues {
// 			fmt.Printf("%d. %s\n", i+1, issue)
// 		}
// 	}

// 	fmt.Println()

// 	if len(warnings) == 0 {
// 		fmt.Println("No warnings found! 🎉")
// 	} else {
// 		fmt.Printf("Warnings (%d):\n", len(warnings))
// 		for i, warning := range warnings {
// 			fmt.Printf("%d. %s\n", i+1, warning)
// 		}
// 	}

// 	fmt.Println("\nPress Enter to continue...")
// 	bufio.NewReader(os.Stdin).ReadString('\n')
// }

// // backupVault creates a backup of the current vault
// func backupVault() {
// 	if _, err := os.Stat(config.VaultPath); os.IsNotExist(err) {
// 		fmt.Println("No vault found to backup.")
// 		return
// 	}

// 	// Create backup filename with timestamp
// 	backupDir := filepath.Join(defaultPath, "backups")
// 	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
// 		if err := os.MkdirAll(backupDir, 0700); err != nil {
// 			fmt.Println("Error creating backup directory:", err)
// 			return
// 		}
// 	}

// 	timestamp := time.Now().Format("20060102_150405")
// 	backupPath := filepath.Join(backupDir, fmt.Sprintf("vault_backup_%s.json", timestamp))

// 	// Read vault file
// 	vaultData, err := os.ReadFile(config.VaultPath)
// 	if err != nil {
// 		fmt.Println("Error reading vault file:", err)
// 		return
// 	}

// 	// Write backup file
// 	if err := os.WriteFile(backupPath, vaultData, 0600); err != nil {
// 		fmt.Println("Error writing backup file:", err)
// 		return
// 	}

// 	fmt.Printf("Vault successfully backed up to %s\n", backupPath)
// }

// // restoreVault restores the vault from a backup
// func restoreVault() {
// 	backupDir := filepath.Join(defaultPath, "backups")
// 	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
// 		fmt.Println("No backups found.")
// 		return
// 	}

// 	// List available backups
// 	files, err := os.ReadDir(backupDir)
// 	if err != nil {
// 		fmt.Println("Error reading backup directory:", err)
// 		return
// 	}

// 	backups := []string{}
// 	for _, f := range files {
// 		if !f.IsDir() && strings.HasPrefix(f.Name(), "vault_backup_") {
// 			backups = append(backups, f.Name())
// 		}
// 	}

// 	if len(backups) == 0 {
// 		fmt.Println("No backups found.")
// 		return
// 	}

// 	fmt.Println("Available backups:")
// 	for i, backup := range backups {
// 		fmt.Printf("%d. %s\n", i+1, backup)
// 	}

// 	fmt.Print("Select backup to restore (0 to cancel): ")
// 	var choice int
// 	if _, err := fmt.Scanln(&choice); err != nil || choice < 1 || choice > len(backups) {
// 		if choice != 0 {
// 			fmt.Println("Invalid choice.")
// 		}
// 		return
// 	}

// 	backupPath := filepath.Join(backupDir, backups[choice-1])

// 	// Confirm restoration
// 	fmt.Println("WARNING: Restoring will overwrite your current vault.")
// 	fmt.Print("Are you sure you want to continue? (y/n): ")
// 	var confirm string
// 	fmt.Scanln(&confirm)
// 	if strings.ToLower(confirm) != "y" {
// 		fmt.Println("Restoration cancelled.")
// 		return
// 	}

// 	// Read backup file
// 	backupData, err := os.ReadFile(backupPath)
// 	if err != nil {
// 		fmt.Println("Error reading backup file:", err)
// 		return
// 	}

// 	// Write to vault file
// 	if err := os.WriteFile(config.VaultPath, backupData, 0600); err != nil {
// 		fmt.Println("Error writing vault file:", err)
// 		return
// 	}

// 	// Reset vault state
// 	isUnlocked = false
// 	masterKey = nil
// 	secrets = nil

// 	fmt.Println("Vault restored successfully! Please unlock to continue.")
// }
