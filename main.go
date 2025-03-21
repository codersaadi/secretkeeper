package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// SecretEntry represents a stored credential
type SecretEntry struct {
	ID           string    `json:"id"`
	Title        string    `json:"title"`
	Username     string    `json:"username"`
	Password     string    `json:"password"`
	URL          string    `json:"url"`
	Notes        string    `json:"notes"`
	CreatedAt    time.Time `json:"created_at"`
	ModifiedAt   time.Time `json:"modified_at"`
	LastAccessed time.Time `json:"last_accessed"`
}

// Vault represents the encrypted password vault
type Vault struct {
	Salt       string         `json:"salt"`
	Nonce      string         `json:"nonce"`
	Data       string         `json:"data"`
	KDFType    string         `json:"kdf_type"` // "argon2id" or "pbkdf2"
	KDFParams  map[string]int `json:"kdf_params"`
	Iterations int            `json:"iterations"`
	Version    string         `json:"version"`
}

// Config represents application configuration
type Config struct {
	VaultPath      string    `json:"vault_path"`
	Timeout        int       `json:"timeout"`        // Auto logout time in minutes
	KeyDerivation  string    `json:"key_derivation"` // "argon2id" or "pbkdf2"
	LastAccessTime time.Time `json:"last_access_time"`
	APIPort        int       `json:"api_port"`
	JWTSecret      string    `json:"jwt_secret"`
	EnableTLS      bool      `json:"enable_tls"`
	CertFile       string    `json:"cert_file"`
	KeyFile        string    `json:"key_file"`
}

// Session represents an authenticated user session
type Session struct {
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// AuthRequest represents an authentication request
type AuthRequest struct {
	Password string `json:"password"`
}

// APIResponse represents a standardized API response
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// Global variables
var (
	config      Config
	secrets     []SecretEntry
	masterKey   []byte
	isUnlocked  bool
	configPath  string
	defaultPath string
	sessions    map[string]Session // Map of token to session
)

const (
	AppName    = "SecretKeeper"
	Version    = "2.0.0"
	ConfigFile = "config.json"
)

// CORSMiddleware adds CORS headers to every response
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers for all responses
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Process other requests
		next.ServeHTTP(w, r)
	})
}

func init() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("Error getting home directory:", err)
		os.Exit(1)
	}
	defaultPath = filepath.Join(homeDir, "."+strings.ToLower(AppName))
	configPath = filepath.Join(defaultPath, ConfigFile)

	// Create app directory if it doesn't exist
	if _, err := os.Stat(defaultPath); os.IsNotExist(err) {
		if err := os.MkdirAll(defaultPath, 0700); err != nil {
			fmt.Println("Error creating app directory:", err)
			os.Exit(1)
		}
	}

	// Initialize sessions map
	sessions = make(map[string]Session)

	// Load or create config
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Generate random JWT secret
		jwtSecret := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, jwtSecret); err != nil {
			fmt.Println("Error generating JWT secret:", err)
			os.Exit(1)
		}

		config = Config{
			VaultPath:     filepath.Join(defaultPath, "vault.json"),
			Timeout:       15,
			KeyDerivation: "argon2id", // Default to Argon2id
			APIPort:       3200,
			JWTSecret:     base64.StdEncoding.EncodeToString(jwtSecret),
			EnableTLS:     false,
		}
		saveConfig()
	} else {
		loadConfig()
	}

	// Clean up expired sessions every minute
	go func() {
		for {
			time.Sleep(1 * time.Minute)
			cleanExpiredSessions()
		}
	}()
}

// Global OPTIONS handler for preflight requests
func globalOptionsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusOK)
}

func main() {
	fmt.Printf("\n%s API Server v%s\n", AppName, Version)
	fmt.Println(strings.Repeat("=", 40))

	// Initialize router
	router := mux.NewRouter()

	// Apply CORS middleware to all routes
	router.Use(CORSMiddleware)

	// Add a global handler for OPTIONS requests
	router.Methods("OPTIONS").HandlerFunc(globalOptionsHandler)

	// API endpoints
	apiRouter := router.PathPrefix("/api").Subrouter()

	// Handle OPTIONS for the API endpoints
	apiRouter.Methods("OPTIONS").HandlerFunc(globalOptionsHandler)

	// Public routes
	apiRouter.HandleFunc("/auth", handleAuth).Methods("POST")
	apiRouter.HandleFunc("/init", handleInitVault).Methods("POST")
	apiRouter.HandleFunc("/health", handleHealthCheck).Methods("GET")

	// Protected routes (require authentication)
	protectedRouter := apiRouter.PathPrefix("").Subrouter()
	protectedRouter.Use(authMiddleware)

	protectedRouter.HandleFunc("/secrets", handleGetSecrets).Methods("GET")
	protectedRouter.HandleFunc("/secrets", handleAddSecret).Methods("POST")
	protectedRouter.HandleFunc("/secrets/{id}", handleGetSecret).Methods("GET")
	protectedRouter.HandleFunc("/secrets/{id}", handleUpdateSecret).Methods("PUT")
	protectedRouter.HandleFunc("/secrets/{id}", handleDeleteSecret).Methods("DELETE")
	protectedRouter.HandleFunc("/generate-password", handleGeneratePassword).Methods("GET")
	protectedRouter.HandleFunc("/vault/health", handleVaultHealth).Methods("GET")
	protectedRouter.HandleFunc("/vault/backup", handleBackupVault).Methods("POST")
	protectedRouter.HandleFunc("/vault/restore", handleRestoreVault).Methods("POST")
	protectedRouter.HandleFunc("/vault/change-password", handleChangeMasterPassword).Methods("POST")
	protectedRouter.HandleFunc("/logout", handleLogout).Methods("POST")

	// Admin routes
	adminRouter := apiRouter.PathPrefix("/admin").Subrouter()
	adminRouter.Use(authMiddleware)
	adminRouter.HandleFunc("/config", handleGetConfig).Methods("GET")
	adminRouter.HandleFunc("/config", handleUpdateConfig).Methods("PUT")

	// Start server
	serverAddr := fmt.Sprintf(":%d", 3200)
	fmt.Printf("Starting %s API server on %s\n", AppName, serverAddr)
	fmt.Printf("CORS enabled: Allowing requests from http://localhost:3000\n")

	if config.EnableTLS {
		log.Fatal(http.ListenAndServeTLS(serverAddr, config.CertFile, config.KeyFile, router))
	} else {
		log.Fatal(http.ListenAndServe(serverAddr, router))
	}
}
