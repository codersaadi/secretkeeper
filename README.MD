# SecretKeeper

SecretKeeper is a secure password vault application with a RESTful API for storing and managing sensitive credentials. Built in Go, it provides robust encryption, flexible configuration options, and comprehensive credential management features.

## Features

- **Secure Encryption**: AES-GCM encryption with Argon2id or PBKDF2 key derivation
- **Credential Management**: Store, retrieve, update, and delete credentials
- **Password Generator**: Create strong random passwords with customizable options
- **Security Analysis**: Check vault health for weak or duplicate passwords
- **Backup & Restore**: Create and manage vault backups
- **Session Management**: Secure token-based authentication with configurable timeout
- **TLS Support**: Optional TLS encryption for API connections

## API Endpoints

### Authentication
- `POST /api/auth`: Authenticate with the vault
- `POST /api/init`: Initialize a new vault
- `POST /api/logout`: Invalidate the current session

### Credentials
- `GET /api/secrets`: List all stored credentials
- `POST /api/secrets`: Add a new credential
- `GET /api/secrets/{id}`: Retrieve a specific credential
- `PUT /api/secrets/{id}`: Update a credential
- `DELETE /api/secrets/{id}`: Delete a credential

### Utilities
- `GET /api/generate-password`: Generate a secure random password
- `GET /api/vault/health`: Check vault security health
- `POST /api/vault/backup`: Create a vault backup
- `POST /api/vault/restore`: Restore from a backup
- `POST /api/vault/change-password`: Change the master password
- `GET /api/health`: Check service status

### Configuration
- `GET /api/admin/config`: View current configuration
- `PUT /api/admin/config`: Update configuration settings

## Installation

```bash
# Clone the repository
git clone https://github.com/codersaadi/secretkeeper.git

# Change to the directory
cd secretkeeper

# Build the application
go build -o secretkeeper

# Run the application
./secretkeeper
```

## Configuration

SecretKeeper automatically creates a configuration file at `~/.secretkeeper/config.json` with these default settings:

```json
{
  "vault_path": "~/.secretkeeper/vault.json",
  "timeout": 15,
  "key_derivation": "argon2id",
  "api_port": 3200,
  "enable_tls": false
}
```

You can modify these settings via the configuration API endpoint or by directly editing the config file.

## Security Features

- **Zero Knowledge Design**: Your master password is never stored
- **Strong Encryption**: AES-256 in GCM mode with authentication
- **Modern Key Derivation**: Argon2id (default) or PBKDF2 with SHA-256
- **Auto-Timeout**: Configurable session timeout for added security
- **Secure Password Generation**: Cryptographically secure random password generator
- **Security Health Checks**: Detection of weak or duplicate passwords

## Usage Examples

### Initialize a new vault

```bash
curl -X POST http://localhost:3200/api/init \
  -H "Content-Type: application/json" \
  -d '{"password": "your-strong-master-password"}'
```

### Authenticate

```bash
curl -X POST http://localhost:3200/api/auth \
  -H "Content-Type: application/json" \
  -d '{"password": "your-strong-master-password"}'
```

### Add a new credential

```bash
curl -X POST http://localhost:3200/api/secrets \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-session-token" \
  -d '{
    "title": "My Email",
    "username": "user@example.com",
    "password": "password123",
    "url": "https://mail.example.com",
    "notes": "Personal email account"
  }'
```

### Generate a password

```bash
curl -X GET "http://localhost:3200/api/generate-password?length=20&upper=true&lower=true&digits=true&special=true" \
  -H "Authorization: Bearer your-session-token"
```

## Dependencies

- [github.com/gorilla/mux](https://github.com/gorilla/mux): HTTP router
- [golang.org/x/crypto/argon2](https://golang.org/x/crypto/argon2): Argon2 key derivation
- [golang.org/x/crypto/pbkdf2](https://golang.org/x/crypto/pbkdf2): PBKDF2 key derivation

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.