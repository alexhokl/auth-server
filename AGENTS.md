# AGENTS.md - AI Coding Agent Guidelines

This document provides guidelines for AI coding agents working on the auth-server codebase.

## Project Overview

OAuth2/OpenID Connect authentication server with WebAuthn (FIDO2) support built in Go 1.21.

**Tech Stack:**
- **Framework:** Gin web framework
- **ORM:** GORM with PostgreSQL
- **Session/Token Storage:** Redis
- **OAuth2:** go-oauth2/oauth2
- **WebAuthn:** go-webauthn/webauthn
- **Configuration:** Viper (environment variables prefixed with `AUTH_`)

## Build/Lint/Test Commands

This project uses [Task](https://taskfile.dev/) (not Make) for task running.

| Command | Description |
|---------|-------------|
| `task build` | Build without output (validates compilation) |
| `task test` | Run all unit tests |
| `task run-debug` | Run with debug logs (starts DB containers) |
| `task run` | Run in release mode |
| `task swagger` | Generate Swagger documentation |
| `task swagger-format` | Format Swagger comments in code |
| `task tidy` | Run `go mod tidy` |
| `task up-db` | Start PostgreSQL and Redis containers |
| `task down` | Stop all Docker containers |

### Running a Single Test

```bash
# Run a specific test by name
go test -v -run TestSignUp ./server/...

# Run tests in a specific package
go test -v ./api/...

# Run with race detection
go test -race -v ./...
```

### Build Tags

Always use `-tags=nomsgpack` when building or running:
```bash
go build -tags=nomsgpack -o /dev/null
go run -tags=nomsgpack main.go
```

## Code Style Guidelines

### Import Organization

Group imports in this order, separated by blank lines:
1. Standard library
2. Internal packages (`github.com/alexhokl/auth-server/...`)
3. External packages

```go
import (
    "context"
    "log/slog"

    "github.com/alexhokl/auth-server/api"

    "github.com/gin-gonic/gin"
)
```

### Naming Conventions

- **Packages:** lowercase, single word (`api`, `db`, `store`, `server`)
- **Exported functions/types:** PascalCase (`SignUp`, `CreateClient`, `GetRouter`)
- **Unexported functions/types:** camelCase (`handleInternalError`, `getPasswordHash`)
- **Constants:** camelCase for unexported (`defaultPort`, `queryParamRedirectURL`)
- **Receiver names:** Single letter, consistent throughout file (`c *gin.Context`, `s *Store`)

### Error Handling

Use helper functions in `api/helper.go` for consistent error responses:
- `handleInternalError(c, err, message)` - Logs error, returns 500
- `handleBadRequest(c, err, message)` - Logs error, returns 400
- `handleUnexpectedError(c, err)` - Logs error, returns 500

```go
func SomeHandler(c *gin.Context) {
    dbConn, ok := getDatabaseConnectionFromContext(c)
    if !ok {
        handleInternalError(c, nil, "Missing configuration for database")
        return
    }
    result, err := db.SomeOperation(dbConn, input)
    if err != nil {
        handleInternalError(c, err, "Unable to perform operation")
        return
    }
    c.JSON(http.StatusOK, result)
}
```

### Logging

Use `log/slog` for structured logging:

```go
slog.Error("Unable to connect", slog.String("error", err.Error()))
slog.Info("Database connection established")
logger := slog.With(slog.String("email", email))
logger.Warn("User not found")
```

### Struct Tags

```go
// Form binding (x-www-form-urlencoded)
type UserSignInRequest struct {
    Email string `form:"email" binding:"required,email" example:"alex@test.com"`
}

// JSON binding
type ClientCreateRequest struct {
    ClientID string `json:"client_id" binding:"required" example:"cli"`
}

// GORM models
type User struct {
    Email     string `gorm:"primary_key;unique;not null"`
    IsEnabled bool   `gorm:"default:false;not null"`
    Roles     []Role `gorm:"many2many:user_roles;"`
}
```

### Swagger Documentation

Document API endpoints with swagger comments. Run `task swagger` after changes.

```go
// SignUp creates a new user
//
//	@Summary		Creates a new user
//	@Tags			user
//	@Accept			json
//	@Param			body	body	UserSignUpRequest	true	"Request"
//	@Router			/signup [post]
func SignUp(c *gin.Context) { }
```

### Database Operations

- Use GORM for all database operations
- Database connection is passed via Gin context (`c.Get("db")`)
- Define models in `db/model.go`, operations in `db/helper.go`

## Testing Patterns

- Use `testing` package with `testify/assert` for assertions
- Use `go-sqlmock` for database mocking
- Test file naming: `*_test.go` in `package_test` namespace

```go
func TestSomething(t *testing.T) {
    router, mock := getRouter()
    w := httptest.NewRecorder()
    req, _ := http.NewRequest(http.MethodPost, "/endpoint", nil)
    router.ServeHTTP(w, req)
    assert.Equal(t, http.StatusOK, w.Code)
}
```

## Project Structure

```
├── api/          # HTTP handlers, middleware, models
├── db/           # GORM models and database operations
├── server/       # Router setup and configuration
├── store/        # OAuth2 client store implementation
├── jwthelper/    # JWT token generation utilities
├── assets/       # Frontend HTML/JS/CSS files
├── docs/         # Generated Swagger documentation
└── main.go       # Application entry point
```

## Environment Variables

Configuration via Viper with `AUTH_` prefix:
- `AUTH_PORT` - Server port (default: 8080)
- `AUTH_DATABASE_CONNECTION_STRING_FILE_PATH` - Path to DB connection string
- `AUTH_REDIS_HOST` - Redis server address
- `AUTH_PRIVATE_KEY_PATH` - Path to ECDSA private key for JWT signing
- `AUTH_DOMAIN` - Application domain
- `AUTH_ENABLE_OIDC` - Enable OIDC provider support
