# auth-server

Serving authentication and OAuth2 authorization

It is based on the following libraries.

- [go-oauth2/oauth2](https://github.com/go-oauth2/oauth2).
- [golang-jwt/jwt](https://github.com/golang-jwt/jwt)
- [spf13/viper](https://github.com/spf13/viper)
- [gin-gonic/gin](https://github.com/gin-gonic/gin)
- [go-webauthn/webauthn](https://github.com/go-webauthn/webauthn)
- [resendlabs/resend-go](https://github.com/resendlabs/resend-go)

:warning: This is a work in progress and not ready for production yet :warning:

## Features

### OAuth 2.0

- Authorization code, client credentials and refresh token grants
- Response types `code` and `token`; access tokens are issued only over `POST
  /token` as GET access requests are disabled
- PKCE, enforced by default and controlled by `AUTH_ENFORCE_PKCE`
- Access tokens are ECDSA-signed JWTs (`ES256`) with a configurable key ID
- Tokens are stored in Redis; clients, scopes and users are stored in PostgreSQL

### OpenID Connect

- Discovery document at `/.well-known/openid-configuration`
- JSON Web Key Set at `/.well-known/openid-configuration/jwks`
- [WebFinger](https://www.rfc-editor.org/rfc/rfc7033) at `/.well-known/webfinger`
- Well-known change-password URL at `/.well-known/change-password`

### Authentication

- Email and password sign-in with `bcrypt` password hashes, as a two-step flow
  (`POST /signin` followed by `POST /signin/challenge`)
- WebAuthn (FIDO2) registration and passwordless sign-in, including credential
  management and clone detection; see
  [Current FIDO2/WebAuthn Support](#current-fido2webauthn-support)
- Sign-in through an external OIDC provider (currently Google), enabled with
  `AUTH_ENABLE_OIDC`
- Server-side sessions held in Redis under a configurable cookie name

### User and account management

- Self-service sign-up with email confirmation through a one-time password
  (`POST /signup` followed by `GET /confirm/:otp`)
- Password change for an authenticated user (`POST /changepassword`)
- Password reset by email through a one-time password link
  (`POST /resetpassword` and `GET`/`POST /confirmresetpassword/:otp`)
- Confirmation, password-changed and password-reset emails sent through
  [Resend](https://resend.com), with configurable subjects and sender
- One-time passwords expire after `AUTH_EXPIRATION_PERIOD` seconds
- Administrators seeded from a JSON file on the first start of an empty database

### Administration

- OAuth client management, restricted to users holding role `admin`
  (`POST`, `PATCH` and `GET` on `/clients`)
- Scope management, globally via `/scopes` and per client via
  `/clients/:client_id/scopes`
- OIDC provider management (`GET`, `POST`, `PUT` and `DELETE` on `/oidcclients`)
- User listing (`GET /users`)
- Role-based access enforced by middleware on each route group

### Operations

- Swagger 2.0 UI at `/swagger/index.html`, generated from code comments by
  [swag](https://github.com/swaggo/swag)
- Optional built-in front end covering sign-in, sign-up, password change and
  credential management, toggled with `AUTH_FRONTEND_ENDPOINTS`
- Database schema applied automatically on start-up through GORM AutoMigrate
- Structured JSON logging through `log/slog`
- Graceful shutdown on `SIGINT` and `SIGTERM`
- Configuration through environment variables prefixed with `AUTH_`, with
  secrets read from file paths rather than values

## Setting up server

Users with administrative privileges can be seeded by starting this server with
an empty database (technically empty database table `users`). The server will
read the file configured via environment variable `AUTH_SEED_USERS_FILE_PATH`.

The file is in JSON format and the schema is defined by `ImportUser` in
[api/model.go](api/model.go). The following is an example of content of the
file.

```json
[
  {
    "email": "user@test.com",
    "password": "password",
    "display_name": "Test User",
    "roles": ["admin"]
  }
]
```

Note that setting of role `admin` is important to allow the user to act as an
administrator to configure other aspects (such as OAuth clients) of this server.

## Development setup

### Prerequisite

- [Task](https://taskfile.dev/) as the task runner (this repository has no
  `Makefile`)
- Docker (for the PostgreSQL and Redis containers)
- [swag](https://github.com/swaggo/swag) as tasks `run` and `run-debug`
  regenerate the Swagger documentation before starting the server

```sh
go install github.com/swaggo/swag/cmd/swag@latest
```

### Build and test

```sh
task build
task test
```

Note that the build uses build tag `nomsgpack`; see `Taskfile.yml`.

### Keys and secrets

Secrets are configured as *file paths* rather than values (for example
`AUTH_DATABASE_CONNECTION_STRING_FILE_PATH`, `AUTH_REDIS_PASSWORD_FILE_PATH`
and `AUTH_PRIVATE_KEY_PASSWORD_FILE_PATH`). For local development these files
live in directory `keys/`. The ECDSA key used for signing tokens can be
generated with [step](https://smallstep.com/docs/step-cli/).

```sh
task gen-key
```

The full set of environment variables used by a working local run is the `env`
block of task `run-debug` in `Taskfile.yml`.

### Using localhost

Using localhost is not recommended as it is hard, if not impossible, do test the
workflow of webauthn and some of the OIDC providers.

### Using MagicDNS of Tailscale and Caddy

Assuming the domain is `node-name.some-name.ts.net`.

Set environment variable `AUTH_DOMAIN` to `node-name.some-name.ts.net`.

To setup the API and its databases (task `run` starts the database containers
and regenerates the Swagger documentation first)

```sh
task run
```

Assuming `Caddyfile` like the following has been prepared.

```
node-name.some-name.ts.net

reverse_proxy :8080
```

To start reverse proxy from the MagicDNS domain name from Tailscale to port
`8080`.

```sh
task caddy
```

To create a user and an OAuth client

```sh
task test-signup
task test-client-create
```

To test sign-in and access token retrieval

```sh
task test-step
```

or

```sh
task test-login
task test-password
task test-token
```

Note that these `test-*` tasks are cURL/`step` smoke tests against a running
server; most of them require environment variable `AUTH_DOMAIN` and the cookie
file produced by `task test-login`.

To test WebAuthn (FIDO2) registration

1. Sign-in using password via `https://node-name.some-name.ts.net/`
2. Once authenticated, press button `Register key` via
   `https://node-name.some-name.ts.net/authenticated/`

To test login via OIDC provider

1. Ensure environment variable `AUTH_ENABLE_OIDC` is set to `true`.
2. Setup a OIDC provider via `POST /oidcclients` (currently only `google` is
   supported).

### Webauthn (FIDO2)

#### Encoding

This server implementation uses
[base64url](https://datatracker.ietf.org/doc/html/rfc4648#section-5) encoding.
As a result, front-end has to convert standard `base64` encoding to the
encoding.

#### Default authenticator selection

```json
"authenticatorSelection": {
  "authenticatorAttachment": "cross-platform",
  "requireResidentKey": false,
  "residentKey": "discouraged",
  "userVerification": "required"
}
```

## Current FIDO2/WebAuthn Support

The auth-server has a complete FIDO2/WebAuthn implementation with the following
capabilities.

| Feature | Status | Details |
|---------|--------|---------|
| Credential Registration | Complete | Users can register security keys/passkeys |
| Passwordless Authentication | Complete | Login using WebAuthn credentials |
| Credential Management | Complete | List, rename, and delete credentials |
| Cross-platform Authenticators | Supported | USB keys, NFC, BLE, platform authenticators |
| User Verification | Required | PIN/biometric required |
| Clone Detection | Implemented | Sign counter tracking |

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| /fido/register/challenge | POST | Start registration (auth required) |
| /fido/register | POST | Complete registration |
| /fido/signin/challenge | POST | Start authentication |
| /fido/signin | POST | Complete authentication |
| /fido/credentials | GET | List user's credentials |
| /fido/credentials/:id | DELETE | Delete a credential |
| /fido/credentials/:id | PATCH | Rename a credential |

### Authentication Flow

1. User enters email at /signin → stored in session
2. Client requests challenge from /fido/signin/challenge
3. Browser's navigator.credentials.get() prompts user
4. Server validates assertion at /fido/signin
5. Session marked authenticated, optional redirect

### WebAuthn Configuration

- `AuthenticatorAttachment`: `protocol.CrossPlatform` (Hardware keys supported)
- `ResidentKey`: `protocol.ResidentKeyRequirementDiscouraged`
- `UserVerification`: `protocol.VerificationRequired` (PIN/biometric required)
- `AttestationPreference`: `protocol.PreferDirectAttestation`

### Storage

- Credentials: PostgreSQL via GORM (UserCredential model)
- Sessions/Challenges: Redis (temporary challenge storage)
- User binding: Via WebAuthnUserID (UUID) on User model

### Frontend

JavaScript implementation in assets/ handles:
- Base64URL encoding/decoding
- WebAuthn API calls (navigator.credentials.create/get)
- Credential table rendering and management UI

## References

- [Sign-in form best practices](https://web.dev/sign-in-form-best-practices/)
- [Sign-up form best practices](https://web.dev/sign-up-form-best-practices/)
- [Well-known URL for changing passwords](https://web.dev/change-password-url/)
- [13 best practices for user account, authentication, and password
  management](https://cloud.google.com/blog/products/identity-security/account-authentication-and-password-management-best-practices)
- [RFC 6749 The OAuth 2.0 Authorization
  Framework](https://www.rfc-editor.org/rfc/rfc6749)
- [RFC 8414 OAuth 2.0 Authorization Server
  Metadata](https://www.rfc-editor.org/rfc/rfc8414.html)
- [RFC 7636 Proof Key for Code Exchange by OAuth Public
  Clients](https://www.rfc-editor.org/rfc/rfc7636)
- [RFC 8693 OAuth 2.0 Token
  Exchange](https://www.rfc-editor.org/rfc/rfc8693.html)
  * An explanation from Scott Brady in [Delegation Patterns for OAuth 2.0 using
    Token
    Exchange](https://www.scottbrady91.com/oauth/delegation-patterns-for-oauth-20)
  * example implementation in .NET from
    [RockSolidKnowledge/TokenExchange](https://github.com/RockSolidKnowledge/TokenExchange)
    + [sample](https://docs.duendesoftware.com/identityserver/v5/tokens/extension_grants/token_exchange/)
- [RFC 7522 Security Assertion Markup Language (SAML) 2.0 Profile for OAuth 2.0
  Client Authentication and Authorization
  Grants](https://www.rfc-editor.org/rfc/rfc7522)
- [RFC 7033 WebFinger](https://www.rfc-editor.org/rfc/rfc7033)
- [bcrypt](https://en.wikipedia.org/wiki/Bcrypt)
- [swaggo/swag](https://github.com/swaggo/swag)
- [swaggo/gin-swagger](https://github.com/swaggo/gin-swagger)
