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
- An unexpected internal error is returned to a client as `server_error` with
  the standard description, without internal details; it is logged instead
- Tokens are stored in Redis; clients, scopes and users are stored in PostgreSQL
- Token introspection ([RFC 7662](https://www.rfc-editor.org/rfc/rfc7662)) at
  `POST /introspect` for access and refresh tokens, for confidential clients
  authenticated with `client_secret_basic` or `client_secret_post` (see
  [Introspecting tokens](#introspecting-tokens))

### OpenID Connect

- Discovery document at `/.well-known/openid-configuration`
- JSON Web Key Set at `/.well-known/openid-configuration/jwks`
- [WebFinger](https://www.rfc-editor.org/rfc/rfc7033) at `/.well-known/webfinger`
- Well-known change-password URL at `/.well-known/change-password`
- ID tokens (`ES256`, signed with the access token key) returned by `/token`
  for an authorization code granted with scope `openid`, and on refreshing it;
  they carry `iss`, `sub`, `aud`, `azp`, `iat`, `exp`, the `nonce` of the
  authorization request and, with scope `email`, `email`
- `userinfo` endpoint (`GET` and `POST /userinfo`) for a bearer access token
  with scope `openid`, returning `sub`, plus `email` and `email_verified` with
  scope `email` and `name` with scope `profile`
- The subject (`sub`) of tokens and userinfo is the email address of the user
- Only the authorization code flow is supported; response types `id_token` and
  hybrid flows, and request parameters `claims`, `max_age` and `prompt` are not

### Authentication

- Email and password sign-in with Argon2id password hashes (64 MiB, 2 passes,
  1 lane, PHC string format), as a two-step flow (`POST /signin` followed by
  `POST /signin/challenge`); a hash with outdated parameters is replaced on the
  next successful sign-in
- WebAuthn (FIDO2) registration and passwordless sign-in, including credential
  management and clone detection; the WebAuthn user display name is the
  display name of the user, or the email address when it is not set; see
  [Current FIDO2/WebAuthn Support](#current-fido2webauthn-support)
- Passkeys: platform authenticators (Touch ID, Windows Hello, iCloud Keychain,
  Google Password Manager) and security keys create discoverable credentials
  where supported, and usernameless sign-in with them (a "Sign in with a
  passkey" button and passkey autofill on the email field of `/signin`)
- Sign-up and sign-in through Google, GitHub, Apple, Okta or Microsoft,
  enabled with `AUTH_ENABLE_OIDC`; an account is matched by an email address
  which the provider has verified (see
  [Configuring external sign-in](#configuring-external-sign-in))
- Server-side sessions held in Redis under a configurable cookie name
- Throttling of failed sign-ins (see
  [Throttling failed sign-ins](#throttling-failed-sign-ins))

### User and account management

- Self-service sign-up with email confirmation through a one-time password
  (`POST /signup` followed by `GET /confirm/:otp`)
- Password change for an authenticated user (`POST /changepassword`)
- Password reset by email through a one-time password link
  (`POST /resetpassword` and `GET`/`POST /confirmresetpassword/:otp`)
- Confirmation, password-changed and password-reset emails sent through
  [Resend](https://resend.com), with configurable subjects and sender
- One-time passwords expire after `AUTH_EXPIRATION_PERIOD` seconds, can be
  used once, and only for the purpose (sign-up or password reset) they were
  issued for; issuing a new one replaces the previous one of the user
- Administrators seeded from a JSON file on the first start of an empty database
- Redirect targets after sign-up and password change, set with
  `AUTH_SIGNUP_REDIRECT` (default `/signup_continue`) and
  `AUTH_CHANGE_PASSWORD_REDIRECT` (default `/changepassword_completed`); the
  default pages are served only with `AUTH_FRONTEND_ENDPOINTS`, so a deployment
  with its own front end can point them elsewhere, including at absolute URLs

### Administration

- OAuth client management, restricted to users holding role `admin`
  (`POST` and `GET` on `/clients`, `PATCH /clients/:client_id`)
- Scope management, globally via `/scopes` and per client via
  `/clients/:client_id/scopes`
- OIDC provider management (`GET`, `POST`, `PUT` and `DELETE` on `/oidcclients`)
- User management (`GET /users`, and `GET`, `PATCH` and `DELETE` on
  `/users/:email`): display name and enabled state can be updated; a user
  owning OAuth clients cannot be deleted
- Role management per user (`POST /users/:email/roles` and
  `DELETE /users/:email/roles/:role`); a role is created when it is first
  granted
- An administrator cannot disable or delete themselves, or revoke their own
  role `admin`
- Disabling or deleting a user revokes their sessions, authorization codes,
  access tokens and refresh tokens; they stay revoked when the user is enabled
  again or an account with the same email address is created (see
  [Revoking sessions and tokens](#revoking-sessions-and-tokens))
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

## Implementation status

`task build` and `task test` pass. Unit test coverage of statements by package:

| Package | Coverage |
|---------|----------|
| `api` | 93.7% |
| `db` | 94.4% |
| `jwthelper` | 97.7% |
| `server` | 99.2% |
| `store` | 97.0% |

### Not yet implemented / known gaps

None known.

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

## Revoking sessions and tokens

Disabling a user (`PATCH /users/:email` with `"is_enabled": false`) records
the time in `revoked_at` of the user. A session, authorization code, access
token or refresh token is rejected if its user no longer exists, is disabled,
or was disabled or created after it was issued. Nothing is deleted from Redis;
the check is made whenever a session is used (`RequiredAuthenticated` and
`RequiredAdminAccess`, after which the session is signed out) and whenever a
code or token is looked up (`/token`, `/userinfo`, `/introspect`).

A session signed in before this check was introduced has no time of sign-in
and is rejected, so its user has to sign in again.

## Introspecting tokens

`POST /introspect` tells a resource server whether a token is still active
([RFC 7662](https://www.rfc-editor.org/rfc/rfc7662)). The caller authenticates
as a confidential client, with HTTP basic authentication or `client_id` and
`client_secret` in the form; any such client can introspect a token issued to
any client. Form field `token` is the access or refresh token, and optional
`token_type_hint` (`access_token` or `refresh_token`) is the type tried first.

```sh
curl -d token=<access token> --user <client ID>:<client secret> https://<AUTH_DOMAIN>/introspect
```

An active token is described by `active`, `scope`, `client_id`, `username`
and `sub` (the email address of the user; absent for the client credentials
grant), `token_type` (`Bearer`, or `refresh_token`), `iat`, `exp`, `aud` and
`iss`. A token which is unknown, has expired or has been revoked (see
[Revoking sessions and tokens](#revoking-sessions-and-tokens)) is described as
`{"active": false}`, as is any token when Redis or the database cannot be
reached. A client which fails to authenticate, or is public, gets
`401 invalid_client`.

Access tokens are also self-contained JWTs. A resource server which verifies
them with the JSON Web Key Set alone accepts a revoked token until it expires,
so one which has to honour revocation should introspect them.

## Throttling failed sign-ins

Failed password and WebAuthn sign-ins are counted per email address and per
client IP address in Redis, in a fixed window which starts at the first
failure. Once either count reaches its limit, `POST /signin`,
`POST /signin/challenge`, `POST /fido/signin/challenge`, `POST /fido/signin`,
`POST /fido/signin/passkey/challenge` and `POST /fido/signin/passkey` respond
with `429 Too Many Requests` until the window ends. A successful sign-in resets
the count of the email address but not that of the IP address. Sign-in through
an external provider is not counted.

A passkey sign-in has no email address until the user is resolved from the
user handle of the assertion, so a failure before that (such as an unknown or
malformed user handle) is counted against the IP address only, and
`POST /fido/signin/passkey/challenge` checks the IP address only.

| Setting | Default | Description |
|---------|---------|-------------|
| `AUTH_SIGNIN_MAX_FAILURES_PER_EMAIL` | `5` | Failures of an email address before it is blocked; `0` disables the limit |
| `AUTH_SIGNIN_MAX_FAILURES_PER_IP` | `20` | Failures from an IP address before it is blocked; `0` disables the limit |
| `AUTH_SIGNIN_FAILURE_WINDOW` | `15m` | Length of the window, as a Go duration |
| `AUTH_REDIS_RATE_LIMIT_DB` | `auth-rate-limit` | Prefix of the Redis keys of the counts |
| `AUTH_TRUSTED_PROXIES` | `127.0.0.1 ::1` | Space-separated addresses or CIDRs of reverse proxies whose `X-Forwarded-For` header is trusted for the client IP address |

Behind a reverse proxy such as Caddy, set `AUTH_TRUSTED_PROXIES` to the
address the proxy connects from; otherwise every client appears to have the
address of the proxy and shares its limit. If Redis cannot be reached, a
sign-in is allowed and the error is logged.

As the limit per email address applies to any client, anyone who knows an
email address can block its sign-in for a window by failing on purpose.

## Configuring external sign-in

External sign-in is enabled with `AUTH_ENABLE_OIDC=true`. An administrator
configures each provider with `POST /oidcclients` (`PUT /oidcclients/:name` to
update it), where `name` is one of `google`, `github`, `apple`, `okta` and
`microsoft`; at most one client can be configured per provider. Register the
redirect URI `https://<AUTH_DOMAIN>/signin/<name>/callback` with the provider
and set the same value as `redirect_uri`.

```json
{
  "name": "okta",
  "client_id": "<client ID>",
  "client_secret": "<client secret>",
  "redirect_uri": "https://auth.example.com/signin/okta/callback",
  "button_name": "Sign in with Okta",
  "issuer": "https://acme.okta.com/oauth2/default"
}
```

A user signs up or signs in with the email address the provider reports, and
only if the provider has verified it. PKCE is used with all the providers but
Apple, and a nonce is checked in the ID token of all the providers but GitHub
(which does not issue one).

| Provider | Settings | Notes |
|----------|----------|-------|
| `google` | `client_id`, `client_secret` | Scopes `openid profile email`; the ID token must have `email_verified` |
| `github` | `client_id`, `client_secret` of an OAuth app | Scopes `read:user user:email`; the primary email must be verified on GitHub |
| `apple` | `client_id` (the Services ID), `team_id`, `key_id`, and the content of the `.p8` private key as `client_secret` | Scopes `name email`; the callback is a form post (`response_mode=form_post`), so the redirect URI must be `https`; a client secret is signed with the private key on every token request |
| `okta` | `client_id`, `client_secret`, `issuer` | `issuer` is the authorization server, such as `https://acme.okta.com/oauth2/default` or `https://acme.okta.com`; endpoints are discovered from it |
| `microsoft` | `client_id`, `client_secret`, `issuer` | `issuer` is `https://login.microsoftonline.com/<tenant>/v2.0`, where `<tenant>` is `common`, `organizations`, `consumers` or a tenant ID |

As the email of an organisational Microsoft account can be set by a tenant
administrator, it is trusted only if Microsoft has verified the owner of its
domain. Add optional claims `email` and `xms_edov` to the ID token in the app
registration; otherwise only personal Microsoft accounts can sign in.

A client of a provider which is no longer supported is not shown on the
sign-in page and can be removed with `DELETE /oidcclients/:name`.

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
live in directory `keys/`. The ECDSA (P-256) key pair used for signing tokens
is generated with OpenSSL, encrypted with the passphrase in `keys/passphrase`.

```sh
task gen-key
```

The key must be an encrypted PKCS #8 key (`-----BEGIN ENCRYPTED PRIVATE
KEY-----`), which is what `task gen-key` produces. A key in the legacy
`-----BEGIN EC PRIVATE KEY-----` format (as produced by `step crypto keypair`)
fails to load with `pkcs8: only PKCS #5 v2.0 supported` and has to be
regenerated.

The full set of environment variables used by a working local run is the `env`
block of task `run-debug` in `Taskfile.yml`.

### Running in Docker

`docker-compose.yml` runs PostgreSQL, Redis and the server image. The server
reads its secrets from directory `keys/`, mounted at `/mnt/keys`, and expects
one extra file, `keys/database_connection_string_compose`, which is
`keys/database_connection_string` with `host=db` instead of `host=localhost`.

```sh
sed 's/host=localhost/host=db/' keys/database_connection_string > keys/database_connection_string_compose
task image -- dev
task up
```

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
2. Setup a provider via `POST /oidcclients` (see
   [Configuring external sign-in](#configuring-external-sign-in)).

### Webauthn (FIDO2)

#### Encoding

This server implementation uses
[base64url](https://datatracker.ietf.org/doc/html/rfc4648#section-5) encoding.
As a result, front-end has to convert standard `base64` encoding to the
encoding.

#### Default authenticator selection

```json
"authenticatorSelection": {
  "requireResidentKey": false,
  "residentKey": "preferred",
  "userVerification": "required"
}
```

`authenticatorAttachment` is not set, so both platform authenticators and
security keys can be registered. With `residentKey` set to `preferred`, a
security key without resident-key slots still registers, as a non-discoverable
credential, while a security key with slots uses one up (older YubiKeys hold
about 25).

## Current FIDO2/WebAuthn Support

The auth-server has a complete FIDO2/WebAuthn implementation with the following
capabilities.

| Feature | Status | Details |
|---------|--------|---------|
| Credential Registration | Complete | Users can register passkeys (platform authenticators and passkey providers) and security keys (roaming authenticators); credentials are discoverable where the authenticator supports it |
| Passwordless Authentication | Complete | Login using WebAuthn credentials, after entering an email address or, with a discoverable credential, without one |
| Credential Management | Complete | List, rename, and delete credentials; synced (backup eligible) credentials are marked |
| Platform Authenticators | Supported | Touch ID, Windows Hello, on-device Android and iOS passkeys, iCloud Keychain, Google Password Manager |
| Cross-platform Authenticators | Supported | USB keys, NFC, BLE, a phone through hybrid |
| User Verification | Required | PIN/biometric required |
| Clone Detection | Implemented | The sign counter is stored after each sign-in; a credential whose counter does not increase gets a clone warning and is rejected until it is deleted and registered again |

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| /fido/register/challenge | POST | Start registration (auth required) |
| /fido/register | POST | Complete registration |
| /fido/signin/challenge | POST | Start authentication of the email in the session |
| /fido/signin | POST | Complete authentication of the email in the session |
| /fido/signin/passkey/challenge | POST | Start authentication with a passkey, without an email |
| /fido/signin/passkey | POST | Complete authentication with a passkey |
| /fido/credentials | GET | List user's credentials |
| /fido/credentials/:id | DELETE | Delete a credential |
| /fido/credentials/:id | PATCH | Rename a credential |

### Authentication Flow

Email first:

1. User enters email at /signin → stored in session
2. Client requests challenge from /fido/signin/challenge
3. Browser's navigator.credentials.get() prompts user
4. Server validates assertion at /fido/signin
5. Session marked authenticated, optional redirect

Usernameless (passkey):

1. On /signin, the client requests a challenge from
   /fido/signin/passkey/challenge, either when the page loads (passkey
   autofill on the email field) or when "Sign in with a passkey" is clicked
2. Browser's navigator.credentials.get() lets the user pick a passkey, with no
   `allowCredentials`
3. Server resolves the user from the user handle of the assertion and
   validates it at /fido/signin/passkey
4. Session marked authenticated as that user; the client redirects to
   `redirect_uri` or /authenticated

Notes:

- The sign-in endpoints accept only `Content-Type: application/json`, which a
  third-party page cannot send without a CORS preflight.
- A challenge is used at most once (for requests made one after another); it
  is removed from the session before the assertion is validated.
- The sign counter, clone warning and backup state of the credential are
  stored after each sign-in. A credential with a clone warning is rejected
  until it is deleted (`DELETE /fido/credentials/:id`) and registered again.
- Security keys registered before passkey support are non-discoverable and
  still need the email-first flow.
- A discoverable credential registered before the user handle fix in the front
  end (through a phone, or a password-manager browser extension) holds a wrong
  user handle and fails both flows; delete it and register it again.

### WebAuthn Configuration

- `AuthenticatorAttachment`: unset (platform authenticators and security keys)
- `ResidentKey`: `protocol.ResidentKeyRequirementPreferred` (discoverable
  where supported), with `RequireResidentKey` false
- `UserVerification`: `protocol.VerificationRequired` (PIN/biometric required)
- `AttestationPreference`: `protocol.PreferNoAttestation`; attestation is not
  verified against a metadata service, and the stored AAGUID may be all zeros

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
- [RFC 7662 OAuth 2.0 Token
  Introspection](https://www.rfc-editor.org/rfc/rfc7662)
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
- [Argon2id](https://www.rfc-editor.org/rfc/rfc9106)
- [Post-Quantum Cryptographic Right
  Answers](https://words.filippo.io/right-answers/) by Filippo Valsorda, the
  basis for the choice of Argon2id over bcrypt
- [swaggo/swag](https://github.com/swaggo/swag)
- [swaggo/gin-swagger](https://github.com/swaggo/gin-swagger)
