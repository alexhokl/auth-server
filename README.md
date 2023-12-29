# auth-server

Serving authentication and OAuth2 authorization

It is based on [go-oauth2/oauth2](https://github.com/go-oauth2/oauth2).

:warning: This is a work in progress and not ready for production yet :warning:

## Setting up server

Users with administrative privileges can be seeded by starting this server with
an empty database (technically empty database table `users`). The server will
read the file configured via environment variable `AUTH_SEED_USERS_FILE_PATH`.

The file is in JSON format and the schema can be found in
[ImportUser](https://github.com/alexhokl/auth-server/blob/c7a770df8026e77f4163df6a9a9d40db3b76a29e/api/model.go#L118). The following is an example of content of the file.

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

```sh
go install github.com/swaggo/swag/cmd/swag@latest
```

### Using localhost

Note that port `8080` and `8088` will be used.

To setup the API and its databases

```sh
task up-db
task run
```

To create user and OAuth client

```sh
task test-client-create
```

To test sign-in and getting access token

```sh
task test-login
task test-password
task test-token
```

To test WebAuthn (FIDO2) registration

1. Sign-in using password via `http://localhost:8080/`
2. Once authenticated, press button `Register key` via
   `http://localhost:8080/authenticated/`

### Using MagicDNS of Tailscale and Caddy

Assuming the domain is `node-name.some-name.ts.net`.

Set environment variable `AUTH_DOMAIN` to `node-name.some-name.ts.net`.

To setup the API and its databases

```sh
task up-db
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

To create user and OAuth client

```sh
task test-client-create
```

To test sign-in and getting access token

```sh
task test-step-domain
```

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
