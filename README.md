# auth-server

Serving authentication and OAuth2 authorization

It is based on [go-oauth2/oauth2](https://github.com/go-oauth2/oauth2).

:warning: This is a work in progress and not ready for production yet :warning:

## Development setup

Note that port `8080` and `8088` will be used.

### Using localhost

To setup the API and its databases

```sh
task up-db
task run
```

To create user and OAuth client

```sh
task test-signup
task test-client-create
```

To test sign-in and getting access token

```sh
task test-login
task test-token
```

### Using MagicDNS of Tailscale and Caddy

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
task test-signup
task test-client-create
```

To test sign-in and getting access token

```sh
task test-step-domain
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
