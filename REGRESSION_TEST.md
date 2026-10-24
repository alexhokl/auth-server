# Manual regression test

A full end-to-end regression test of auth-server, performed by a human before
a release. It covers what the unit tests (`task test`, `task test-js`) cannot:
real browsers and authenticators, external OIDC providers, emails sent through
Resend, Redis-backed sessions and throttling, and the Docker image.

## How to use this document

1. Copy this file (or print it) for the run and fill in the run record below.
2. Work through the sections in order; later sections reuse the accounts,
   clients and tokens created by earlier ones.
3. For each case, tick the box and write `PASS`, `FAIL` (with a short note and
   a defect reference) or `SKIP` (with the reason) in the Result column.
4. Fill in the [Results summary](#results-summary) at the end.

Expected HTTP status codes are those returned by the server; when using cURL,
pass `-i` to see them.

### Run record

| Field | Value |
|-------|-------|
| Date | |
| Tester | |
| Commit (`git rev-parse --short HEAD`) | |
| `AUTH_DOMAIN` | |
| Server run with | `task run` / `task run-debug` / Docker image |
| Desktop browsers and OS | |
| Mobile devices and browsers | |
| Authenticators used | (e.g. Touch ID, YubiKey 5, iPhone via hybrid, 1Password) |
| OIDC providers configured | |

## 1. Test environment

### 1.1 Prerequisites

- Task, Docker, Go, Node.js and npm, `swag`
  (`go install github.com/swaggo/swag/cmd/swag@latest`)
- `curl`, `jq`, `xh`, `step` (for `task test-step`), `psql`, `redis-cli`
- Tailscale with MagicDNS and Caddy. `localhost` is not suitable, as WebAuthn
  and several OIDC providers need a real HTTPS origin.
- A Resend API key and a verified sender, and access to the mailboxes of the
  test accounts
- Client registrations with each OIDC provider to be tested (Google, GitHub,
  Apple, Okta, Microsoft), with redirect URI
  `https://<AUTH_DOMAIN>/signin/<name>/callback`
- Authenticators: at least one platform authenticator (Touch ID, Windows Hello
  or Android), one security key with a PIN, one phone for hybrid (QR code)
  sign-in, and optionally a password manager extension that stores passkeys
- Two browsers, or two browser profiles, to hold separate sessions

### 1.2 Set-up

1. `export AUTH_DOMAIN=<node-name>.<tailnet>.ts.net`
2. Generate keys if `keys/` is empty: `task gen-key`, and create
   `keys/database_connection_string`, `keys/redis_password` and
   `keys/passphrase`.
3. Start from an empty database: `task down`, remove the PostgreSQL volume,
   then `task up-db`.
4. In the `env:` block of task `run-debug` (or your shell), set
   `AUTH_RESEND_API_KEY`, `AUTH_MAIL_FROM`, `AUTH_MAIL_FROM_NAME` and the three
   mail subjects; set `AUTH_DOMAIN`; keep `AUTH_FRONTEND_ENDPOINTS=true` and
   `AUTH_ENABLE_OIDC=true`. Leave `AUTH_ENFORCE_PKCE` unset (default `true`).
   For the throttling section, a short `AUTH_SIGNIN_FAILURE_WINDOW` such as
   `2m` saves waiting.
5. Edit `import_users.json` so the seeded administrator uses a mailbox you can
   read. This document calls it **ADMIN**.
6. `task run-debug` and, in another terminal, `task caddy`.

### 1.3 Accounts and clients used throughout

| Name | Description | Created in |
|------|-------------|------------|
| ADMIN | Seeded administrator with role `admin` | SU-02 |
| USER | Normal user signed up through the UI | SG-01 |
| USER2 | Second normal user, used for revocation | SG-01 (repeat) |
| CLIENT | Confidential OAuth client owned by ADMIN, redirect URI `http://127.0.0.1:8088/callback` (works with `task test-step`) | AD-01 |

### 1.4 Pre-flight automated checks

| | ID | Case | Steps | Expected | Result |
|-|----|------|-------|----------|--------|
| [ ] | PF-01 | Build | `task build` | Succeeds | |
| [ ] | PF-02 | Go unit tests | `task test` | All pass | |
| [ ] | PF-03 | Frontend tests | `task test-js` | All pass | |
| [ ] | PF-04 | Swagger is current | `task swagger`, then `git status docs/` | No changes to `docs/` | |

## 2. Start-up and operations

| | ID | Case | Steps | Expected | Result |
|-|----|------|-------|----------|--------|
| [ ] | SU-01 | Schema migration | Start the server on an empty database; `task db-list-users` | Server starts; tables exist | |
| [ ] | SU-02 | Admin seeding | `task db-list-users` | ADMIN exists, enabled, with role `admin` | |
| [ ] | SU-03 | No re-seeding | Change the display name in `import_users.json`, restart | ADMIN unchanged; no second import | |
| [ ] | SU-04 | Legacy key format rejected | Point `AUTH_PRIVATE_KEY_PATH` at a `BEGIN EC PRIVATE KEY` key, start | Start-up fails with `pkcs8: only PKCS #5 v2.0 supported` | |
| [ ] | SU-05 | Swagger UI | Open `https://<AUTH_DOMAIN>/swagger/index.html` | UI loads and lists all endpoint groups | |
| [ ] | SU-06 | Structured logs | Inspect the server output during any request | Application logs are JSON (`log/slog`) | |
| [ ] | SU-07 | Graceful shutdown | Press Ctrl+C (SIGINT); restart; `kill -TERM <pid>` | Server logs shutdown and exits cleanly both times | |
| [ ] | SU-08 | Frontend disabled | Restart with `AUTH_FRONTEND_ENDPOINTS=false`; GET `/`, `/signin`, `/signup`, `/assets/signin.js` | All `404`; `POST /signin` still works. Restore `true` afterwards | |
| [ ] | SU-09 | Home page | Open `https://<AUTH_DOMAIN>/` | Links Sign In, Reset Password, Sign Up work | |

## 3. Sign-up and email confirmation

| | ID | Case | Steps | Expected | Result |
|-|----|------|-------|----------|--------|
| [ ] | SG-01 | Sign up through the UI | Open `/signup`, enter USER's email and a password, press Sign Up | Redirected to `/signup_continue`; confirmation email arrives with the configured sender and subject | |
| [ ] | SG-02 | Show password toggle | On `/signup`, press Show password twice | Password shown as text, then hidden again | |
| [ ] | SG-03 | Unconfirmed user cannot sign in | Sign in as USER before confirming | `401 Invalid email or password` | |
| [ ] | SG-04 | Confirm | Open the link in the email (`/confirm/<otp>`) | `204`; USER can now sign in | |
| [ ] | SG-05 | Confirmation link reused | Open the same link again | `410 Gone` | |
| [ ] | SG-06 | Unknown confirmation | Open `/confirm/doesnotexist` | `404` | |
| [ ] | SG-07 | Expired confirmation | Restart with `AUTH_EXPIRATION_PERIOD=60`, sign up another address, wait more than 60 s, open the link | `410 Gone`; restore the period afterwards | |
| [ ] | SG-08 | Wrong-purpose OTP | Take the OTP of a password-reset email (PR-05) and open `/confirm/<otp>` | `404`; account state unchanged | |
| [ ] | SG-09 | Duplicate email | Sign up again with USER's email | Fails; no second account in `task db-list-users` | |
| [ ] | SG-10 | Invalid input | `POST /signup` with no password, or a malformed email | `400` | |
| [ ] | SG-11 | Custom redirect | Restart with `AUTH_SIGNUP_REDIRECT=https://example.com/welcome`, sign up | Redirected to the absolute URL; restore afterwards | |

Repeat SG-01 and SG-04 for USER2.

## 4. Password sign-in, session and sign-out

| | ID | Case | Steps | Expected | Result |
|-|----|------|-------|----------|--------|
| [ ] | SI-01 | Two-step sign-in | Open `/signin`, enter USER's email, press Continue, enter the password, press Sign In | Email step goes to `/signin/challenge`; signed in to `/authenticated` | |
| [ ] | SI-02 | Wrong password | Enter a wrong password at the challenge | `401 Invalid email or password` | |
| [ ] | SI-03 | Unknown email | Use an email with no account | Same `401` message as SI-02 (no user enumeration) | |
| [ ] | SI-04 | Challenge without email | In a fresh browser, open `/signin/challenge` directly; also `POST /signin/challenge` with only a password | Page is not usable without an email; POST returns `400` | |
| [ ] | SI-05 | Safe `redirect_uri` honoured | Open `/signin?redirect_uri=/changepassword`, sign in | Ends at `/changepassword` | |
| [ ] | SI-06 | Open redirect blocked | `POST /signin?redirect_uri=https://evil.example`, also `//evil.example` and `/\evil.example` | `400` each | |
| [ ] | SI-07 | API sign-in without redirect | `task test-login` then `task test-password` (set `LOGIN_NAME`/`LOGIN_PASSWORD` vars) | `302` to the challenge, then `201` | |
| [ ] | SI-08 | Session cookie attributes | Inspect the cookie in DevTools | Name is `AUTH_SESSION_COOKIE_NAME`; `Secure`; `SameSite=None` with OIDC enabled | |
| [ ] | SI-09 | SameSite without OIDC | Restart with `AUTH_ENABLE_OIDC=false`, sign in | Cookie has `SameSite=Strict`; no provider buttons on `/signin`; restore afterwards | |
| [ ] | SI-10 | Session stored in Redis | `task list-sessions` | A session key exists | |
| [ ] | SI-11 | Protected page while signed out | In a fresh browser open `/authenticated` | `302` to `/signin?redirect_uri=%2Fauthenticated` | |
| [ ] | SI-12 | Sign out | On `/authenticated`, press Sign Out, then reload `/authenticated` | Redirected to sign-in | |
| [ ] | SI-13 | Sign out when signed out | `POST /signout` without a session | Redirected to `/signin` (route requires authentication) | |
| [ ] | SI-14 | Password hash upgrade | For a user whose stored hash has outdated Argon2id parameters (edit `password_hash` in the database to a weaker PHC string for a known password), sign in | Sign-in succeeds; the stored hash now has `m=65536,t=2,p=1` | |

## 5. Throttling of failed sign-ins

Use a short `AUTH_SIGNIN_FAILURE_WINDOW` (e.g. `2m`). Check `AUTH_TRUSTED_PROXIES`
contains the address Caddy connects from (default `127.0.0.1 ::1`).

| | ID | Case | Steps | Expected | Result |
|-|----|------|-------|----------|--------|
| [ ] | TH-01 | Per-email limit | Fail the password challenge for USER 5 times | 6th attempt (even with the correct password) returns `429` | |
| [ ] | TH-02 | All sign-in endpoints blocked | While blocked, call `POST /signin`, `/signin/challenge`, `/fido/signin/challenge`, `/fido/signin` for USER | `429` on each | |
| [ ] | TH-03 | Other users unaffected | Sign in as USER2 from the same IP | Succeeds | |
| [ ] | TH-04 | Window expiry | Wait for the window to end, sign in as USER | Succeeds | |
| [ ] | TH-05 | Success resets email count | Fail 4 times, succeed, fail 4 more times | No `429` | |
| [ ] | TH-06 | Per-IP limit | Fail 20 times across different (even non-existent) emails | Next attempt for any email, including passkey endpoints, returns `429` | |
| [ ] | TH-07 | Client IP from proxy | With the IP blocked through Caddy, sign in from a second device on the tailnet | Second device not blocked (proves `X-Forwarded-For` is trusted) | |
| [ ] | TH-08 | OIDC not counted | While USER's email is blocked, sign in through an external provider with the same email | Succeeds | |
| [ ] | TH-09 | Limit disabled | Restart with `AUTH_SIGNIN_MAX_FAILURES_PER_EMAIL=0`, fail 10 times | No `429` for the email; restore afterwards | |
| [ ] | TH-10 | Redis down | Stop Redis briefly and attempt a sign-in | The failure is logged; throttling does not block (note that sessions also need Redis) | |

## 6. Password change and reset

| | ID | Case | Steps | Expected | Result |
|-|----|------|-------|----------|--------|
| [ ] | PW-01 | Change password page requires sign-in | Signed out, open `/changepassword` | Redirected to sign-in, then back to `/changepassword` | |
| [ ] | PW-02 | Change password | Signed in as USER, press Change Password on `/authenticated`, enter current and new passwords | Redirected to `/changepassword_completed`; password-changed email arrives | |
| [ ] | PW-03 | Wrong current password | Repeat PW-02 with a wrong current password | `400 Invalid old password` | |
| [ ] | PW-04 | Old password rejected | Sign out, sign in with the old password, then the new one | Old fails with `401`; new succeeds | |
| [ ] | PW-05 | Well-known change-password URL | Open `/.well-known/change-password` | `302` to `https://<AUTH_DOMAIN>/changepassword` | |
| [ ] | PR-01 | Request reset | Open `/resetpassword`, enter USER's email, press Continue | Reset email arrives with the configured subject | |
| [ ] | PR-02 | Reset for unknown email | Request a reset for an address with no account | `200` (a known email gets `204`); no email sent | |
| [ ] | PR-03 | Set new password | Open the link in the email, enter a new password, press Set new password | Succeeds; password-changed email arrives; new password works, old one fails | |
| [ ] | PR-04 | Reset link reused | Open the link again (GET), and POST to it again | `410 Gone` | |
| [ ] | PR-05 | New request replaces previous | Request two resets; open the first link | First link rejected; second works | |
| [ ] | PR-06 | Expired reset link | With a short `AUTH_EXPIRATION_PERIOD`, wait, then open the link | `410 Gone` | |
| [ ] | PR-07 | Signup OTP not usable for reset | Open `/confirmresetpassword/<signup otp>` | `404`; password unchanged | |

## 7. WebAuthn and passkeys

Sign in as USER with a password first. Registration is on `/authenticated`
with the button Add a passkey or security key.

| | ID | Case | Steps | Expected | Result |
|-|----|------|-------|----------|--------|
| [ ] | WA-01 | Register platform authenticator | Add a passkey, approve with Touch ID / Windows Hello | Credential appears in the table; UV (biometric or PIN) was required | |
| [ ] | WA-02 | Register security key | Add a passkey with the security key; enter its PIN | Credential appears; a discoverable credential if the key has slots | |
| [ ] | WA-03 | Register through a phone (hybrid) | Add a passkey, choose phone / QR code | Credential appears, marked as synced | |
| [ ] | WA-04 | Register in a password manager | Add a passkey saved by the password manager extension | Credential appears | |
| [ ] | WA-05 | Synced badge | Compare credentials | iCloud Keychain / Google Password Manager / phone credentials marked as synced (backup eligible); hardware key not | |
| [ ] | WA-06 | Display name shown | During registration, read the account name in the browser prompt | The user's display name, or the email when none is set | |
| [ ] | WA-07 | Rename credential | Rename a credential in the table | New name shown after a reload | |
| [ ] | WA-08 | Cancel registration | Start registering and cancel the browser prompt | Error message shown; no credential added | |
| [ ] | WA-09 | Register requires sign-in | Signed out, `POST /fido/register/challenge` | Redirected to `/signin` | |
| [ ] | WA-10 | Email-first passwordless sign-in | Sign out; at `/signin` enter USER's email, Continue, press Sign In Password-less, use any registered credential | Signed in to `/authenticated` | |
| [ ] | WA-11 | Passkey button | Sign out; at `/signin` press Sign in with a passkey, pick USER's passkey | Signed in as USER without typing an email | |
| [ ] | WA-12 | Passkey autofill | Sign out; focus the email field on `/signin` | Browser offers USER's passkeys in the autofill list; choosing one signs in | |
| [ ] | WA-13 | Passkey honours redirect | Open `/signin?redirect_uri=/changepassword` and use the passkey button | Ends at `/changepassword` | |
| [ ] | WA-14 | Passkey from phone | On desktop, press Sign in with a passkey and use the phone via QR code | Signed in | |
| [ ] | WA-15 | Cancel sign-in | Press Sign in with a passkey and cancel | Error message; still on `/signin`; autofill still works afterwards | |
| [ ] | WA-16 | Second user | Register a passkey for USER2 and sign in with it | Signed in as USER2, not USER | |
| [ ] | WA-17 | Delete credential | Delete a credential, then try signing in with it | Removed from the table; sign-in with it fails | |
| [ ] | WA-18 | Other users' credentials | As USER2, `DELETE` / `PATCH /fido/credentials/<USER's id>` | Rejected; USER's credential unchanged | |
| [ ] | WA-19 | JSON only | `POST /fido/signin/passkey/challenge` with `Content-Type: application/x-www-form-urlencoded` | Rejected | |
| [ ] | WA-20 | Challenge used once | Replay a captured `POST /fido/signin/passkey` body | Rejected | |
| [ ] | WA-21 | Disabled user | Disable USER2 (AD-12), try a passkey sign-in as USER2 | Rejected; re-enable afterwards | |

## 8. External sign-in (OIDC)

Requires `AUTH_ENABLE_OIDC=true`. Use the `name` values `google`, `github`,
`apple`, `okta` and `microsoft`; see "Configuring external sign-in" in
`README.md` for the settings of each.

| | ID | Case | Steps | Expected | Result |
|-|----|------|-------|----------|--------|
| [ ] | OI-01 | Create provider | As ADMIN, `POST /oidcclients` for each provider to be tested | `201`; `GET /oidcclients` lists them without secrets | |
| [ ] | OI-02 | Duplicate provider | `POST /oidcclients` again for the same `name` | Rejected | |
| [ ] | OI-03 | Unsupported name | `POST /oidcclients` with `name` `facebook` | `400` | |
| [ ] | OI-04 | Buttons | Open `/signin` | One button per provider with its `button_name` | |
| [ ] | OI-05 | Sign up through a provider | For each provider, with an account whose email is new to the server, press its button | Account created with that email; signed in | |
| [ ] | OI-06 | Sign in through a provider | Sign out and repeat OI-05 | Signed in to the same account | |
| [ ] | OI-07 | Match existing account | Sign in through a provider whose verified email equals USER's | Signed in as USER | |
| [ ] | OI-08 | Unverified email | Use a provider account whose email is unverified (e.g. GitHub with an unverified primary email) | Sign-in refused | |
| [ ] | OI-09 | Apple form post | Sign in with Apple | Callback `POST`ed to `/signin/apple/callback` and succeeds | |
| [ ] | OI-10 | Microsoft organisational account | Sign in with an Entra ID account, with and without optional claims `email`/`xms_edov` | With claims: succeeds; without: refused | |
| [ ] | OI-11 | Update provider | `PUT /oidcclients/<name>` with a new `button_name` | New label on `/signin` | |
| [ ] | OI-12 | Delete provider | `DELETE /oidcclients/<name>` | Button disappears | |
| [ ] | OI-13 | Non-admin | As USER, `GET /oidcclients` | `403` | |
| [ ] | OI-14 | Redirect preserved | Open `/authorize?...` signed out, sign in through a provider | Authorization flow continues to the client | |

## 9. OAuth 2.0

Use CLIENT (AD-01). The `test-*` tasks use the Taskfile vars `CLIENT_ID`,
`LOGIN_PASSWORD` (as the client secret) and `REDIRECT_URI`.

| | ID | Case | Steps | Expected | Result |
|-|----|------|-------|----------|--------|
| [ ] | OA-01 | Authorization code with PKCE | `task test-step` (signs in through the browser) | Access, refresh and ID tokens returned | |
| [ ] | OA-02 | `/authorize` signed out | Open an authorization URL in a fresh browser | Redirected to `/signin` with `redirect_uri` back to `/authorize`; flow completes after sign-in | |
| [ ] | OA-03 | PKCE enforced | `task test-authorize` (no `code_challenge`) | Error redirect / `invalid_request`; no code issued | |
| [ ] | OA-04 | PKCE optional | Restart with `AUTH_ENFORCE_PKCE=false`; `task test-token` | Token returned; restore afterwards | |
| [ ] | OA-05 | Wrong code verifier | Exchange a code with a different `code_verifier` | `invalid_grant` | |
| [ ] | OA-06 | Code used once | Exchange the same code twice | Second fails with `invalid_grant` | |
| [ ] | OA-07 | Wrong redirect URI | `/authorize` with a `redirect_uri` not registered for CLIENT | Error shown; no redirect to that URI | |
| [ ] | OA-08 | Wrong client secret | Exchange a code with a wrong secret | `401 invalid_client` | |
| [ ] | OA-09 | Response type `token` | `/authorize?response_type=token&...` | Access token in the redirect fragment | |
| [ ] | OA-10 | Client credentials | `curl -d grant_type=client_credentials --user <id>:<secret> https://$AUTH_DOMAIN/token` | Access token without a user | |
| [ ] | OA-11 | Refresh token | `grant_type=refresh_token` with the refresh token of OA-01 | New access token (and ID token for scope `openid`) | |
| [ ] | OA-12 | GET token request | `curl "https://$AUTH_DOMAIN/token?grant_type=client_credentials&..."` | Rejected | |
| [ ] | OA-13 | Unsupported grant | `grant_type=password` | `unsupported_grant_type` | |
| [ ] | OA-14 | Access token format | Decode the access token (jwt.io or `step crypto jwt inspect --insecure`) | Header `alg` `ES256`, `kid` = `AUTH_KEY_ID` | |
| [ ] | OA-15 | Tokens in Redis | `task list-tokens` | Token keys exist | |
| [ ] | OA-16 | No internal details | Stop PostgreSQL briefly and request a token | `server_error` with the standard description only; details in the log | |

## 10. OpenID Connect

| | ID | Case | Steps | Expected | Result |
|-|----|------|-------|----------|--------|
| [ ] | OC-01 | Discovery | `task openid-configuration-domain` | Issuer and endpoints use `AUTH_DOMAIN`, including `introspection_endpoint`, `jwks_uri`, `userinfo_endpoint` | |
| [ ] | OC-02 | JWKS | GET `jwks_uri` | One `EC` `P-256` key with `kid` = `AUTH_KEY_ID`; it verifies the tokens of OA-01 | |
| [ ] | OC-03 | ID token claims | Request scope `openid email` with a `nonce`; decode the ID token | `iss`, `sub` (email), `aud`, `azp`, `iat`, `exp`, `nonce`, `email`; `ES256` | |
| [ ] | OC-04 | ID token without `email` | Request scope `openid` only | No `email` claim | |
| [ ] | OC-05 | No ID token without `openid` | Request scopes without `openid` | No `id_token` in the response | |
| [ ] | OC-06 | ID token on refresh | Refresh a token granted with `openid` | New ID token returned | |
| [ ] | OC-07 | Userinfo GET and POST | `curl -H "Authorization: Bearer <token>"` to `/userinfo` with GET and POST, for scopes `openid`, `openid email`, `openid profile` | `sub` always; `email`/`email_verified` with `email`; `name` with `profile` | |
| [ ] | OC-08 | Userinfo without `openid` | Use a token without scope `openid` | `403 insufficient_scope` | |
| [ ] | OC-09 | Userinfo with invalid token | Use a garbage token | `401 invalid_token` | |
| [ ] | OC-10 | WebFinger | `task webfinger-configuration-domain` | Subject and issuer link for `AUTH_WEBFINGER_EMAIL` | |
| [ ] | OC-11 | Generic client | Configure any off-the-shelf OIDC client library or app against the discovery URL | Sign-in completes and claims are read | |

## 11. Token introspection

`task test-introspect -- <token>` posts to `POST /introspect` as CLIENT.

| | ID | Case | Steps | Expected | Result |
|-|----|------|-------|----------|--------|
| [ ] | IN-01 | Active access token | `task test-introspect -- <access token>` | `active: true` with `scope`, `client_id`, `username`, `sub`, `token_type` `Bearer`, `iat`, `exp`, `aud`, `iss` | |
| [ ] | IN-02 | Active refresh token | Introspect the refresh token | `active: true`, `token_type` `refresh_token` | |
| [ ] | IN-03 | Type hint | Pass `token_type_hint=refresh_token` with an access token, and vice versa | Still described correctly | |
| [ ] | IN-04 | `client_secret_post` | Send `client_id` and `client_secret` in the form instead of basic auth | Same result as IN-01 | |
| [ ] | IN-05 | Client credentials token | Introspect the token of OA-10 | Active; no `sub` or `username` | |
| [ ] | IN-06 | Unknown token | Introspect `abc` | `{"active": false}` | |
| [ ] | IN-07 | Expired token | Introspect a token past its `exp` | `{"active": false}` | |
| [ ] | IN-08 | Wrong client secret | Introspect with a wrong secret | `401 invalid_client` | |
| [ ] | IN-09 | Public client | Mark a client public in the database (`is_public = true`), introspect with it | `401 invalid_client` | |

## 12. Administration

Run each case as ADMIN unless stated. For access control, repeat a sample of
requests as USER (expect `403`) and signed out (expect a redirect to
`/signin`).

| | ID | Case | Steps | Expected | Result |
|-|----|------|-------|----------|--------|
| [ ] | AD-01 | Create client | `task test-client-create` (or Swagger UI) | Client created; `task db-list-clients` shows it | |
| [ ] | AD-02 | List clients | `GET /clients` | CLIENT listed with `client_id`, `redirect_uri`, `user_email`; no secret | |
| [ ] | AD-03 | Update client | `PATCH /clients/<id>` with a new `redirect_uri`, then a new `client_secret` | Changes take effect in the OAuth flow | |
| [ ] | AD-04 | Client scopes | `POST`, `GET`, `DELETE /clients/<id>/scopes[/<scope>]`; also add a scope that does not exist globally | Scope added, listed, removed; unknown scope `409` | |
| [ ] | AD-05 | Global scopes | `POST /scopes` `{"name":"read"}` twice; `DELETE /scopes/read` while assigned to a client, then after removing it | `201` then `409`; `409 Scope is in use`, then deleted | |
| [ ] | AD-06 | List users | `GET /users` | All users with roles, credentials and `is_enabled` | |
| [ ] | AD-07 | Get user | `GET /users/<USER>`; `GET /users/nobody@example.com` | User returned; `404` for unknown | |
| [ ] | AD-08 | Update display name | `PATCH /users/<USER>` `{"display_name":"New"}` | Returned and persisted; shown in the next WebAuthn registration prompt | |
| [ ] | AD-09 | Add role | `POST /users/<USER>/roles` `{"name":"admin"}`; repeat | `201`; then `409` | |
| [ ] | AD-10 | Role grants access | As USER, `GET /users` | `200` | |
| [ ] | AD-11 | Remove role | `DELETE /users/<USER>/roles/admin`; repeat | `204`; then `404`; USER gets `403` again | |
| [ ] | AD-12 | Disable user | `PATCH /users/<USER2>` `{"is_enabled":false}` | USER2 cannot sign in by any method | |
| [ ] | AD-13 | Self-protection | As ADMIN: disable self, delete self, remove own `admin` role | `400` each | |
| [ ] | AD-14 | User owning clients | `DELETE /users/<owner of CLIENT>` (use a non-self owner) | `409 user owns OAuth clients` | |
| [ ] | AD-15 | Delete user | `DELETE /users/<a throwaway user>` | `204`; user gone | |
| [ ] | AD-16 | Access control | As USER: `GET /clients`, `POST /scopes`, `GET /users`, `GET /oidcclients` | `403` each | |

## 13. Revocation of sessions and tokens

Prepare USER2 with: a signed-in session in browser B, an unused authorization
code, and an access and refresh token for CLIENT.

| | ID | Case | Steps | Expected | Result |
|-|----|------|-------|----------|--------|
| [ ] | RV-01 | Disable revokes session | As ADMIN disable USER2; in browser B reload `/authenticated` | Redirected to `/signin` | |
| [ ] | RV-02 | Disable revokes tokens | Introspect USER2's access and refresh tokens; call `/userinfo`; refresh | `active: false`; userinfo and refresh rejected | |
| [ ] | RV-03 | Disable revokes codes | Exchange the unused authorization code | Rejected | |
| [ ] | RV-04 | Stay revoked after re-enable | Re-enable USER2; repeat RV-02 with the old tokens | Still rejected; a fresh sign-in issues working tokens | |
| [ ] | RV-05 | Delete revokes | Obtain new tokens for a throwaway user, delete them, sign up again with the same email | Old session and tokens rejected | |
| [ ] | RV-06 | Admin session revoked | Disable a second admin while signed in; that admin calls `GET /users` | `403`, and the session is signed out | |

## 14. Docker image

| | ID | Case | Steps | Expected | Result |
|-|----|------|-------|----------|--------|
| [ ] | DK-01 | Build image | `task image -- dev` | Image builds | |
| [ ] | DK-02 | Run compose stack | Create `keys/database_connection_string_compose` (see `README.md`), `task up` | Server, PostgreSQL and Redis start; logs show no errors | |
| [ ] | DK-03 | Assets present | Open `/signin` through the container | Page and scripts load | |
| [ ] | DK-04 | End-to-end | Sign in with a password and a passkey through the container | Both succeed | |
| [ ] | DK-05 | Shutdown | `task down` | Container stops gracefully | |

## 15. Cross-browser and device smoke test

Run SI-01, SI-12, WA-01 (or WA-02), WA-10, WA-11, WA-12, PW-02 and one OIDC
sign-in on each.

| | Browser / device | Result | Notes |
|-|------------------|--------|-------|
| [ ] | Chrome (macOS or Windows) | | |
| [ ] | Safari (macOS) | | |
| [ ] | Firefox | | |
| [ ] | Edge (Windows, Windows Hello) | | |
| [ ] | Safari (iOS) | | |
| [ ] | Chrome (Android) | | |

## 16. Clean-up

- [ ] Delete test credentials from authenticators, phones and password managers
- [ ] `task db-remove-all-user-credentials` (or `task db-remove-all` to reset)
- [ ] Remove test client registrations at the OIDC providers if no longer needed
- [ ] Restore any changed environment variables and `import_users.json`
- [ ] `task down`

## Results summary

| Section | Passed | Failed | Skipped | Defects |
|---------|--------|--------|---------|---------|
| 1. Pre-flight | | | | |
| 2. Start-up and operations | | | | |
| 3. Sign-up | | | | |
| 4. Password sign-in | | | | |
| 5. Throttling | | | | |
| 6. Password change and reset | | | | |
| 7. WebAuthn and passkeys | | | | |
| 8. External sign-in | | | | |
| 9. OAuth 2.0 | | | | |
| 10. OpenID Connect | | | | |
| 11. Introspection | | | | |
| 12. Administration | | | | |
| 13. Revocation | | | | |
| 14. Docker image | | | | |
| 15. Cross-browser | | | | |

Overall verdict (release / do not release):

Sign-off:
