# MIndie Identity Provider (IdP)

Original: [MinToken](https://github.com/Zegnat/php-mintoken.git)
License: [0BSD](LICENSE)

## Code Changes

### [README](README.md)

- section: MIndie Identity Provider (IdP)
- section: Metadata Discovery
- section: Endpoints

### [endpoint](endpoint.php)

- `define('MINTOKEN_SQLITE_PATH', '/var/lib/php-mintoken/tokens.sqlite3');`
- [no more me](https://github.com/Zegnat/php-mintoken/pull/14)
- [introspection](https://github.com/Zegnat/php-mintoken/pull/15)

# Mintoken

A minimal [IndieAuth][] compatible [Token Endpoint][].

Several times I have been asked if there is a token endpoint available to be used together with [Selfauth][]. A minimal solution that would just work for issuing access tokens that is self-hostable on a server with PHP.

I do not have a need for a token endpoint like this myself, thus developing one would go against my [selfdogfooding][] principles. But because I have a general interest in the IndieAuth specification, here is an implementation anyway!

[IndieAuth]: https://indieauth.net/
[Token Endpoint]: https://indieauth.spec.indieweb.org/#token-endpoint
[Selfauth]: https://github.com/Inklings-io/selfauth
[selfdogfooding]: https://indieweb.org/selfdogfood

## Setup

1. Download [the latest release](https://github.com/Zegnat/php-mintoken/releases/latest) from GitHub and extract the files.
   
2. Create an SQLite database; these instructions assume the database is called `tokens.db`.
   
   **You can do this from the command line:**
   
   ```bash
   sqlite3 tokens.db < schema.sql
   ```
   
   If you prefer, create the SQLite database by your favourite means and use `schema.sql` to create the expected tables.
   
3. Define trusted authorization endpoints in the `settings` table of the SQLite database. Mintoken will only check codes with these endpoints, and takes the `me` value they return as trusted without further verification.
   
   E.g. if we take [the example setup for Selfauth](https://github.com/Inklings-io/selfauth#setup), the endpoint `https://example.com/auth/` should be whitelisted.
   
   **From the command line:**
   
   ```bash
   sqlite3 tokens.db 'INSERT INTO settings VALUES ("endpoint", "https://example.com/auth/");'
   ```
   
4. Upload the SQLite database to a secure directory on your server. Make sure it is not publicly available to the web! This is very important for security reasons.
   
5. Edit `endpoint.php` so line 5 defines the correct path to the SQLite database as the value for `MINTOKEN_SQLITE_PATH`.
   
   You should use the full path to `tokens.db`. For example, `define('MINTOKEN_SQLITE_PATH', '../../tokens.db');`
   
6. Put `endpoint.php` anywhere on your server where it is available to the web. (This can be in the same folder as Selfauth, for simplicity.)
   
7. Make the token endpoint discoverable. Either by defining a `Link` HTTP header, or adding the following to the `<head>` of the pages where you also link to your `authorization_endpoint`:
   
   ```html
   <link rel="token_endpoint" href="https://example.com/auth/endpoint.php">
   ```
   
   (The `href` must point at your `endpoint.php` file.)

### Metadata Discovery
Note that the use of `authorization_endpoint` and `token_endpoint` are deprecated but *SHOULD* be included for backwards compatibility.

Instead the [spec supports a metadata discovery endpoint](https://indieauth.spec.indieweb.org/#discovery).

Assuming the same configuration from above, the minimal metadata endpoint would look like
```json
{
	"issuer": "https://example.com",
	"authorization_endpoint": "https://example.com/auth/",
	"token_endpoint": "https://example.com/auth/endpoint.php",
	"introspection_endpoint": "https://example.com/auth/endpoint.php",
	"code_challenge_methods_supported": ["S256"]
}
```
And the full recommended metadata endpoint would look like
```json
{
	"issuer": "https://example.com",
	"authorization_endpoint": "https://example.com/auth/",
	"token_endpoint": "https://example.com/auth/endpoint.php",
	"introspection_endpoint": "https://example.com/auth/endpoint.php",
	"response_types_supported": ["code"],
	"response_modes_supported": ["query"],
	"grant_types_supported": ["authorization_code"],
	"introspection_endpoint_auth_methods_supported": ["client_secret_basic"],
	"service_documentation": "https://indieauth.spec.indieweb.org/#discovery",
	"code_challenge_methods_supported": ["S256"]
}
```

## Endpoints

### Authorize
```curl
curl --include -X POST -H "Content-Type: application/x-www-form-urlencoded" -d 'grant_type=authorization_code&code=<from SelfAuth submit>&redirect_uri=https%3A%2F%2Fexample.com%2Fclient%2Fredirect.php&client_id=https%3A%2F%2Fexample.com%2Fclient%2F&code_verifier=<value used to generate code_challenge>' 'https://example.com/auth/endpoint.php?action=authorize'
```

### Consume
```curl
curl --include --oauth2-bearer <token from authorize> https://example.com/selfauth/token.php
```

### Revoke
```curl
curl --include -X POST -H "Content-Type: application/x-www-form-urlencoded" -d 'token=<token from authorize>' https://example.com/selfauth/token.php?action=revoke
```

### Introspection
```curl
curl --include -u https://example.com/client/:_ -X POST -H "Content-Type: application/x-www-form-urlencoded" -d 'token=<token from authorize>' https://example.com/selfauth/token.php?action=introspect
```
Note that this endpoint requires a fixed password of `_`.

## License

The BSD Zero Clause License (0BSD). Please see the LICENSE file for
more information.

