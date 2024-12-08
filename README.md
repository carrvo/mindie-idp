# MIndie Identity Provider (IdP)

Built upon [SelfAuth](selfauth/README.md) ([source](https://github.com/Inklings-io/selfauth)) + [MinToken](mintoken/README.md) ([source](https://github.com/Zegnat/php-mintoken.git)) to give a minimally self-hosted [IndieAuth](https://indieweb.org/IndieAuth) Identity Provider (IdP). This IdP will be compatible with both [IndieAuth](https://indieauth.net/) ([spec](https://indieauth.spec.indieweb.org/)) and [OAuth2.0](https://www.oauth.com/) ([Auth0.com](https://auth0.com/docs)) clients. This also supports metadata discovery and the deprecated `rel="authorization_endpoint"` mechanisms.

If you are **NOT** looking for self-hosting, then you likely want to look at [IndieAuth.com](https://indieauth.com/) to find information on how you can use your existing social accounts for IndieAuth logins.

## Setup

1. Clone to `/usr/local/src/`
1. Run `dependencies.bash` to install dependent Ubuntu packages (like Apache HTTPd and PHP).
1. Run `setup.bash` to setup required directories and files.
1. Add configuration to your Apache HTTPd configuration
    ```
    Include /usr/local/src/mindie-idp/sitewide-metadata.conf
    Include /usr/local/src/mindie-idp/selfauth.conf
    Include /usr/local/src/mindie-idp/mintoken.conf
    ```
1. Trust your server
    ```bash
    sudo sqlite3 /var/lib/php-mintoken/tokens.sqlite3 'INSERT INTO settings VALUES ("endpoint", "https://example.com/selfauth/index");'
    ```

This will setup the following endpoints on your Apache server:
- https://example.com/.well-known/oauth-authorization-server
- https://example.com/selfauth/setup
- https://example.com/selfauth/index
- https://example.com/selfauth/token

## Usage

Use the https://example.com/selfauth/setup to add users.

To use with clients, you will need to add links to your profile.
```html
<link rel="indieauth-metadata" href="https://example.com/.well-known/oauth-authorization-server" />
<link rel="authorization_endpoint" href="https://example.com/selfauth/index" />
<link rel="token_endpoint" href="https://example.com/selfauth/token" />
```

## License

Copyright 2024 by carrvo

Available under the MIT license.

See [MIT-LICENSE.md](MIT-LICENSE.md) for the text of this license.

