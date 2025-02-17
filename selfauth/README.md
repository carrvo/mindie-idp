# MIndie Identity Provider (IdP)

Original: [SelfAuth](https://github.com/Inklings-io/selfauth)
License: [MIT](MIT-LICENSE.md)

## Code Changes

### [README](README.md)

- section: MIndie Identity Provider (IdP)
- section: Multi-User Support
- section: Endpoints

### [schema](schema.sql)

- new file
- [multi-user support](https://github.com/Inklings-io/selfauth/pull/57) --> now [DB fix](https://github.com/carrvo/mindie-idp/issues/15)

### [setup](setup.php)

- [multi-user support](https://github.com/Inklings-io/selfauth/pull/57) --> now [DB fix](https://github.com/carrvo/mindie-idp/issues/15)
- line 98: remove `.php` extension because the endpoint is mapped to urlspace without it.

### [index](index.php)

- [support discovery](https://github.com/Inklings-io/selfauth/pull/55)
- [multi-user support](https://github.com/Inklings-io/selfauth/pull/57) --> now [DB fix](https://github.com/carrvo/mindie-idp/issues/15)
- [client discovery](https://github.com/Inklings-io/selfauth/pull/59)
- auto-click for configured anonymous user (lines 458-465)
- enforce some scope returned (lines 246-249)
- additional logging statements

# Selfauth

Selfauth is a self-hosted [Authorization Endpoint](https://indieweb.org/authorization-endpoint) used to login with a personal URL (as [Web sign-in](http://indieweb.org/Web_sign-in)) via [IndieAuth](https://indieweb.org/IndieAuth). See [How it works](#how-it-works) for more.

Selfauth is not a [Token Endpoint](https://indieweb.org/token-endpoint). To fully use Selfauth for authorization (and not just authentication) a separate token endpoint needs to be set-up, e.g. when using [Micropub](https://micropub.net/) clients. Examples of Token Endpoints are [listed on the wiki](https://indieweb.org/token_endpoint#IndieWeb_Examples).


## Warnings

- While Selfauth will work with old versions of PHP, some of the more secure functions Selfauth uses were not added until version 5.6. While older versions are not completely insecure, **it is strongly recommended you upgrade to a newer version of PHP**.


## Setup

To set up Selfauth, create a folder on your webserver and add the files in this repository to it. You can name the folder anything you like, but in this example we will work with 'auth' under `https://example.com/auth/`.

1. Create a folder called 'auth' on your webserver and add at least `index.php` and `setup.php`.

2. Go to `https://example.com/auth/setup.php` and fill in the form: pick the personal URL you're trying to log in for (in our case `https://example.com`) and choose a password.

3. Find the index-page of your domain and add the following code inside the `<head>` tag:
    ```html
    <link rel="authorization_endpoint" href="https://example.com/auth/" />
    ```
    ... where `https://example.com/auth/` is the URL you installed Selfauth to.
    (The exact location of your HTML `<head>` could be hidden in your CMS. Look for help in their documentation. Setting a HTTP Link header like `Link: <https://example.com/auth/>; rel="authorization_endpoint"` should work too.)

You can delete the file `setup.php` if you want, but this is optional. It will not be able to save a new password for you once the setup is completed.


### Multi-User Support
By default, only single users are supported. To enable multiple users with `setup.php` and `index.php`, set the environment variable `SELFAUTH_MULTIUSER` to `true`. When this is enabled, it store the config encoded with the user URI (e.g. entering `https://example.com/user/myuser/` will save the config as `config_https%3A%2F%2Fexample.com%2Fuser%2Fmyuser%2F.php`).

Optionally you can set the environment variable `SELFAUTH_CONFIG` to the directory you wish to store your user config `config*.php` files in. Ensure that the server has the permissions to create files in this directory.


## Changing your password

To change your password, make sure the `setup.php` file is in place again and delete `config.php`. Then follow the steps under [Setup](#setup) again.


## How it works

On a (Web)App which supports [IndieAuth](https://indieweb.org/IndieAuth), you can enter your personal URL. The App will detect Selfauth as Authorization Endpoint and redirect you to it. After you enter your password in Selfauth, you are redirected back to the App with a code. The App will verify the code with Selfauth and logs you in as your personal URL.

To test it, you can go to an App that supports IndieAuth and enter your personal URL. [IndieAuth.com](https://indieauth.com/) has a test-form on the frontpage. If you also link to your social media accounts using `rel="me"`, IndieAuth.com might show you a list of buttons.  To use Selfauth, click the one that has your Selfauth URL on it.


## Endpoints

### Login Form
```curl
curl --include 'https://example.com/auth/?response_type=code&me=https%3A%2F%2Fexample.com%2Fuser%2Ftest&redirect_uri=https%3A%2F%2Fexample.com%2Fclient%2Fredirect&client_id=https%3A%2F%2Fexample.com%2Fclient%2F&state=debc5ebf28088469&scope=profile+testscope&code_challenge=YFWSOwEz6EuAQOIg4X-lFIWAsdMO26A_NcaMFEH4RAU&code_challenge_method=S256'
```

### Login Submit
```curl
curl --include -X POST 'https://example.com/auth/?response_type=code&me=https%3A%2F%2Fexample.com%2Fuser%2Ftest&redirect_uri=https%3A%2F%2Fexample.com%2Fclient%2Fredirect&client_id=https%3A%2F%2Fexample.com%2Fclient%2F&state=debc5ebf28088469&scope=profile+testscope&code_challenge=YFWSOwEz6EuAQOIg4X-lFIWAsdMO26A_NcaMFEH4RAU&code_challenge_method=S256' -d '_csrf=<look for this field from the Form endpoint, it should end with a colon (:)>&password=<your password>'
```

### Verify Code
```curl
curl --include -X POST -H "Content-Type: application/x-www-form-urlencoded" -d 'grant_type=authorization_code&code=<from submit>&redirect_uri=https%3A%2F%2Fexample.com%2Fclient%2Fredirect.php&client_id=https%3A%2F%2Fexample.com%2Fclient%2F' 'https://testapache.local/auth/'
```

## License

Copyright 2017 by Ben Roberts and contributors

Available under the Creative Commons CC0 1.0 Universal and MIT licenses.

See CC0-LICENSE.md and MIT-LICENSE.md for the text of these licenses.

