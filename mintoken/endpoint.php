<?php
declare(strict_types=1);

define('MINTOKEN_SQLITE_PATH', getenv('MINTOKEN_SQLITE_PATH'));
define('MINTOKEN_CURL_TIMEOUT', (int)getenv('MINTOKEN_CURL_TIMEOUT'));
define('MINTOKEN_REVOKE_AFTER', getenv('MINTOKEN_REVOKE_AFTER'));

if (!file_exists(MINTOKEN_SQLITE_PATH)) {
    header('HTTP/1.1 500 Internal Server Error');
    header('Content-Type: text/plain;charset=UTF-8');
    exit('The token endpoint is not ready for use.');
}

function connectToDatabase(): PDO
{
    static $pdo;
    if (!isset($pdo)) {
        $pdo = new PDO('sqlite:' . MINTOKEN_SQLITE_PATH, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
    }
    return $pdo;
}

function initCurl(string $url)/* : resource */
{
    $curl = curl_init();
    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($curl, CURLOPT_MAXREDIRS, 8);
    curl_setopt($curl, CURLOPT_TIMEOUT_MS, round(MINTOKEN_CURL_TIMEOUT * 1000));
    curl_setopt($curl, CURLOPT_CONNECTTIMEOUT_MS, 2000);
    curl_setopt($curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2);
    return $curl;
}

function storeToken(string $me, string $client_id, string $scope): string
{
    $pdo = connectToDatabase();
    do {
        $hashable = substr(str_replace(chr(0), '', random_bytes(100)), 0, 72);
        $hash = password_hash($hashable, PASSWORD_BCRYPT);
    } while (strlen($hashable) !== 72 || $hash === false);
    for ($i = 0; $i < 10; $i++) {
        $lastException = null;
        $id = bin2hex(random_bytes(32));
        $revokeColumn = '';
        $revokeValue = '';
        $revoking = [];
        if (is_string(MINTOKEN_REVOKE_AFTER) && strlen(MINTOKEN_REVOKE_AFTER) > 0) {
            $revokeColumn = ', revoked';
            $revokeValue = ', datetime(CURRENT_TIMESTAMP, ?)';
            $revoking = ['+' . MINTOKEN_REVOKE_AFTER];
        }
        // We have to prepare inside the loop, https://github.com/teamtnt/tntsearch/pull/126
        $statement = $pdo->prepare('INSERT INTO tokens (token_id, token_hash, auth_me, auth_client_id, auth_scope' . $revokeColumn . ') VALUES (?, ?, ?, ?, ?' . $revokeValue . ')');
        try {
            $statement->execute(array_merge([$id, $hash, $me, $client_id, $scope], $revoking));
        } catch (PDOException $e) {
            $lastException = $e;
            if ($statement->errorInfo()[1] !== 19) {
                throw $e;
            }
            continue;
        }
        break;
    }
    if ($lastException !== null) {
        throw $e;
    }
    return $id . '_' . bin2hex($hashable);
}

function retrieveToken(string $token): ?array
{
    list($id, $hashable) = explode('_', $token);
    $pdo = connectToDatabase();
    $statement = $pdo->prepare('SELECT *, revoked > CURRENT_TIMESTAMP AS active FROM tokens WHERE token_id = ?');
    $statement->execute([$id]);
    $token = $statement->fetch(PDO::FETCH_ASSOC);
    if ($token !== false && password_verify(hex2bin($hashable), $token['token_hash'])) {
        return $token;
    }
    return null;
}

function markTokenUsed(string $tokenId): void
{
    $pdo = connectToDatabase();
    $statement = $pdo->prepare('UPDATE tokens SET last_use = CURRENT_TIMESTAMP WHERE token_id = ? AND (last_use IS NULL OR last_use < CURRENT_TIMESTAMP)');
    $statement->execute([$tokenId]);
}

function revokeToken(string $token): void
{
    $token = retrieveToken($token);
    if ($token !== null) {
        $pdo = connectToDatabase();
        $statement = $pdo->prepare('UPDATE tokens SET revoked = CURRENT_TIMESTAMP WHERE token_id = ? AND (revoked IS NULL OR revoked > CURRENT_TIMESTAMP)');
        $statement->execute([$token['token_id']]);
    }
}

function getTrustedEndpoints(): array
{
    $pdo = connectToDatabase();
    $statement = $pdo->prepare('SELECT setting_value FROM settings WHERE setting_name = ?');
    $statement->execute(['endpoint']);
    $nextValue = $statement->fetchColumn();
    while ($nextValue) {
        $trusted[] = $nextValue;
        $nextValue = $statement->fetchColumn();
    }
    return $trusted;
}

function verifyCode(string $code, string $client_id, string $redirect_uri, string $endpoint): ?array
{
    $curl = initCurl($endpoint);
    curl_setopt($curl, CURLOPT_POST, true);
    curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query([
        'code' => $code,
        'client_id' => $client_id,
        'redirect_uri' => $redirect_uri,
    ]));
    curl_setopt($curl, CURLOPT_HTTPHEADER, ['Accept: application/json']);
    $body = curl_exec($curl);
    curl_close($curl);
    $info = json_decode($body, true, 2);
    if (json_last_error() !== JSON_ERROR_NONE) {
        error_log('Failed to decode '.$body);
        return null;
    }
    $info = filter_var_array($info, [
        'me' => FILTER_VALIDATE_URL,
        'scope' => [
            'filter' => FILTER_VALIDATE_REGEXP,
            'options' => ['regexp' => '@^[\x21\x23-\x5B\x5D-\x7E]+( [\x21\x23-\x5B\x5D-\x7E]+)*$@'],
        ],
    ]);
    if (in_array(null, $info, true) || in_array(false, $info, true)) {
    error_log('Found null or false in '.print_r($info, true).' during code verification');
        return null;
    }
    return $info;
}

function invalidRequest(string $log): void
{
    error_log($log);
    // This is probably wrong, but RFC 6750 is a little unclear.
    // Maybe this should be handled per RFC 6749, putting the error code in the redirect?
    header('HTTP/1.1 400 Bad Request');
    header('Content-Type: text/plain;charset=UTF-8');
    exit('invalid_request');
}

$method = filter_input(INPUT_SERVER, 'REQUEST_METHOD', FILTER_VALIDATE_REGEXP, ['options' => ['regexp' => '@^[!#$%&\'*+.^_`|~0-9a-z-]+$@i']]);
if ($method === 'GET') {
    $bearer_regexp = '@^Bearer [0-9a-f]+_[0-9a-f]+$@';
    $authorization = filter_input(INPUT_SERVER, 'HTTP_AUTHORIZATION', FILTER_VALIDATE_REGEXP, ['options' => ['regexp' => $bearer_regexp]])
        ?? filter_input(INPUT_SERVER, 'REDIRECT_HTTP_AUTHORIZATION', FILTER_VALIDATE_REGEXP, ['options' => ['regexp' => $bearer_regexp]]);
    if ($authorization === null && function_exists('apache_request_headers')) {
        $headers = array_change_key_case(apache_request_headers(), CASE_LOWER);
        if (isset($headers['authorization'])) {
            $authorization = filter_var($headers['authorization'], FILTER_VALIDATE_REGEXP, ['options' => ['regexp' => $bearer_regexp]]);
        }
    }
    if ($authorization === null) {
        header('HTTP/1.1 401 Unauthorized');
        header('WWW-Authenticate: Bearer');
        exit();
    } elseif ($authorization === false) {
        header('HTTP/1.1 401 Unauthorized');
        header('WWW-Authenticate: Bearer, error="invalid_token", error_description="The access token is malformed"');
        exit();
    } else {
        $token = retrieveToken(substr($authorization, 7));
        if ($token === null) {
            header('HTTP/1.1 401 Unauthorized');
            header('WWW-Authenticate: Bearer, error="invalid_token", error_description="The access token is unknown"');
            exit();
        } elseif ($token['active'] === '0') {
            header('HTTP/1.1 401 Unauthorized');
            header('WWW-Authenticate: Bearer, error="invalid_token", error_description="The access token is revoked"');
            exit();
        } else {
            header('HTTP/1.1 200 OK');
            header('Content-Type: application/json;charset=UTF-8');
            markTokenUsed($token['token_id']);
            exit(json_encode([
                'me' => $token['auth_me'],
                'client_id' => $token['auth_client_id'],
                'scope' => $token['auth_scope'],
            ]));
        }
    }
} elseif ($method === 'POST') {
    $type = filter_input(INPUT_SERVER, 'CONTENT_TYPE', FILTER_VALIDATE_REGEXP, ['options' => ['regexp' => '@^application/x-www-form-urlencoded(;.*)?$@']]);
    if (!is_string($type)) {
        header('HTTP/1.1 415 Unsupported Media Type');
        exit();
    }
    $action = filter_input(INPUT_GET, 'action', FILTER_VALIDATE_REGEXP, ['options' => ['regexp' => '@^(revoke|introspect|authorize)$@']]);
    $token = filter_input(INPUT_POST, 'token', FILTER_VALIDATE_REGEXP, ['options' => ['regexp' => '@^[0-9a-f]+_[0-9a-f]+$@']]);
    if (!is_string($action)) {
        invalidRequest('no action provided');
    }
    // check if is POST+revoke request
    if ($action === 'revoke') {
        if (is_string($token)) {
            revokeToken($token);
        }
        header('HTTP/1.1 200 OK');
        exit();
    }
    // check if is POST+introspection request
    if ($action === 'introspect') {
        $tokenInfo = retrieveToken($token);
        if ($tokenInfo === null || $tokenInfo['active'] === '0') {
            header('HTTP/1.1 200 OK');
            header('Content-Type: application/json;charset=UTF-8');
            exit(json_encode([
                'active' => false,
            ]));
        }
        // Authorize resource server as per specification (see https://indieauth.spec.indieweb.org/#access-token-verification-response-p-1)
        // For us this means we are expecting the Basic user to be the client ID of the consumer.
        // With basic, everything after the first colon (:) is considered the password.
        // Since we are working with URIs to identify, we need to handle
        // the pattern scheme://domain/path:password
        // To do this, we assume (and enforce) that the password is a single underscore (_).
        $basicAuth = $_SERVER['PHP_AUTH_USER'] . ':' . $_SERVER['PHP_AUTH_PW'];
        $storedAuth = $tokenInfo['auth_client_id'] . ':_';
        $storedAuthEncoded = urlencode($tokenInfo['auth_client_id']) . ':_';
        if ($storedAuth !== $basicAuth && $storedAuthEncoded !== $basicAuth) {
            header('WWW-Authenticate: Basic');
            header('HTTP/1.0 401 Unauthorized');
            exit('Unauthorized');
        }
        header('HTTP/1.1 200 OK');
        header('Content-Type: application/json;charset=UTF-8');
        exit(json_encode([
            'token_type' => 'Bearer',
            'me' => $tokenInfo['auth_me'],
            'sub' => $tokenInfo['auth_me'],
            'client_id' => $tokenInfo['auth_client_id'],
            'scope' => $tokenInfo['auth_scope'],
            'iat' => strtotime($tokenInfo['created']),
            'exp' => strtotime($tokenInfo['revoked']),
            'active' => true,
        ]));
    }
    // else is a POST+authorization request
    $request = filter_input_array(INPUT_POST, [
        'grant_type' => [
            'filter' => FILTER_VALIDATE_REGEXP,
            'options' => ['regexp' => '@^authorization_code$@'],
        ],
        'code' => [
            'filter' => FILTER_VALIDATE_REGEXP,
            'options' => ['regexp' => '@^[\x20-\x7E]+$@'],
        ],
        'client_id' => FILTER_VALIDATE_URL,
        'redirect_uri' => FILTER_VALIDATE_URL,
    ]);
    if (in_array(null, $request, true) || in_array(false, $request, true)) {
        invalidRequest('missing field for request: '.print_r($request, true));
    }
    $endpoints = getTrustedEndpoints();
    foreach ($endpoints as $endpoint) {
        $info = verifyCode($request['code'], $request['client_id'], $request['redirect_uri'], $endpoint);
        if ($info !== null) {
            break;
        }
    }
    if ($info === null) {
        invalidRequest('no trusted endpoint accepted the code');
    }
    $token = storeToken($info['me'], $request['client_id'], $info['scope']);
    header('HTTP/1.1 200 OK');
    header('Content-Type: application/json;charset=UTF-8');
    exit(json_encode([
        'access_token' => $token,
        'token_type' => 'Bearer',
        'scope' => $info['scope'],
        'me' => $info['me'],
    ]));
} else {
    header('HTTP/1.1 405 Method Not Allowed');
    header('Allow: GET, POST');
    exit();
}

/**
 * The following wall of code is dangerous. There be dragons.
 * Taken from the mf2-php project, which is pledged to the public domain under CC0.
 */
function parseUriToComponents(string $uri): array
{
    $result = [
        'scheme' => null,
        'authority' => null,
        'path' => null,
        'query' => null,
        'fragment' => null,
    ];
    $u = @parse_url($uri);
    if (array_key_exists('scheme', $u)) {
        $result['scheme'] = $u['scheme'];
    }
    if (array_key_exists('host', $u)) {
        if (array_key_exists('user', $u)) {
            $result['authority'] = $u['user'];
        }
        if (array_key_exists('pass', $u)) {
            $result['authority'] .= ':' . $u['pass'];
        }
        if (array_key_exists('user', $u) || array_key_exists('pass', $u)) {
            $result['authority'] .= '@';
        }
        $result['authority'] .= $u['host'];
        if (array_key_exists('port', $u)) {
            $result['authority'] .= ':' . $u['port'];
        }
    }
    if (array_key_exists('path', $u)) {
        $result['path'] = $u['path'];
    }
    if (array_key_exists('query', $u)) {
        $result['query'] = $u['query'];
    }
    if (array_key_exists('fragment', $u)) {
        $result['fragment'] = $u['fragment'];
    }
    return $result;
}
function resolveUrl(string $baseURI, string $referenceURI): string
{
    $target = [
        'scheme' => null,
        'authority' => null,
        'path' => null,
        'query' => null,
        'fragment' => null,
    ];
    $base = parseUriToComponents($baseURI);
    if ($base['path'] == null) {
        $base['path'] = '/';
    }
    $reference = parseUriToComponents($referenceURI);
    if ($reference['scheme']) {
        $target['scheme'] = $reference['scheme'];
        $target['authority'] = $reference['authority'];
        $target['path'] = removeDotSegments($reference['path']);
        $target['query'] = $reference['query'];
    } else {
        if ($reference['authority']) {
            $target['authority'] = $reference['authority'];
            $target['path'] = removeDotSegments($reference['path']);
            $target['query'] = $reference['query'];
        } else {
            if ($reference['path'] == '') {
                $target['path'] = $base['path'];
                if ($reference['query']) {
                    $target['query'] = $reference['query'];
                } else {
                    $target['query'] = $base['query'];
                }
            } else {
                if (substr($reference['path'], 0, 1) == '/') {
                    $target['path'] = removeDotSegments($reference['path']);
                } else {
                    $target['path'] = mergePaths($base, $reference);
                    $target['path'] = removeDotSegments($target['path']);
                }
                $target['query'] = $reference['query'];
            }
            $target['authority'] = $base['authority'];
        }
        $target['scheme'] = $base['scheme'];
    }
    $target['fragment'] = $reference['fragment'];
    $result = '';
    if ($target['scheme']) {
        $result .= $target['scheme'] . ':';
    }
    if ($target['authority']) {
        $result .= '//' . $target['authority'];
    }
    $result .= $target['path'];
    if ($target['query']) {
        $result .= '?' . $target['query'];
    }
    if ($target['fragment']) {
        $result .= '#' . $target['fragment'];
    } elseif ($referenceURI == '#') {
        $result .= '#';
    }
    return $result;
}
function mergePaths(array $base, array $reference): string
{
    if ($base['authority'] && $base['path'] == null) {
        $merged = '/' . $reference['path'];
    } else {
        if (($pos=strrpos($base['path'], '/')) !== false) {
            $merged = substr($base['path'], 0, $pos + 1) . $reference['path'];
        } else {
            $merged = $base['path'];
        }
    }
    return $merged;
}
function removeLeadingDotSlash(string &$input): void
{
    if (substr($input, 0, 3) == '../') {
        $input = substr($input, 3);
    } elseif (substr($input, 0, 2) == './') {
        $input = substr($input, 2);
    }
}
function removeLeadingSlashDot(string &$input): void
{
    if (substr($input, 0, 3) == '/./') {
        $input = '/' . substr($input, 3);
    } else {
        $input = '/' . substr($input, 2);
    }
}
function removeOneDirLevel(string &$input, string &$output): void
{
    if (substr($input, 0, 4) == '/../') {
        $input = '/' . substr($input, 4);
    } else {
        $input = '/' . substr($input, 3);
    }
    $output = substr($output, 0, strrpos($output, '/'));
}
function removeLoneDotDot(string &$input): void
{
    if ($input == '.') {
        $input = substr($input, 1);
    } else {
        $input = substr($input, 2);
    }
}
function moveOneSegmentFromInput(string &$input, string &$output): void
{
    if (substr($input, 0, 1) != '/') {
        $pos = strpos($input, '/');
    } else {
        $pos = strpos($input, '/', 1);
    }
    if ($pos === false) {
        $output .= $input;
        $input = '';
    } else {
        $output .= substr($input, 0, $pos);
        $input = substr($input, $pos);
    }
}
function removeDotSegments(string $path): string
{
    $input = $path;
    $output = '';
    $step = 0;
    while ($input) {
        $step++;
        if (substr($input, 0, 3) == '../' || substr($input, 0, 2) == './') {
            removeLeadingDotSlash($input);
        } elseif (substr($input, 0, 3) == '/./' || $input == '/.') {
            removeLeadingSlashDot($input);
        } elseif (substr($input, 0, 4) == '/../' || $input == '/..') {
            removeOneDirLevel($input, $output);
        } elseif ($input == '.' || $input == '..') {
            removeLoneDotDot($input);
        } else {
            moveOneSegmentFromInput($input, $output);
        }
    }
    return $output;
}
