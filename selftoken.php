<?php
declare(strict_types=1);

require __DIR__ . '/selfauth/index.php';
require __DIR__ . '/mintoken/endpoint.php';

$app_url = 'http' . (isset($_SERVER['HTTPS']) ? 's' : '') . '://' . $_SERVER['HTTP_HOST']
  . preg_replace('/token.*$/', '', $_SERVER['REQUEST_URI']);

$method = get_method();
if ($method === 'GET') {
    token_use();
} elseif ($method === 'POST') {
    $type = get_media_type();
    $action = get_token_action();
    $token = get_token();
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
        token_introspection($token, $tokenInfo);
    }
    // else is a POST+authorization request
    $request = get_request();


    // query SelfAuth library directly
    $configs = load_user_config($app_url);

    // Scan through the existing users then
    // Exit if there are errors in the client supplied data.
    $user_verified = user_verify($request['code'], $request['redirect_uri'], $request['client_id'], $configs);
    if ($user_verified === false) {
        invalidRequest('Verification Failed: Given Code Was Invalid');
    }

    $info = get_response($request['code'], $user_verified);
    // end SelfAuth library


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

