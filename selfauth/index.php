<?php
define('SELFAUTH_SQLITE_PATH', getenv('SELFAUTH_SQLITE_PATH'));

$app_url = 'http' . (isset($_SERVER['HTTPS']) ? 's' : '') . '://' . $_SERVER['HTTP_HOST']
  . preg_replace('/index.*$/', '', $_SERVER['REQUEST_URI']);

if (!file_exists(SELFAUTH_SQLITE_PATH)) {
    header('HTTP/1.1 500 Internal Server Error');
    header('Content-Type: text/plain;charset=UTF-8');
    exit('The SelfAuth is not ready for use.');
}

function connectToDatabase(): PDO
{
    static $pdo;
    if (!isset($pdo)) {
        $pdo = new PDO('sqlite:' . SELFAUTH_SQLITE_PATH, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
    }
    return $pdo;
}

function error_page($header, $body, $http = '400 Bad Request')
{
    $protocol = isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0';
    header($protocol . ' ' . $http);
    error_log($protocol . ' ' . $http . ' Error: ' . $header . ' - ' . $body);
    $html = <<<HTML
<!doctype html>
<html>
    <head>
        <style>
            .error{
                width:100%;
                text-align:center;
                margin-top:10%;
            }
        </style>
        <title>Error: $header</title>
    </head>
    <body>
        <div class='error'>
            <h1>Error: $header</h1>
            <p>$body</p>
        </div>
    </body>
</html>
HTML;
    die($html);
}

// Enable string comparison in constant time.
if (!function_exists('hash_equals')) {
    function hash_equals($known_string, $user_string)
    {
        $known_length = strlen($known_string);
        if ($known_length !== strlen($user_string)) {
            return false;
        }
        $match = 0;
        for ($i = 0; $i < $known_length; $i++) {
            $match |= (ord($known_string[$i]) ^ ord($user_string[$i]));
        }
        return $match === 0;
    }
}

// Signed codes always have an time-to-live, by default 1 year (31536000 seconds).
function create_signed_code($key, $message, $ttl = 31536000, $appended_data = '')
{
    $expires = time() + $ttl;
    $body = $message . $expires . $appended_data;
    $signature = hash_hmac('sha256', $body, $key);
    return dechex($expires) . ':' . $signature . ':' . base64_url_encode($appended_data);
}

function verify_signed_code($key, $message, $code)
{
    $code_parts = explode(':', $code, 3);
    if (count($code_parts) !== 3) {
        return false;
    }
    $expires = hexdec($code_parts[0]);
    if (time() > $expires) {
        return false;
    }
    $body = $message . $expires . base64_url_decode($code_parts[2]);
    $signature = hash_hmac('sha256', $body, $key);
    return hash_equals($signature, $code_parts[1]);
}

function verify_password($pass, $config)
{
    $hash_user = trim(preg_replace('/^https?:\/\//', '', $config['user_url']), '/');
    $hash = md5($hash_user . $pass . $config['app_key']);

    return hash_equals($config['user_hash'], $hash);
}

function filter_input_regexp($type, $variable, $regexp, $flags = null)
{
    $options = array(
        'options' => array('regexp' => $regexp)
    );
    if ($flags !== null) {
        $options['flags'] = $flags;
    }
    return filter_input(
        $type,
        $variable,
        FILTER_VALIDATE_REGEXP,
        $options
    );
}

function get_q_value($mime, $accept)
{
    $fulltype = preg_replace('@^([^/]+\/).+$@', '$1*', $mime);
    $regex = implode(
        '',
        array(
            '/(?<=^|,)\s*(\*\/\*|',
            preg_quote($fulltype, '/'),
            '|',
            preg_quote($mime, '/'),
            ')\s*(?:[^,]*?;\s*q\s*=\s*([0-9.]+))?\s*(?:,|$)/'
        )
    );
    $out = preg_match_all($regex, $accept, $matches);
    $types = array_combine($matches[1], $matches[2]);
    if (array_key_exists($mime, $types)) {
        $q = $types[$mime];
    } elseif (array_key_exists($fulltype, $types)) {
        $q = $types[$fulltype];
    } elseif (array_key_exists('*/*', $types)) {
        $q = $types['*/*'];
    } else {
        return 0;
    }
    return $q === '' ? 1 : floatval($q);
}

// URL Safe Base64 per https://tools.ietf.org/html/rfc7515#appendix-C

function base64_url_encode($string)
{
    $string = base64_encode($string);
    $string = rtrim($string, '=');
    $string = strtr($string, '+/', '-_');
    return $string;
}

function base64_url_decode($string)
{
    $string = strtr($string, '-_', '+/');
    $padding = strlen($string) % 4;
    if ($padding !== 0) {
        $string .= str_repeat('=', 4 - $padding);
    }
    $string = base64_decode($string);
    return $string;
}

function load_user_config($app_url, $user_uri=null): array {
    $pdo = connectToDatabase();

    // searching for user
    if ($user_uri === null) {
        $statement = $pdo->prepare('SELECT * FROM logins WHERE app_url = ?');
        $statement->execute([$app_url]);
        $configs = $statement->fetchall(PDO::FETCH_ASSOC);
        if ($configs === false || count($configs) === 0) {
            error_page(
                'Configuration Error',
                'Endpoint not yet configured, visit <a href="setup">setup</a> for instructions on how to set it up.'
            );
        }
        return $configs;
    }

    // checking single user
    $statement = $pdo->prepare('SELECT * FROM logins WHERE app_url = ? AND user_url = ?');
    $statement->execute([$app_url, $user_uri]);
    $config = $statement->fetch(PDO::FETCH_ASSOC);
    if ($config === false) {
        error_page(
            'Configuration Error',
            'Endpoint not yet configured, visit <a href="setup">setup</a> for instructions on how to set it up.'
        );
    }

    if ((!$config['app_url'] || $config['app_url'] == '')
        || (!$config['app_key'] || $config['app_key'] == '')
        || (!$config['user_hash'] || $config['user_hash'] == '')
        || (!$config['user_url'] || $config['user_url'] == '')
    ) {
        error_page(
            'Configuration Error',
            'Endpoint not configured correctly, visit <a href="setup">setup</a> for instructions on how to set it up.'
        );
    }

    return [$config];
}

// First handle verification of codes.
$code = filter_input_regexp(INPUT_POST, 'code', '@^[0-9a-f]+:[0-9a-f]{64}:@');

if ($code !== null) {
    $redirect_uri = filter_input(INPUT_POST, 'redirect_uri', FILTER_VALIDATE_URL);
    $client_id = filter_input(INPUT_POST, 'client_id', FILTER_VALIDATE_URL);

    $configs = load_user_config($app_url);

    // Scan through the existing users then
    // Exit if there are errors in the client supplied data.
    $user_verified = false;
    foreach ($configs as $config) {
        if (!(is_string($code)
            && is_string($redirect_uri)
            && is_string($client_id)
            && verify_signed_code($config['app_key'], $config['user_url'] . $redirect_uri . $client_id, $code))
        ) {
            // NOT valid for this user
            continue;
        }
        else {
            $user_verified = true;
            break;
        }
    }
    if ($user_verified !== true) {
        error_page('Verification Failed', 'Given Code Was Invalid');
    }

    $response = array('me' => $config['user_url']);

    $code_parts = explode(':', $code, 3);

    if ($code_parts[2] !== '') {
        $response['scope'] = base64_url_decode($code_parts[2]);
    }
    else {
        # MinToken requires there to be *some* scope as a part of ensuring a valid reply
        $response['scope'] = 'none';
    }

    // Accept header
    $accept_header = '*/*';
    if (isset($_SERVER['HTTP_ACCEPT']) && strlen($_SERVER['HTTP_ACCEPT']) > 0) {
        $accept_header = $_SERVER['HTTP_ACCEPT'];
    }

    // Find the q value for application/json.
    $json = get_q_value('application/json', $accept_header);

    // Find the q value for application/x-www-form-urlencoded.
    $form = get_q_value('application/x-www-form-urlencoded', $accept_header);

    // Respond in the correct way.
    if ($json === 0 && $form === 0) {
        error_page(
            'No Accepted Response Types',
            'The client accepts neither JSON nor Form encoded responses.',
            '406 Not Acceptable'
        );
    } elseif ($json >= $form) {
        header('Content-Type: application/json');
        exit(json_encode($response));
    } else {
        header('Content-Type: application/x-www-form-urlencoded');
        exit(http_build_query($response));
    }
}

// If this is not verification, collect all the client supplied data. Exit on errors.

$me = filter_input(INPUT_GET, 'me', FILTER_VALIDATE_URL);
$config = load_user_config($app_url, $me)[0];
$client_id = filter_input(INPUT_GET, 'client_id', FILTER_VALIDATE_URL);
$redirect_uri = filter_input(INPUT_GET, 'redirect_uri', FILTER_VALIDATE_URL);
$state = filter_input_regexp(INPUT_GET, 'state', '@^[\x20-\x7E]*$@');
$response_type = filter_input_regexp(INPUT_GET, 'response_type', '@^(id|code)?$@');
$scope = filter_input_regexp(INPUT_GET, 'scope', '@^([\x21\x23-\x5B\x5D-\x7E]+( [\x21\x23-\x5B\x5D-\x7E]+)*)?$@');

if (!is_string($client_id)) { // client_id is either omitted or not a valid URL.
    error_page(
        'Faulty Request',
        'There was an error with the request. The "client_id" field is invalid.'
    );
}
if (!is_string($redirect_uri)) { // redirect_uri is either omitted or not a valid URL.
    error_page(
        'Faulty Request',
        'There was an error with the request. The "redirect_uri" field is invalid.'
    );
}
if ($state === false) { // state contains invalid characters.
    error_page(
        'Faulty Request',
        'There was an error with the request. The "state" field contains invalid data.'
    );
}
if ($response_type === false) { // response_type is given as something other than id or code.
    error_page(
        'Faulty Request',
        'There was an error with the request. The "response_type" field must be "code".'
    );
}
if ($scope === false) { // scope contains invalid characters.
    error_page(
        'Faulty Request',
        'There was an error with the request. The "scope" field contains invalid data.'
    );
}
if ($scope === '') { // scope is left empty.
    // Treat empty parameters as if omitted.
    $scope = null;
}

// If the user submitted a password, get ready to redirect back to the callback.

$pass_input = filter_input(INPUT_POST, 'password', FILTER_UNSAFE_RAW);

if ($pass_input !== null) {
    $csrf_code = filter_input(INPUT_POST, '_csrf', FILTER_UNSAFE_RAW);

    // Exit if the CSRF does not verify.
    if ($csrf_code === null || !verify_signed_code($config['app_key'], $client_id . $redirect_uri . $state, $csrf_code)) {
        error_page(
            'Invalid CSF Code',
            'Usually this means you took too long to log in. Please try again.'
        );
    }

    // Exit if the password does not verify.
    if (!verify_password($pass_input, $config)) {
        // Optional logging for failed logins.
        //
        // Enabling this on shared hosting may not be a good idea if syslog
        // isn't private and accessible. Enable with caution.
        if (function_exists('syslog') && defined('SYSLOG_FAILURE') && SYSLOG_FAILURE === 'I understand') {
            syslog(LOG_CRIT, sprintf(
                'IndieAuth: login failure from %s for %s',
                $_SERVER['REMOTE_ADDR'],
                $me
            ));
        }

        error_page('Login Failed', 'Invalid password.');
    }

    $scope = filter_input_regexp(INPUT_POST, 'scopes', '@^[\x21\x23-\x5B\x5D-\x7E]+$@', FILTER_REQUIRE_ARRAY);

    // Scopes are defined.
    if ($scope !== null) {
        // Exit if the scopes ended up with illegal characters or were not supplied as array.
        if ($scope === false || in_array(false, $scope, true)) {
            error_page('Invalid Scopes', 'The scopes provided contained illegal characters.');
        }

        // Turn scopes into a single string again.
        $scope = implode(' ', $scope);
    }

    $code = create_signed_code($config['app_key'], $config['user_url'] . $redirect_uri . $client_id, 5 * 60, $scope);

    $final_redir = $redirect_uri;
    if (strpos($redirect_uri, '?') === false) {
        $final_redir .= '?';
    } else {
        $final_redir .= '&';
    }
    $issuer = 'http' . (isset($_SERVER['HTTPS']) ? 's' : '') . '://' . $_SERVER['HTTP_HOST']; // this is the same as in setup.php
    $parameters = array(
        'code' => $code,
        'iss' => $issuer,
        'me' => $config['user_url']
    );
    if ($state !== null) {
        $parameters['state'] = $state;
    }
    $final_redir .= http_build_query($parameters);

    // Optional logging for successful logins.
    //
    // Enabling this on shared hosting may not be a good idea if syslog
    // isn't private and accessible. Enable with caution.
    if (function_exists('syslog') && defined('SYSLOG_SUCCESS') && SYSLOG_SUCCESS === 'I understand') {
        syslog(LOG_INFO, sprintf(
            'IndieAuth: login from %s for %s',
            $_SERVER['REMOTE_ADDR'],
            $me
        ));
    }

    // Redirect back.
    header('Location: ' . $final_redir, true, 302);
    exit();
}

// If neither password nor a code was submitted, we need to ask the user to authenticate.

$csrf_code = create_signed_code($config['app_key'], $client_id . $redirect_uri . $state, 2 * 60);

function client_info(string $client_id) : ?array {
    if (function_exists('curl_init') !== true) {
        return null;
    }
    $curl = curl_init();
    curl_setopt($curl, CURLOPT_URL, $client_id);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($curl, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($curl, CURLOPT_TIMEOUT_MS, round(4 * 1000));
    curl_setopt($curl, CURLOPT_CONNECTTIMEOUT_MS, 2000);
    curl_setopt($curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2);
    curl_setopt($curl, CURLOPT_HTTPHEADER, ['Accept: application/json']);
    $body = curl_exec($curl);
    curl_close($curl);
    $info = json_decode($body, true, 3);
    if (json_last_error() !== JSON_ERROR_NONE) {
        return null;
    }
    return $info;
}

$client_meta = client_info($client_id);

?><!doctype html>
<html>
    <head>
        <title>Login</title>
        <style>
h1{text-align:center;margin-top:3%;}
body {text-align:center;}
fieldset, pre {width:400px; margin-left:auto; margin-right:auto;margin-bottom:50px; background-color:#FFC; min-height:1em;}
.client-title {width:400px; margin-left:auto; margin-right:auto; min-height:1em;}
.client-meta {width:400px; margin-left:auto; margin-right:auto;margin-bottom:50px; min-height:1em;}
fieldset {text-align:left;}

.form-login{ 
margin-left:auto;
width:300px;
margin-right:auto;
text-align:center;
margin-top:20px;
border:solid 1px black;
padding:20px;
}
.form-line{ margin:5px 0 0 0;}
.submit{width:100%}
.yellow{background-color:#FFC}

        </style>
        <?php if (strcmp(getenv('SELFAUTH_ANONYMOUS_USER'), $config['user_url']) === 0) : ?>
        <script>
        document.addEventListener("DOMContentLoaded", (event) => {
            document.getElementById("password").value = "<?php echo getenv('SELFAUTH_ANONYMOUS_PASS') ?>";
            document.getElementsByClassName("submit")[0].click();
        });
        </script>
        <?php endif; ?>
    </head>
    <body>
        <form method="POST" action="">
            <h1>Authenticate</h1>
            <div>You are attempting to login with client <pre><?php echo htmlspecialchars($client_id); ?></pre></div>
            <?php if (isset($client_meta)) : ?>
            <div class="client-title">
                <?php if (isset($client_meta['client_logo'])) : ?>
                <img src="<?php echo htmlspecialchars($client_meta['client_logo']) ?>" alt="[logo]" />
                <?php endif; ?>
                <?php if (isset($client_meta['client_name'])) : ?>
                <span><?php echo htmlspecialchars($client_meta['client_name']) ?></span>
                <?php endif; ?>
            </div>
            <div class="client-meta">
                <?php if (isset($client_meta['client_uri'])) : ?>
                <a href="<?php echo htmlspecialchars($client_meta['client_uri']) ?>">Webpage</a>
                <?php endif; ?>
                <?php if (isset($client_meta['client_tos'])) : ?>
                <a href="<?php echo htmlspecialchars($client_meta['client_tos']) ?>">Terms of Service</a>
                <?php endif; ?>
                <?php if (isset($client_meta['client_policy'])) : ?>
                <a href="<?php echo htmlspecialchars($client_meta['client_policy']) ?>">Privacy Policy</a>
                <?php endif; ?>
            </div>
            <?php endif; ?>
            <?php if (strlen($scope) > 0) : ?>
            <div>It is requesting the following scopes, uncheck any you do not wish to grant:</div>
            <fieldset>
                <legend>Scopes</legend>
                <?php foreach (explode(' ', $scope) as $n => $checkbox) : ?>
                <div>
                    <input id="scope_<?php echo $n; ?>" type="checkbox" name="scopes[]" value="<?php echo htmlspecialchars($checkbox); ?>" checked>
                    <label for="scope_<?php echo $n; ?>"><?php echo $checkbox; ?></label>
                </div>
                <?php endforeach; ?>
            </fieldset>
            <?php endif; ?>
            <div>After login you will be redirected to  <pre><?php echo htmlspecialchars($redirect_uri); ?></pre></div>
            <div class="form-login">
                <input type="hidden" name="_csrf" value="<?php echo $csrf_code; ?>" />
                <p class="form-line">
                    Logging in as:<br />
                    <span class="yellow"><?php echo htmlspecialchars($config['user_url']); ?></span>
                </p>
                <div class="form-line">
                    <label for="password">Password:</label><br />
                    <input type="password" name="password" id="password" />
                </div>
                <div class="form-line">
                    <input class="submit" type="submit" name="submit" value="Submit" />
                </div>
            </div>
        </form>
    </body>
</html>
