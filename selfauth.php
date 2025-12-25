<?php

require __DIR__ . '/selfauth/index.php';

$app_url = 'http' . (isset($_SERVER['HTTPS']) ? 's' : '') . '://' . $_SERVER['HTTP_HOST']
  . preg_replace('/index.*$/', '', $_SERVER['REQUEST_URI']);

// First handle verification of codes.
$code = get_verification_code();

if ($code !== null) {
    $redirect_uri = get_redirect_uri();
    $client_id = get_client_id();

    $configs = load_user_config($app_url);

    // Scan through the existing users then
    // Exit if there are errors in the client supplied data.
    $user_verified = user_verify($code, $redirect_uri, $client_id, $configs);
    if ($user_verified === false) {
        error_page('Verification Failed', 'Given Code Was Invalid');
    }

    $response = get_response($code, $user_verified);

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

verify_client_supplied_data($me, $config, $client_id, $redirect_uri, $state, $response_type, $scope);
if ($scope === '') { // scope is left empty.
    // Treat empty parameters as if omitted.
    $scope = null;
}

// If the user submitted a password, get ready to redirect back to the callback.

$pass_input_post = filter_input(INPUT_POST, 'password', FILTER_UNSAFE_RAW);

$csrf_code_post = filter_input(INPUT_POST, '_csrf', FILTER_UNSAFE_RAW);

$scope_post = filter_input_regexp(INPUT_POST, 'scopes', '@^[\x21\x23-\x5B\x5D-\x7E]+$@', FILTER_REQUIRE_ARRAY);

check_pass($redirect_uri, $client_id, $user_verified, $me, $state, $pass_input_post, $csrf_code_post, $scope_post);

// If neither password nor a code was submitted, we need to ask the user to authenticate.

$csrf_code = create_signed_code($config['app_key'], $client_id . $redirect_uri . $state, 2 * 60);

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
