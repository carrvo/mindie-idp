<html>
<head>
<title>
Setup Selfauth
</title>
<style>
h1{text-align:center;margin-top:5%;}
h2{text-align:center;}
.instructions{text-align:center;}
.message{margin-top:20px;text-align:center;font-size:1.2em;font-weight:bold;}
pre {width:400px; margin-left:auto; margin-right:auto;margin-bottom:50px;}
form{ 
margin-left:auto;
width:300px;
margin-right:auto;
text-align:center;
margin-top:20px;
border:solid 1px black;
padding:20px;
}
.form-line{ margin-top:5px;}
.submit{width:100%}
</style>
</head>
<body>
<h1>Setup Selfauth</h1>
<div>
<?php
define('RANDOM_BYTE_COUNT', 32);
define('SELFAUTH_SQLITE_PATH', getenv('SELFAUTH_SQLITE_PATH'));

$app_url = 'http' . (isset($_SERVER['HTTPS']) ? 's' : '') . '://' . $_SERVER['HTTP_HOST']
  . str_replace('setup', '', $_SERVER['REQUEST_URI']);

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

function load_user_config($app_url, $user_uri): mixed {
    $pdo = connectToDatabase();

    // checking single user
    $statement = $pdo->prepare('SELECT * FROM logins WHERE app_url = ? AND user_url = ?');
    $statement->execute([$app_url, $user_uri]);
    $config = $statement->fetch(PDO::FETCH_ASSOC);
    if ($config === false) {
        return null;
    }

    if ((!$config['app_url'] || $config['app_url'] == '')
        || (!$config['app_key'] || $config['app_key'] == '')
        || (!$config['user_hash'] || $config['user_hash'] == '')
        || (!$config['user_url'] || $config['user_url'] == '')
    ) {
        return null;
    }

    return $config;
}

function store_user_config(string $app_url, string $app_key, string $pass, string $user): void
{
    $pdo = connectToDatabase();
    for ($i = 0; $i < 10; $i++) {
        // We have to prepare inside the loop, https://github.com/teamtnt/tntsearch/pull/126
        $statement = $pdo->prepare('INSERT INTO logins (app_url, app_key, user_hash, user_url) VALUES (?, ?, ?, ?)');
        try {
            $statement->execute([$app_url, $app_key, $pass, $user]);
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
}

if (function_exists('random_bytes')) {
    $bytes = random_bytes(RANDOM_BYTE_COUNT);
    $strong_crypto = true;
} elseif (function_exists('openssl_random_pseudo_bytes')) {
    $bytes = openssl_random_pseudo_bytes(RANDOM_BYTE_COUNT, $strong_crypto);
} else {
    $bytes = '';
    for ($i=0; $i < RANDOM_BYTE_COUNT; $i++) {
        $bytes .= chr(mt_rand(0, 255));
    }
    $strong_crypto = false;
}
$app_key = bin2hex($bytes);

$configured = true;

if (isset($_POST['username'])) {
    $app_user = $_POST['username'];
    $config = load_user_config($app_user, null);
    if ($config === null) {
        $configured = false;
    }
} else {
    $configured = false;
}

if ($configured) : ?>
    <h2>System already configured</h2>
    <div class="instructions">
        If you with to reconfigure, please remove <?php $userfile ?> and reload this page.
    </div>

<?php else : ?>
    <?php if ($strong_crypto === false) : ?>
        <h2>
           WARNING: this version of PHP does not support functions 'random_bytes' or 'openssl_random_pseudo_bytes'. 
           This means your application is not as secure as it could be.  You may continues, but it is strongly recommended you upgrade PHP.
        </h2> 
    <?php endif; ?>

    <div class="instructions">In order to configure Selfauth, you need to fill in a few values, this page helps generate those options.</div>
    <?php if (isset($_POST['username'])) : ?>
    <div>
    <?php
    $app_url = 'http' . (isset($_SERVER['HTTPS']) ? 's' : '') . '://' . $_SERVER['HTTP_HOST'] . str_replace('setup', '', $_SERVER['REQUEST_URI']);

    $user = $_POST['username'];

    $user_tmp = trim(preg_replace('/^https?:\/\//', '', $_POST['username']), '/');
    $pass = md5($user_tmp . $_POST['password'] . $app_key);

    store_user_config($app_url, $app_key, $pass, $user);

    echo '<div class="message">Was successfully written to disk</div>';
?>
    </div>
    <?php endif ?>
    <form method="POST" action="">
    <div class="form-line"><label>Login Url:</label> <input name='username' /></div>
    <div class="form-line"><label>Password:</label> <input type='password' name='password' /></div>
    <div class="form-line"><input class="submit" type="submit" name="submit" value="Generate Config"/></div>
    </form>
<?php endif; ?>
</body>
</html>
