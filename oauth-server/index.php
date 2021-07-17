<?php

function fixtures()
{
    write_file([
        [
            "user_id" => "user_6087d1978824c4.38987336",
            "firstname" => "Jean",
            "lastname" => "Dupond",
            "username" => "jdup",
            "password" => "jdup"
        ]
    ], "./data/user.data");
}

function read_file($file)
{
    if (!file_exists($file)) {
        throw new \Exception("{$file} not exists");
    }
    $data = file($file);
    return array_map(fn($item) => unserialize($item), $data);
}

function write_file($data, $file)
{
    $data = array_map(fn($item) => serialize($item), $data);
    return file_put_contents($file, implode(PHP_EOL, $data));
}

function register()
{
    ['name' => $name] = $_POST;

    if (findApp(["name" => $name]) !== null) throw new InvalidArgumentException("{$name} already registered");

    $clientID = uniqid('client_', true);
    $clientSecret = sha1($clientID);
    $apps = read_file('./data/app.data');
    $apps[] = array_merge(
        ["client_id" => $clientID, "client_secret" => $clientSecret],
        $_POST
    );
    write_file($apps, "./data/app.data");

    http_response_code(201);
    header("Content-Type: application/json");
    echo json_encode([
        "client_id" => $clientID, "client_secret" => $clientSecret
    ]);
}

function findItem($filename, $criteria, $findAll = false)
{
    $apps = read_file($filename);
    $results = array_values(
        array_filter($apps, function ($item) use ($criteria) {
            return count(array_intersect_assoc($criteria, $item)) === count($criteria);
        })
    );

    return count($results) === 0 ? null : ($findAll ? $results : $results[0]);
}

function findApp($criteria)
{
    return findItem("./data/app.data", $criteria);
}

function findCode($criteria)
{
    return findItem("./data/code.data", $criteria);
}

function findToken($criteria)
{
    return findItem("./data/token.data", $criteria);
}

function findUser($criteria)
{
    return findItem("./data/user.data", $criteria);
}

function findAllCode($criteria)
{
    return findItem("./data/code.data", $criteria, true);
}


function auth()
{
    ["client_id" => $clientID, "scope" => $scope, "state" => $state] = $_GET;
    $app = findApp(["client_id" => $clientID]);
    if (!$app) throw new RuntimeException("{$clientID} not found");
    if (null !== findAllCode(["client_id" => $clientID])) return handleAuth(true);
    http_response_code(200);
    echo "{$app['client_id']}/{$app['name']} {$app['uri']}";
    echo $scope;
    echo "<a href='/auth-yes?client_id={$app['client_id']}&state={$state}'>Yes</a>";
    echo "<a href='/auth-no?client_id={$app['client_id']}&state={$state}'>No</a>";
}

function handleAuth($success)
{
    ["client_id" => $clientID, "state" => $state] = $_GET;
    $app = findApp(["client_id" => $clientID]);
    if (!$app) throw new RuntimeException("{$clientID} not found");

    $urlRedirect = $success ? $app["redirect_success"] : $app["redirect_error"];
    $queryParams = [
        "state" => $state
    ];
    if ($success) {
        $code = uniqid('code_');
        $codes = read_file("./data/code.data");
        $codes[] = [
            "code" => $code,
            "client_id" => $clientID,
            "user_id" => "user_6087d1978824c4.38987336",
            "expired_in" => (new \DateTimeImmutable())->modify('+5 minutes')
        ];
        write_file($codes, './data/code.data');
        $queryParams['code'] = $code;
    }
    //echo("Location: {$urlRedirect}?" . http_build_query($queryParams));
    header("Location: {$urlRedirect}?" . http_build_query($queryParams));
}

//https://auth-server/token?grant_type=authorization_code&code=...&client_id=..&client_secret=...
//⇒ {"access_token":"TOKEN", "expires_in":3600}
function handleAuthCode($clientId) {
    ["code" => $code] = $_GET;
    // Check code with client_id
    if (!($codeEntity = findCode(["code" => $code, "client_id" => $clientId]))) throw new RuntimeException("{$code} not found");
    if ($codeEntity["expired_in"]->getTimestamp() < (new DateTimeImmutable())->getTimestamp()) throw new RuntimeException("{$code} has expired");
    return $codeEntity["user_id"];
}

//https://auth-server/token?grant_type=password&client_id=..&client_secret=...&username=...&password=...
//⇒ {"access_token":"TOKEN", "expires_in":3600}
function handlePassword() {
    ["username" => $username, "password" => $password] = $_GET;
    // Check code with client_id
    if (!($userEntity = findUser(["username" => $username, "password" => $password]))) throw new RuntimeException("{$username} not found");
    return $userEntity["user_id"];
}

function token()
{
    ["client_id" => $clientId, "client_secret" => $clientSecret, "grant_type" => $grantType] = $_GET;
    // Check client credentials
    if (!($app = findApp(["client_id" => $clientId, "client_secret" => $clientSecret]))) throw new RuntimeException("Application credentials are invalid");

    // $userId = match ($grantType) {
    //     'authorization_code' => handleAuthCode($clientId),
    //     'password' => handlePassword(),
    //     'client_credentials' => null,
    //     default => null,
    // };

    switch ($grantType) {
		case 'authorization_code':
			$userId = handleAuthCode($clientId);
			break;
		
		case 'password':
			$userId = handlePassword();
			break;
		
		case 'client_credentials':
			break;

		default:
			break;
	}

    // Generate token
    $token = uniqid("token_", true);
    // Save token
    $tokens = read_file("./data/token.data");
    $tokenEntity = [
        "token" => $token,
        "client_id" => $clientId,
        "user_id" => $userId,
        "expired_in" => (new \DateTimeImmutable())->modify("+1 hour")
    ];
    $tokens[] = $tokenEntity;
    write_file($tokens, "./data/token.data");
    // Send token
    echo json_encode(["access_token" => $tokenEntity['token'], "expires_in" => $tokenEntity['expired_in']->getTimestamp() - (new \DateTimeImmutable())->getTimestamp()]);
}

function api()
{
    preg_match("/Bearer ([\w\.]+)/", getallheaders()["Authorization"] ?? getallheaders()["authorization"] ?? "", $matches);
    if (!count($matches)) throw new RuntimeException("Token not found");
    $token = $matches[1];

    if (null === ($tokenEntity = findToken(['token' => $token]))) throw new RuntimeException("{$token} not found");

    if ($tokenEntity["expired_in"]->getTimestamp() < (new DateTimeImmutable())->getTimestamp()) throw new RuntimeException("{$token} has expired");

    $user = findUser(["user_id" => $tokenEntity["user_id"]]);
    unset($user["password"]);

    echo json_encode($user);
}

$route = strtok($_SERVER['REQUEST_URI'], '?');
switch ($route) {
    case '/fixtures':
        fixtures();
        break;
        
    case '/register':
        register();
        break;
        
    case '/auth':
        auth();
        break;
        
    case '/auth-yes':
        handleAuth(true);
        break;
        
    case '/auth-no':
        handleAuth(false);
        break;
        
    case '/token':
        token();
        break;
        
    case '/api':
        api();
        break;
    
    default:
        echo "404: Route $route not found";
        break;
}
