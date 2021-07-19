<?php

$rootURI = 'https://' . $_SERVER['SERVER_NAME'];

// TODO create provider objets (clientId, clientSecret, redirectURI, authURL, userURL, perms)

// Copy-paste from ../oauth-server/data/app.data 
const CLIENT_ID = 'client_60f324e98d1cb3.40889045';
const CLIENT_SECRET = '626fe6480483a000f2073f1a612944aacd6ae230';

// https://developers.facebook.com/apps
const FB_CLIENT_ID = '4497703600241793';
const FB_CLIENT_SECRET = '3f53a8d7a73904209580cfb9e4f4360f';

// const FB_PROVIDER = [
// 	'grant_type' => 'authorization_code',
// 	'clientId' => '4497703600241793',
// 	'clientSecret' => '3f53a8d7a73904209580cfb9e4f4360f',
// 	'redirectUri' => $rootURI. '/fb-success',
// 	'scope' => 'openid email profile'
// ];

// const GG_PROVIDER = [
// 	'response_type' => 'code',
// 	'clientId' => '275057285715-irer1dk1h3bv2v8ci5ob4218kiialmrh.apps.googleusercontent.com',
// 	'clientSecret' => 'AR4Skm7xvD875GXHUaKkO_nB',
// 	'redirectUri' => $rootURI. '/gg-success',
// 	'scope' => 'openid email profile',
// 	'state' => $_SESSION['state']
// ];

const GG_CLIENT_ID = '275057285715-irer1dk1h3bv2v8ci5ob4218kiialmrh.apps.googleusercontent.com';
const GG_CLIENT_SECRET = 'AR4Skm7xvD875GXHUaKkO_nB';

const DC_CLIENT_ID = '866078579375997008';
const DC_CLIENT_SECRET = 'YGsuyDLVsnTObG8OZxii0DYtTuiu9g-h';
 
// This is the URL we'll send the user to first
// to get their authorization
$authorizeURL = 'https://accounts.google.com/o/oauth2/v2/auth';
 
// This is Google's OpenID Connect token endpoint
$tokenURL = 'https://www.googleapis.com/oauth2/v4/token';
$baseURL = 'https://' . $_SERVER['SERVER_NAME']
. '/gg-success';

$user = null;

session_start();

function getUser($params)
{
	$result = file_get_contents("https://oauth-server:8081/token?"
		. "client_id=" . CLIENT_ID
		. "&client_secret=" . CLIENT_SECRET
		. "&" . http_build_query($params));
	$token = json_decode($result, true)["access_token"];
	// GET USER by TOKEN
	$context = stream_context_create([
		'http' => [
			'method' => "GET",
			'header' => "Authorization: Bearer " . $token
		]
	]);
	$result = file_get_contents("https://oauth-server:8081/api", false, $context);
	$user = json_decode($result, true);
	var_dump($user);
}

function getFbUser($params)
{
	$result = file_get_contents("https://graph.facebook.com/oauth/access_token?"
		. "redirect_uri=https://localhost/fb-success"
		. "&client_id=" . FB_CLIENT_ID
		. "&client_secret=" . FB_CLIENT_SECRET
		. "&" . http_build_query($params));
	$token = json_decode($result, true)["access_token"];
	// GET USER by TOKEN
	$context = stream_context_create([
		'http' => [
			'method' => "GET",
			'header' => "Authorization: Bearer " . $token
		]
	]);
	$result = file_get_contents("https://graph.facebook.com/me", false, $context);
	$user = json_decode($result, true);
	var_dump($user);
}

function handleHome()
{
	echo <<< HTML
		<h1>Accueil</h1>
		<ul>
			<li><a href="/login">Login</a></li>
			<li><a href="/register">Register</a></li>
		</ul>
	HTML;
}

function handleLogin()
{
    // $googleClientID = '275057285715-irer1dk1h3bv2v8ci5ob4218kiialmrh.apps.googleusercontent.com';
    $authorizeURL = 'https://accounts.google.com/o/oauth2/v2/auth';
    $baseURL = 'https://' . $_SERVER['SERVER_NAME']
    . '/gg-success';
	$client_id = CLIENT_ID;
	$fb_client_id = FB_CLIENT_ID;
	$dc_client_id = DC_CLIENT_ID;

    // Generate a random hash and store in the session
    $_SESSION['state'] = bin2hex(random_bytes(16));

    // Google params
    $params = array(
        'response_type' => 'code',
        'client_id' => GG_CLIENT_ID,
        'redirect_uri' => $baseURL,
        'scope' => 'openid email profile',
        'state' => $_SESSION['state']
    );
    $google_href = $authorizeURL.'?'.http_build_query($params);

	echo <<< HTML
		<h1>Login with</h1>
		<ul>
			<li><a href="https://localhost:8081/auth?response_type=code&client_id=${client_id}&scope=basic&state=azerty">oauth-server</a></li>
			<li><a href="https://facebook.com/v11.0/dialog/oauth?response_type=code&client_id=${fb_client_id}&redirect_uri=https://localhost/fb-success">Facebook</a></li>
			<li><a href="${google_href}">Google</a></li>
			<li><a href="https://discord.com/api/oauth2/authorize?client_id=${dc_client_id}&redirect_uri=https://localhost/dc-success&response_type=code&scope=email%20identify">Discord</a></li>
		</ul>
	HTML;
}

function handleSuccess()
{
	['code' => $code, 'state' => $state] = $_GET;

	getUser([
		'grant_type' => 'authorization_code',
		'code' => $code
	]);
}

function handleFBSuccess()
{
	['code' => $code, 'state' => $state] = $_GET;
	
	// Get token from code
	$result = file_get_contents('https://graph.facebook.com/oauth/access_token?'
		. 'client_id=' . FB_CLIENT_ID
		. '&client_secret=' . FB_CLIENT_SECRET
		. '&redirect_uri=https://localhost/fb-success'
		. "&grant_type=authorization_code&code=$code"
	);
    
	$token = json_decode($result, true)['access_token'];
	
	// Get user from token
	$context = stream_context_create([
		'http' => [
			'method' => 'GET',
			'header' => "Authorization: Bearer $token"
		]
	]);
    
	
	// https://developers.facebook.com/tools/explorer/?method=GET&path=me%3Ffields%3Did%2Cname%2Cemail%2Cpermissions&version=v11.0
	$result = file_get_contents('https://graph.facebook.com/me?fields=id,name,email', false, $context);
	$user = json_decode($result, true);
	print_r('You are logged in with your facebook account ! ');
	print_r($user);
}

function handleGoogleSuccess() {
    $googleClientID = '275057285715-irer1dk1h3bv2v8ci5ob4218kiialmrh.apps.googleusercontent.com';
    $googleClientSecret = 'AR4Skm7xvD875GXHUaKkO_nB';
    $tokenURL = 'https://www.googleapis.com/oauth2/v4/token';
    $baseURL = 'https://' . $_SERVER['SERVER_NAME']
    . '/gg-success';

    // When Google redirects the user back here, there will
    // be a "code" and "state" parameter in the query string
    if (isset($_GET['code'])) {
        // Verify the state matches our stored state
        if(!isset($_GET['state']) || $_SESSION['state'] != $_GET['state']) {
            header('Location: ' . $baseURL . '?error=invalid_state');
            die();
        }
    
        // Exchange the authorization code for an access token
        $ch = curl_init($tokenURL);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
            'grant_type' => 'authorization_code',
            'client_id' => $googleClientID,
            'client_secret' => $googleClientSecret,
            'redirect_uri' => $baseURL,
            'code' => $_GET['code']
        ]));
        $data = json_decode(curl_exec($ch), true);
    
        // Split the JWT string into three parts
        $jwt = explode('.', $data['id_token']);
        // Extract the middle part, base64 decode, then json_decode it
        $userinfo = json_decode(base64_decode($jwt[1]), true);
        
		global $user;
        $_SESSION = $userinfo;
		$user = (object) $_SESSION;
        
        echo 'Connected with a Google account';
        echo '<p>User ID: '.$user->sub.'</p>';
        echo '<p>Name: '.$user->name.'</p>';
        echo '<p>Email: '.$user->email.'</p>';
        echo '<img src="'.$user->picture.'">';
        die();
    }
}

function handleDCSuccess() {
    $tokenURL = 'https://discord.com/api/oauth2/token';
    $baseURL = 'https://' . $_SERVER['SERVER_NAME'] . '/dc-success';
    $userURL = 'https://discord.com/api/users/@me';

    if (isset($_GET['code'])) {    
        // Exchange the authorization code for an access token
        $ch = curl_init($tokenURL);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
            'grant_type' => 'authorization_code',
            'client_id' => DC_CLIENT_ID,
            'client_secret' => DC_CLIENT_SECRET,
            'redirect_uri' => $baseURL,
            'code' => $_GET['code']
        ]));

        $token = json_decode(curl_exec($ch), true)['access_token'];

		$context = stream_context_create([
			'http' => [
				'method' => 'GET',
				'header' => "Authorization: Bearer $token"
			]
		]);

		$result = file_get_contents($userURL, false, $context);
		$user = json_decode($result, true);
		var_dump($user);
    }
}

// https://discord.com/developers/docs/topics/oauth2
function handleDCSuccess0()
{
	['code' => $code, 'state' => $state] = $_GET;

	$data = http_build_query([
		'client_id' => DC_CLIENT_ID,
		'client_secret' => DC_CLIENT_SECRET,
		'grant_type' => 'authorization_code',
		'redirect_uri' => 'https://localhost/dc-success',
		'code' => $code
	]);

	$headers = [
		'http' => [
			'method' => 'POST',
			'header' => 'Content-type: application/x-www-form-urlencoded',
			'content' => $data
		]
	];

	$context = stream_context_create($headers);

	$result = file_get_contents('https://discord.com/oauth2/token', false);
	print_r($result);

	$user = json_decode($result, true);
	print_r($user);

	print_r($_POST);

	print_r('You are logged in with your Discord account ! ');
}

function handleError()
{
	['state' => $state] = $_GET;
	echo "Authentication with state $state has been declined.";
}

function handlePassword()
{
	if ($_SERVER['REQUEST_METHOD'] === 'POST') {
		['username' => $username, 'password' => $password] = $_POST;
		getUser([
			'grant_type' => 'password',
			'username' => $username,
			'password' => $password,
		]);
	} else {
		// Gérer le workflow 'password' jusqu'à afficher les données utilisateurs
		echo <<< HTML
			<form method="post">
				<label for="username">Username</label>
				<input id="username" name="username" type="text" placeholder="ex: john">

				<label for="password">Password</label>
				<input id="password" name="password" type="password" placeholder="ex: doe">

				<input type="submit" value="Submit">
			</form>
		HTML;
	}
}

/**
 * AUTH_CODE WORKFLOW
 *  => Get CODE
 *  => EXCHANGE CODE => TOKEN
 *  => GET USER by TOKEN
 */
/**
 * PASSWORD WORKFLOW
 * => GET USERNAME/PASSWORD (form)
 * => EXHANGE U/P => TOKEN
 * => GET USER by TOKEN
 */

$route = strtok($_SERVER['REQUEST_URI'], '?');

switch ($route) {
	case '/':
		handleHome();
		break;

	case '/login':
		handleLogin();
		break;

	case '/success':
		handleSuccess();
		break;
		
	case '/fb-success':
		handleFBSuccess();
		break;

    case '/gg-success':
        handleGoogleSuccess();
        break;

	case '/dc-success':
		handleDCSuccess();
		break;
		
	case '/error':
		handleError();
		break;
		
	case '/password':
		handlePassword();
		break;
		
	default:
		echo "404: Route $route not found";
		break;
}

