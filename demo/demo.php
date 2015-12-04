<?php

include_once 'includes/functions.php';
include_once 'includes/dbfront.php';

$pdo=connect();

// get function to retrieve user's firstName with specified parameter as sub
if( isset($_GET['get']) ) {
        $sub = $_GET['get'];
        $user = getUser($pdo,$sub);
        echo $user['firstName'];
        return;
}

// initiate session
sec_session_start();
// generate random number for a state parameter
$state = randomDigits(7);

// if a proxy value is in POST parameters, add a 'p' in the state value
if(isset($_POST['proxy'])) {
    $state = "p".$state;
}

// put the state value in the session cookies
if ($state)
	// $_SESSION['oidc_state'] = $state;
	setcookie('oidc_state', $state, 0, '/');
//echo "Location: $IDP_URL/auth?client_id=$CLIENT_ID&response_type=$RESPONSE_TYPE&redirect_uri=$REDIRECT_URI&scope=$SCOPE&state=$state";
// redirect to the Identity Provider
header("Location: $IDP_URL/auth?client_id=$CLIENT_ID&response_type=$RESPONSE_TYPE&redirect_uri=$REDIRECT_URI&scope=$SCOPE&state=$state");

?>
