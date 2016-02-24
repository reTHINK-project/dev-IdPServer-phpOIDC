<?php
/**
* Copyright (c) 2016 Orange
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*   http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
**/


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
