<?php

include_once 'includes/config.php';
include_once 'includes/dbhelper.php';
include_once 'includes/libjsoncrypto.php';

function connect()
{

 $pdo = new PDO('mysql:host='.HOST.';dbname='.DATABASE, USER, PASSWORD);
 $pdo->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_WARNING );
 return $pdo;

}

/**
* return parameter $p read in URL (Http GET)
* or $d (default) value if not found
**/
function paramget($p, $d='') {
  if (isset($_GET[$p])) return $_GET[$p];
  else return $d;
}

function getUserIdInSession() {
  $id=-1;
  if (isset($_SESSION['user_id']) && !empty($_SESSION['user_id'])) $id=$_SESSION['user_id'];
  return $id;
}
function sec_session_start() {
    $session_name = 'sec_session_id';   // Set a custom session name
    $secure = SECURE;
    // This stops JavaScript being able to access the session id.
    $httponly = true;
    // Forces sessions to only use cookies.
    if (ini_set('session.use_only_cookies', 1) === FALSE) {
        header("Location: ../error.php?err=Could not initiate a safe session (ini_set)");
        exit();
    }
    // Gets current cookies params.
    $cookieParams = session_get_cookie_params();
    session_set_cookie_params($cookieParams["lifetime"],
        $cookieParams["path"],
        $cookieParams["domain"],
        $secure,
        $httponly);
    // Sets the session name to the one set above.
    session_name($session_name);
    session_start();            // Start the PHP session
    session_regenerate_id();    // regenerated the session, delete the old one.
}


function randomDigits($digits_needed) {

   $random_number=''; // set up a blank string
   $count=0;

   while ( $count < $digits_needed ) {
      // dans de rares cas, tente d'obtenir un 0. Ceci permet d'éviter d'avoir trop de zeros
      if (mt_rand(0,9)>5) $random_digit=mt_rand(0,9);
      else $random_digit = mt_rand(1, 9);

      $random_number .= $random_digit;
      $count++;
   }
   return $random_number;
}

function clearSession() {
// Unset all session values
$_SESSION = array();

// get session parameters
$params = session_get_cookie_params();

// Delete the actual cookie.
setcookie(session_name(),
        '', time() - 42000,
        $params["path"],
        $params["domain"],
        $params["secure"],
        $params["httponly"]);

// Destroy session
session_destroy();

}

function disp($s) {
  echo date(DATE_ATOM)." $s\n";
}

function rp_decrypt_verify_id_token($id_token) {
    $response = array();
	$jwt_parts = jwt_to_array($id_token);
    if(isset($jwt_parts[0]['enc'])) { // encrypted
        echo "Encrypted ID Token - {$jwt_parts[0]['enc']} {$jwt_parts[0]['alg']} {$jwt_parts[0]['int']}\n";
        $response['jwe'] = $jwt_parts;
        $signed_jwt = jwt_decrypt($id_token, RP_PKEY, true);
        if(!$signed_jwt) {
            echo "Unable to decrypt ID Token response";
            return false;
        }
    } else { // signed 
        $signed_jwt = $id_token;
        // echo "Signed ID Token {$jwt_parts[0]['alg']}\n";
    }

    if($signed_jwt) {
        list($header, $payload, $sig) = jwt_to_array($signed_jwt);
        // echo "Signed ID Token {$header['alg']}\n";
        $response['jws'] = array($header, $payload, $sig);
		if($header['alg'] == 'none') {
            $verified = true;
		} else {
			$verified = jwt_verify($signed_jwt);
		}
        // echo "Signature Verification = $verified";
        if($verified) {
            if(isset($payload['address']) && is_array($payload['address'])) {
                if(isset($payload['address']['formatted']))
                    $payload['address'] = $payload['address']['formatted'];
                else
                    $payload['address'] = "{$payload['address']['street_address']}\n{$payload['address']['locality']}, {$payload['address']['region']} {$payload['address']['postal_code']}\n{$payload['address']['country']}";
            }
            if(isset($payload['aud']) && is_array($payload['aud'])) {
                $payload['aud'] = implode(', ', $payload['aud']);
            }

            $g_id_response = $payload;
            // echo "ID Token Signature Verified\n";
			$_SESSION['login'] = $payload['sub'];
        } else
            echo "ID Token Signature Verification Failed\n";
    }
    return $response;
}

?>
