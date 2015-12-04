<?php
include_once 'includes/functions.php';
include_once 'includes/dbfront.php';
include_once 'includes/libjsoncrypto.php';

setlocale ( LC_ALL, 'fr_FR' );
$pdo = connect ();
sec_session_start ();

$state = $_COOKIE ['oidc_state'];
$code = NULL;
if (isset($_GET ['code']))
{
	$code = $_GET ['code'];
}

function substr_startswith($haystack, $needle) {
	return substr ( $haystack, 0, strlen ( $needle ) ) === $needle;
}

if ($code && $_GET ['state'] == $state) {
	
	$usePost = true;
	
	$postfields = http_build_query ( array (
			"grant_type" => "authorization_code",
			"code" => $code,
			"state" => $state,
			"redirect_uri" => $REDIRECT_URI,
			"client_id" => $CLIENT_ID,
			"client_secret" => $CLIENT_SECRET 
	) );
	$urlpost = "$IDP_URL/token";
	$urlget = "$IDP_URL/token?".$postfields;
	
	$proxy_response = false;
	if (substr_startswith ( $state, 'p' )) {
		$proxy_response = true;
	}
	
	try {
		
		$ch = curl_init ();
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

		if($usePost) {
			curl_setopt ( $ch, CURLOPT_URL, $urlpost );

		} else {
			curl_setopt ( $ch, CURLOPT_URL, $urlget );
		}
		
		curl_setopt ( $ch, CURLOPT_HEADER, FALSE );
		curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, TRUE );

		// check if should use proxy
		$env_http_proxy = getenv ( "HTTP_PROXY" );
	//	if( $env_http_proxy != FALSE)
//			curl_setopt ( $ch, CURLOPT_PROXY, "p-goodway");
//			curl_setopt ( $ch, CURLOPT_PROXYPORT, 3128);
		
		if($usePost) {
			curl_setopt ( $ch, CURLOPT_POST, 1 );
			curl_setopt ( $ch, CURLOPT_POSTFIELDS, $postfields );
		}

		$dataText = curl_exec ( $ch );
		curl_close ( $ch );
		
		// check if result is json
		if (substr_startswith ( $dataText, '{' ) == FALSE) {
			if ($proxy_response) {
				header ( "Location: demo.php/endproxy?error=bad-idp-response" );
			} else {
				echo $dataText;
			}
			return;
		}
		
		$res = json_decode ( $dataText, true );

		print_r($res);		

		
		if (! $res) {
			throw new Exception ( json_last_error_msg (), json_last_error () );
		}
		
		$access_token = $res ['access_token'];
		if (! $access_token)
			throw new Exception ( "no access_token", 1 );
		$id_token = $res['id_token'];
		if (! $id_token)
			throw new Exception ( "no id_token", 1 );
		
		// should verify access_token, id_token
		// ...
		// should throw exception if error

		// now get user informations
		$ch = curl_init ();
		
		if (FALSE === $ch) {
			throw new Exception ( 'failed to initialize curl' );
		}
		
		$url = $IDP_URL . "/userinfo?access_token=" . $access_token;
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt ( $ch, CURLOPT_URL, $url );
		curl_setopt ( $ch, CURLOPT_HEADER, FALSE );
		curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, TRUE );

		// check if should use proxy
//		if( $env_http_proxy != FALSE)
//			curl_setopt ( $ch, CURLOPT_PROXY, "p-goodway");
//			curl_setopt ( $ch, CURLOPT_PROXYPORT, 3128);		


		$dataText = curl_exec ( $ch );

		// echo $dataText;
		curl_close ( $ch );
		
		// if response is json
		if (substr_startswith ( $dataText, '{' )) {
			// parse user info json
			$userinfos = json_decode ( $dataText, true );
			$pdo=connect();

			$user = getUser($pdo,$userinfos ['sub']);
			if ($user['sub'] != $userinfos ['sub'])
			{
				addUser ( $pdo, $userinfos ['sub'], $userinfos ['email'], $userinfos ['given_name'], $userinfos ['family_name'] );
				$user = getUser($pdo,$userinfos ['sub']);
			}
			$_SESSION['USER'] = $user;
			if ($proxy_response) {
				header ( "Location: demo.php/endproxy?sub=" . $userinfos ['sub'] );
			} else {
				header ( "Location: index.php" );
			}
		} else {
			if ($proxy_response) {
				header ( "Location: demo.php/endproxy?error=no-json-userinfo" );
			} else {
				// else display result in html body
				echo $dataText;
			}
		}

	// exception handling
	} catch ( Exception $e ) {
		if ($proxy_response) {
			header ( "Location: demo.php/endproxy?error=exception" );
		} else {
			echo "Error : ".$e->getMessage();
		}
	}
} else {
	if (isset($_GET['error']))
	{
		echo '<br><br><h3>The authentication server has sent an error <font color="red"><br><b>"'.$_GET['error_description']."\"</b></font>";
	}
	else
	{
		// state mismatch
		if ($proxy_response) {
			header ( "Location: demo.php/endproxy?error=state-mismatch" );
		} else {
			echo "Error state mismatch";
		}
	}
	// process sub decoding.
}

?>
