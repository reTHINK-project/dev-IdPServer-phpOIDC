<?php

/**
 * Show Login form.
 * @return String HTML Login form.
 */
function custom_loginform($display_name = '', $user_id = '', $client = null, $oplogin=false){
   
   if($display_name && $user_id) {
		
       $userid_field = " <b>{$display_name}</b><input type='hidden' name='username_display' value='{$display_name}'><input type='hidden' name='username' value='{$user_id}'><input type='hidden' name='client_id' value='{$client['client_id']}'><br/>";
   } else {
       $userid_field = "<input type='text' name='username' value=''><input type='hidden' name='client_id' value='{$client['client_id']}'>";
   }
    $logo_uri = '';
    $tos_uri = '';
    $policy_uri = '';
    if($client) {
        if($client['policy_uri'])
            $policy_uri = sprintf('<a href="%s">Policy</a>', $client['policy_uri']);
        if($client['tos_uri'])
            $policy_uri = sprintf('<a href="%s">TOS</a>', $client['tos_uri']);
        if($client['logo_uri'])
            $logo_uri = sprintf('<img src="%s">', $client['logo_uri']);
        if($client['client_name'])
            $logo_uri = sprintf('%s', $client['client_name']);
    }

   $login_handler = $oplogin ? 'op' : '';
    
   $str='
  <html>
  <head><title> ReThink Authentication </title>
  <meta name="viewport" content="width=320">
  </head>
  <body style="background-color:#EEEEEE;line-height : 1.5;">
  <center>
  <h1>Sign in with your ReTHINK Account</h1>' . "\n  <b>Service " . $logo_uri . ' ask for authentication</b>'.'<br /><br />
  <form method="POST" action="' . $_SERVER['SCRIPT_NAME'] . "/{$login_handler}login\" style='line-height : 2;'>
  Username:" . $userid_field . '<br />
  Password:<input type="password" name="password" value=""><br />
  <input type="checkbox" name="persist" >Keep me logged in. <br />
  <input type="submit">
  </form>' . "\n  " . $policy_uri . "\n{$tos_uri}" . '
  </center>
 
  <img src="../../../img/rethink.png" /> Need an account? <a href=../admin/account/index.php?action=new>Signup</a><br/>
  </body>
  </html>
  ';
  return $str;
}



/**
 * Show Confirmation Dialogue for Attributes.
 * @param  String $r     Request String (JSON)
 * @return String HTML to be shown.
 */
function custom_confirm_userinfo($client = null){
  $req=$_SESSION['rpfA'];
  $scopes = explode(' ', $req['scope']);
  $response_types = explode(' ', $req['response_type']);
  $offline_access = in_array('offline_access', $scopes) && in_array('code', $response_types) ? 'YES' : 'NO';
  $axlabel=get_default_claims();

  $requested_claims = get_all_requested_claims($req, $req['scope']);
  log_info('requested claims = %s', print_r($requested_claims, true));

    $attributes = '';
    $account = db_get_account($_SESSION['username']);
    foreach($requested_claims as $claim => $required) {
        if($required == 1) {
            $star = "<font color='red'>*</font>";
        } else {
            $star = '';
        }
        $claim_label = "{$axlabel[$claim]}{$star}";
        $claim_value = $account[$claim];

        $attributes .= "<tr><td>{$claim_label}</td><td>{$claim_value}</td><td></td></tr>\n";
    }


$attribute_form_template = <<<EOF
  <div class='persona'>
  <form method="POST" action="{$_SERVER['SCRIPT_NAME']}/confirm_userinfo" >
  <input type="hidden" name="mode" value="ax_confirm">
  <table cellspacing="0" cellpadding="0" width="600">
  <thead><tr><th>Attribute</th><th>Value</th><th>Confirm</th></tr></thead>
  $attributes
  <tr><td colspan="3">&nbsp;</td></tr>
  <thead><tr><td><b>Offline Access Requested</b></td><td>$offline_access</td><td></td></tr></thead>
  <tr><td colspan="3">&nbsp;</td></tr>
  <tr><td colspan="3">&nbsp;</td></tr>
  <tr><td colspan="3"  style='line-height : 2;'><input type="checkbox" name="agreed" value="1" checked>I Agree to provide the above information. <br/>
  <input type="radio" name="trust" value="once" checked>Trust this site this time only <br />
  <input type="radio" name="trust" value="always" >Trust this site always <br/>
  </td></tr>
  <tr><td colspan="3"><center><input type="submit" name="confirm" value="confirmed"> </center></td></tr></table>
  </form>
  </div>
EOF;


$styles = <<<EOF

    <style type="text/css">
      /*demo page css*/
      body{ font: 80% "Trebuchet MS", sans-serif; margin: 50px;}
      .persona table{ font: 100% "verdana", san-serif; }
      .persona td { font: 100% "verdana", san-serif;}
    </style>
EOF;

  $str= '
  <html>
  <head><title>' . OP_SERVER_NAME . ' AX Confirm</title>
  <meta name="viewport" content="width=620">' . $styles . '
  </head>
  <body background-color:#EEEEEE;line-height : 1.5;>
  <h1>Attribute Sharing Consent</h1>
  <h2><b>'.$client['client_name'].' service </b> requests following profile values...</h2>' . $attribute_form_template . '
  <img src="../../../img/rethink.png" />
  </body>
  </html>
  ';
  return $str;
}


/**
 * Provide IDP-Proxy
 */
function handle_webfinger_idp_proxy()
{
	if(strpos($_SERVER['REQUEST_URI'], '/rethink-oidc-ns') !== false) {
	$file = "js/rethink-oidc.js";
			if (file_exists($file)) {
					header('Content-Type: application/json');
					readfile("js/rethink-oidc.js");
					exit;
			}
	}
	elseif(strpos($_SERVER['REQUEST_URI'], '/rethink-proxy') !== false) {
    $file = "js/rethink-oidc.js";
            if (file_exists($file)) {
     		    	header('Content-Type: application/json');
     				readfile("js/rethink-proxy.js");
     				exit;
     		}
    }
	else
	   echo "<html><h1>Not Found</h1></html>";
	return;
}

function handle_proxy()
{
	echo '<script>
        var jsonString = {};
        var data = window.location.hash.substring(1).split(\'&\').toString().split(/[=,]+/);
        for(var i=0; i<data.length; i+=2){jsonString[data[i]]=data[i+1];}
        var msg = JSON.stringify(jsonString);
        //Unsecure send to all
        window.opener.postMessage(msg,"*");
        window.close();
        </script>';
}

function webrtc_handle_auth() {

    $state = isset($_REQUEST['state']) ? $_REQUEST['state'] : NULL;
    $error_page = OP_INDEX_PAGE;
    $response_mode = 'query';
        
    try{
        if(!isset($_REQUEST['client_id']))
            throw new OidcException('invalid_request', 'no client');
        // check client id
        $client = db_get_client($_REQUEST['client_id']);
        if(!$client)
            throw new OidcException('unauthorized_client', 'Client ID not found');

/*        if(isset($_REQUEST['redirect_uri'])) {
            if(!is_valid_registered_redirect_uri($client['redirect_uris'], $_REQUEST['redirect_uri']))
                throw new OidcException('invalid_request', 'no matching redirect_uri');
        } else
            throw new OidcException('invalid_request', 'no redirect_uri in request');

        $error_page = $_REQUEST['redirect_uri'];
*/
        $response_mode = get_response_mode($_REQUEST);

        if(!isset($_REQUEST['response_type']))
            throw new OidcException('invalid_request', 'no response_type');
        $response_types = explode(' ', $_REQUEST['response_type']);
        $known_response_types = array('code', 'token', 'id_token');
        if(count(array_diff($response_types, $known_response_types)))
            throw new OidcException('invalid_response_type', "Unknown response_type {$_REQUEST['response_type']}");

        if(ENABLE_PKCE) {
            if(in_array('code', $response_types)) {
                if(!isset($_REQUEST['code_challenge']))
                    throw new OidcException('invalid_request', 'code challenge required');
                if(isset($_REQUEST['code_challenge_method'])) {
                    if(!in_array($_REQUEST['code_challenge_method'], array('plain', 'S256')))
                        throw new OidcException('invalid_request', "unsupported code challenge method {$_REQUEST['code_challenge_method']}");
                }
            }
        }

        if(!isset($_REQUEST['scope']))
            throw new OidcException('invalid_request', 'no scope');
        $scopes = explode(' ', $_REQUEST['scope']);
        if(!in_array('openid', $scopes))
            throw new OidcException('invalid_scope', 'no openid scope');

        if(in_array('token', $response_types) || in_array('id_token', $response_types)) {
            if(!isset($_REQUEST['nonce']))
                throw new OidcException('invalid_request', 'no nonce');
        }

        $_SESSION['get'] = $_GET;
        $request_uri = isset($_REQUEST['request_uri']) ? $_REQUEST['request_uri'] : NULL;

        $requested_userid = NULL;
        $requested_userid_display = NULL;
        $request_object = NULL;
        if($request_uri) {
            $request_object = get_url($request_uri);
            if(!$request_object)
                throw new OidcException('invalid_request', "Unable to fetch request file $request_uri");
        } elseif(isset($_REQUEST['request']))
            $request_object = $_REQUEST['request'];
        if(isset($_GET['claims'])) {
            $_GET['claims'] = json_decode($_GET['claims'], true);
            $_REQUEST['claims'] = $_GET['claims'];
        }
        if(isset($request_object)) {
            $cryptoError = '';
            $payload = decrypt_verify_jwt($request_object, $client, $cryptoError);
            if(!isset($payload)) {
                if($cryptoError == 'error_decrypt')
                    throw new OidcException('invalid_request', 'Unable to decrypt request object');
                elseif($cryptoError == 'error_sig')
                    throw new OidcException('invalid_request', 'Unable to verify request object signature');
            } else {

                if(isset($payload['claims']['id_token'])) {
                    if(array_key_exists('sub', $payload['claims']['id_token']) && isset($payload['claims']['id_token']['sub']['value'])) {
                        $requested_userid_display = $payload['claims']['id_token']['sub']['value'];
                        $requested_userid = unwrap_userid($payload['claims']['id_token']['sub']['value']);
                        if(!db_get_user($requested_userid))
                            throw new OidcException('invalid_request', 'Unrecognized userid in request');
                    }
                }

                $merged_req = array_merge($_GET, $payload);
                if(!array_key_exists('max_age', $merged_req) && $client['default_max_age'])
                    $merged_req['max_age'] = $client['default_max_age'];
                if($merged_req['max_age'])
                    $merged_req['claims']['id_token']['auth_time'] =  array('essential' => true);
                if((!$merged_req['claims']['id_token'] || !array_key_exists('auth_time', $merged_req['claims']['id_token'])) && $client['require_auth_time'])
                    $merged_req['claims']['id_token']['auth_time'] = array('essential' => true);
                if(!$merged_req['claims']['id_token'] || !array_key_exists('acr', $merged_req['claims']['id_token'])) {
                    if($merged_req['acr_values'])
                        $merged_req['claims']['id_token']['acr'] = array('essential' => true, 'values' => explode(' ', $merged_req['acr_values']));
                    elseif($client['default_acr_values'])
                        $merged_req['claims']['id_token']['acr'] = array('essential' => true, 'values' => explode('|', $client['default_acr_values']));
                }
                $_SESSION['rpfA'] = $merged_req;

                log_debug("rpfA = %s", print_r($_SESSION['rpfA'], true));
                foreach(Array('client_id', 'response_type', 'scope', 'nonce', 'redirect_uri') as $key) {
                    if(!isset($payload[$key]))
                        log_error("missing %s in payload => %s", $key, print_r($payload, true));
//                      throw new OidcException('invalid_request', 'Request Object missing required parameters');
                }

                log_debug("payload => %s", print_r($payload, true));
                foreach($payload as $key => $value) {
                    if(isset($_REQUEST[$key]) && (strcmp($_REQUEST[$key],$value))) {
                        log_debug("key : %s value:%s", $key, print_r($value, true));
                        throw new OidcException('invalid_request', "Request Object Param Values do not match request '{$key}' '{$_REQUEST[$key]}' != '{$value}'");
                    }
                }
            }
        } else {
            if(isset($_GET['id_token_hint'])) {
                $cryptoError = '';
                $payload = decrypt_verify_jwt($_REQUEST['id_token_hint'], $client, $cryptoError);
                if(!isset($payload)) {
                    if($cryptoError == 'error_decrypt')
                        throw new OidcException('invalid_request', 'Unable to decrypt request object');
                    elseif($cryptoError == 'error_sig')
                        throw new OidcException('invalid_request', 'Unable to verify request object signature');
                } else {
                    $requested_userid_display = $payload['sub'];
                    $requested_userid = unwrap_userid($payload['sub']);
                    if(!db_get_user($requested_userid))
                        throw new OidcException('invalid_request', 'Unrecognized userid in ID Token');
                }
            } else if(isset($_GET['claims']['id_token']['sub']['value'])) {
                $requested_userid_display = $_GET['claims']['id_token']['sub']['value'];
                $requested_userid = unwrap_userid($_GET['claims']['id_token']['sub']['value']);
                if(!db_get_user($requested_userid))
                    throw new OidcException( 'invalid_request', "Unrecognized userid in ID Token");
            } else if(isset($_GET['login_hint'])) {
                $principal = $_GET['login_hint'];

                $at = strpos($principal, '@');
                if($at !== false) {
                    error_log("EMAIL\n");
                    if($at != 0) {    // XRI
                        // process email address
                        list($principal, $domain) = explode('@', $principal);
                        error_log("==> principal = $principal domain = $domain");
                        $port_pos = strpos($domain, ':');
                        if($port_pos !== false)
                            $domain = substr($domain, 0, $port_pos);
                        $domain_parts = explode('.', $domain);
                        $server_parts = explode('.', OP_SERVER_NAME);
                        // check to see domain matches
                        $domain_start = count($domain_parts) - 1;
                        $server_start = count($server_parts) - 1;
                        $domain_match = true;
                        for($i = $domain_start, $j = $server_start; $i >= 0 && $j >= 0; $i--, $j--) {
                            if(strcasecmp($domain_parts[$i], $server_parts[$j]) != 0) {
                                $domain_match = false;
                            }
                        }
                        if($domain_match) {
                            $requested_userid_display = $principal;
                            $requested_userid = unwrap_userid($requested_userid_display);
                            if(!db_get_user($requested_userid)) {
                                $requested_userid_display = NULL;
                                $requested_userid = NULL;
                            }
                        } else
                            throw new OidcException('invalid_request', 'Unrecognized email domain');
                    }
                } else { // name only

                    $requested_userid_display = $_GET['login_hint'];
                    $requested_userid = unwrap_userid($requested_userid_display);
                    if(!db_get_user($requested_userid)) {
                        $requested_userid_display = NULL;
                        $requested_userid = NULL;
                    }
                }

            }

            if(!array_key_exists('max_age', $_REQUEST) && $client['default_max_age'])
                $_REQUEST['max_age'] = $client['default_max_age'];
            if($_REQUEST['max_age'])
                $_REQUEST['claims']['id_token']['auth_time'] =  array('essential' => true);
            if((!$_REQUEST['claims']['id_token'] || !array_key_exists('auth_time', $_REQUEST['claims']['id_token'])) && $client['require_auth_time'])
                $_REQUEST['claims']['id_token']['auth_time'] = array('essential' => true);
            if(!$_REQUEST['claims']['id_token'] || !array_key_exists('acr', $_REQUEST['claims']['id_token'])) {
                if($_REQUEST['acr_values'])
                    $_REQUEST['claims']['id_token']['acr'] = array('essential' => true, 'values' => explode(' ', $_REQUEST['acr_values']));
                elseif($client['default_acr_values'])
                    $_REQUEST['claims']['id_token']['acr'] = array('essential' => true, 'values' => explode('|', $client['default_acr_values']));
            }

            $_SESSION['rpfA'] = $_REQUEST;
        }

        log_debug("prompt = %s", $_SESSION['rpfA']['prompt']);
        $prompt = $_SESSION['rpfA']['prompt'] ? explode(' ', $_SESSION['rpfA']['prompt']) : array();
        $num_prompts = count($prompt);
        if($num_prompts > 1 && in_array('none', $prompt))
            throw new OidcException('interaction_required', "conflicting prompt parameters {$_SESSION['rpfA']['prompt']}");
        if(in_array('none', $prompt))
            $showUI = false;
        else
            $showUI = true;
        log_debug("num prompt = %d %s", $num_prompts,  print_r($prompt, true));

        if($_SESSION['username']) {
            if(in_array('login', $prompt)){
                echo loginform($requested_userid_display, $requested_userid, $client);
                exit();
            }
            if(isset($_SESSION['rpfA']['max_age'])) {
                if((time() - $_SESSION['auth_time']) > $_SESSION['rpfA']['max_age']) {
                    if(!$showUI)
                        throw new OidcException('interaction_required', 'max_age exceeded and prompt set to none');
                    echo loginform($requested_userid_display, $requested_userid, $client);
                    exit;
                }
            }
            if($requested_userid) {
                if($_SESSION['username'] != $requested_userid) {
                    if(!$showUI) {
//                        throw new OidcException('interaction_required', 'requested account is different from logged in account, no UI requested');
                    } else {
//                        echo loginform($requested_userid_display, $requested_userid, $client);
                        exit;
                    }
                }
            }

            // if(in_array('consent', $prompt)){
                // echo confirm_userinfo();
                // exit();
            // }
            if(!db_get_user_trusted_client($_SESSION['username'], $_REQUEST['client_id'])) {
                if(!$showUI)
                    throw new OidcException('interaction_required', 'consent needed and prompt set to none');

                echo confirm_userinfo();
            } else

                send_response_noRedirect($_SESSION['username'], true);
        } else {
			// SBE Redirect to auth_time
			send_auth_response($request_uri, array(), $response_mode);
		//	header("Location: /auth?client_id=$client_id&response_type=$_REQUEST['response_type']&scope=$_REQUEST['scope']&nonce=$_REQUEST['nonce']");
		//            if(!$showUI)
//                throw new OidcException('interaction_required', 'unauthenticated and prompt set to none');
//            echo custom_loginform($requested_userid_display, $requested_userid, $client);
        }
    }
    catch(OidcException $e) {
        log_debug("handle_auth exception : %s", $e->getTraceAsString());
        send_error($error_page, $e->error_code, $e->desc, NULL, $state, $response_mode);
    }
    catch(Exception $e) {
        log_debug("handle_auth exception : %s", $e->getTraceAsString());
        send_error($error_page, 'invalid_request', $e->getMessage(), NULL, $state, $response_mode);
    }
}


function send_response_noRedirect($username, $authorize = false)
{
    $GET=$_SESSION['get'];
    $rpfA=$_SESSION['rpfA'];
    $rpep=$GET['redirect_uri'];
    $state = isset($GET['state']) ? $GET['state'] : NULL;
    $error_page = isset($GET['redirect_uri']) ? $GET['redirect_uri'] : OP_INDEX_PAGE;
    $response_mode = get_response_mode($GET);

    try
    {
        $client_id = $GET['client_id'];
        $response_types = explode(' ', $GET['response_type']);
        $scopes = explode(' ', $GET['scope']);
        $prompts = explode(' ', $GET['prompt']);

        $is_code_flow = in_array('code', $response_types);
        $is_token_flow = in_array('token', $response_types );
        $is_id_token = in_array('id_token', $response_types);

        $offline_access = $is_code_flow && !$is_token_flow && in_array('consent', $prompts) && in_array('offline_access', $scopes);

        $issue_at = strftime('%G-%m-%d %T');
        $expiration_at = strftime('%G-%m-%d %T', time() + (2*60));
        $response_params = array();

        if(!$authorize)
            throw new OidcException('access_denied', 'User denied access');

        $rpfA['session_id'] = session_id();
        $rpfA['auth_time'] = $_SESSION['auth_time'];
        $confirmed_attribute_list = get_all_requested_claims($rpfA, $GET['scope']);

        if($is_code_flow) {
            $code_info = create_token_info($username, $confirmed_attribute_list, $GET, $rpfA);
            $code = $code_info['name'];
            unset($code_info['name']);
            $fields = array('client' => $GET['client_id'],
                'issued_at' => $issue_at,
                'expiration_at' => $expiration_at,
                'token' => $code,
                'details' => '',
                'token_type' => TOKEN_TYPE_AUTH_CODE,
                'info' => json_encode($code_info)
            );
            db_save_user_token($username, $code, $fields);
        }
        if($is_token_flow) {
            $code_info = create_token_info($username, $confirmed_attribute_list, $GET, $rpfA);
            $token = $code_info['name'];
            unset($code_info['name']);
            $issue_at = strftime('%G-%m-%d %T');
            $expiration_at = strftime('%G-%m-%d %T', time() + (2*60));
            $fields = array('client' => $GET['client_id'],
                'issued_at' => $issue_at,
                'expiration_at' => $expiration_at,
                'token' => $token,
                'details' => '',
                'token_type' => TOKEN_TYPE_ACCESS,
                'info' => json_encode($code_info)
            );
            db_save_user_token($username, $token, $fields);
        }

        if($offline_access) {
            while(true) {
                $refresh_token_name = base64url_encode(mcrypt_create_iv(32, MCRYPT_DEV_URANDOM));
                if(!db_find_token($refresh_token_name))
                    break;
            }
            $fields = array('client' => $GET['client_id'],
                'issued_at' => $issue_at,
                'expiration_at' => $expiration_at,
                'token' => $refresh_token_name,
                'details' => '',
                'token_type' => TOKEN_TYPE_REFRESH,
                'info' => json_encode($code_info)
            );
            $fields['expiration_at'] = strftime('%G-%m-%d %T', time() + (24*60*60));
            db_save_user_token($username, $refresh_token_name, $fields);
        }

        // Handle response_type for code or token
        if(isset($GET['state']))
            $response_params['state'] = $GET['state'];
        if($is_token_flow || $is_id_token) {
            if(isset($token)) {
                $response_params['access_token'] = $token;
                $response_params['token_type'] = 'Bearer';
                if($offline_access)
                    $response_params['refresh_token'] = $refresh_token_name;
                $response_params['expires_in'] = '3600';
            }
        }
        if($is_id_token) {

            $client_secret = null;
            $nonce = isset($GET['nonce']) ? $GET['nonce'] : null;
            $c_hash = null;
            $at_hash = null;
            $ops = null;
            $auth_time = null;
            $acr = null;
            $idt_claims = array();
            $sig = null;
            $alg = null;
            $enc = null;
            $client_secret = null;
            $jwk_uri = null;
            $db_client = db_get_client($client_id);
            if($db_client) {
                $sig = $db_client['id_token_signed_response_alg'];
                if(!isset($sig))
                    $sig = 'RS256';
                $alg = $db_client['id_token_encrypted_response_alg'];
                $enc = $db_client['id_token_encrypted_response_enc'];
                $client_secret = $db_client['client_secret'];
                $jwk_uri = $db_client['jwks_uri'];
                $jwks = $db_client['jwks'];
            }

            if(isset($rpfA['claims']) && isset($rpfA['claims']['id_token'])) {
                if(array_key_exists('auth_time', $rpfA['claims']['id_token']))
                    $auth_time = (int) $_SESSION['auth_time'];

                if(array_key_exists('acr', $rpfA['claims']['id_token'])) {
                    if(array_key_exists('values', $rpfA['claims']['id_token']['acr'])) {
                        if(is_array($rpfA['claims']['id_token']['acr']['values']) && count($rpfA['claims']['id_token']['acr']['values']))
                            $acr = $rpfA['claims']['id_token']['acr']['values'][0];
                    } else
                        $acr = '0';
                }
            }
            if($sig) {
                $bit_length = substr($sig, 2);
                switch($bit_length) {
                    case '384':
                        $hash_alg = 'sha384';
                        break;
                    case '512':
                        $hash_alg = 'sha512';
                        break;
                    case '256':
                    default:
                        $hash_alg = 'sha256';
                        break;
                }
                $hash_length = (int) ((int) $bit_length / 2) / 8;
                if($code)
                    $c_hash = base64url_encode(substr(hash($hash_alg, $code, true), 0, $hash_length));
                if($token)
                    $at_hash = base64url_encode(substr(hash($hash_alg, $token, true), 0, $hash_length));
            }
            $requested_id_token_claims = get_id_token_claims($rpfA);
            if($requested_id_token_claims) {
                $db_user = db_get_user($username);
                if($db_user)
                    $idt_claims = get_account_claims($db_user, $requested_id_token_claims);
                else
                    throw new OidcException('access_denied', 'no such user');
            }
            $id_token_obj = make_id_token(wrap_userid($db_client, $username), SERVER_ID, $client_id, $idt_claims, $nonce, $c_hash, $at_hash, $auth_time, $ops, $acr );

            log_debug('sen_response id_token_obj = %s', print_r($id_token_obj, true));
            $cryptoError = null;
            $id_token = sign_encrypt($id_token_obj, $sig, $alg, $enc, $jwk_uri, $jwks, $client_secret, $cryptoError);

            if(!$id_token) {
                log_error("Unable to sign encrypt response for ID Token %s", $cryptoError);
                throw new OidcException('invalid_request', "idtoken crypto error {$cryptoError}");
            }
            $response_params['id_token'] = $id_token;
        }
        $url_parts = parse_url($rpep);
        $origin = sprintf("%s://%s%s", $url_parts['scheme'], $url_parts['host'], isset($url_parts['port']) ? ':' . $url_parts['port'] : '');
        $salt = bin2hex(mcrypt_create_iv(16, MCRYPT_DEV_URANDOM));
        log_debug("ss = sha256(%s%s%s%s).%s", $client_id, $origin, $_SESSION['ops'], $salt, $salt);
        $session_state = hash('sha256', "{$client_id}{$origin}{$_SESSION['ops']}{$salt}") . '.' . $salt;
        $response_params['session_state'] = $session_state;

        if($is_code_flow) {
            $response_params['code'] = $code;
        }

        if($_SESSION['persist']=='on') {
            $username = $_SESSION['username'];
            $auth_time = $_SESSION['auth_time'];
            $ops = $_SESSION['ops'];
            $login = $_SESSION['login'];
            clean_session();
            $_SESSION['lastlogin']=time();
            $_SESSION['username']=$username;
            $_SESSION['auth_time']=$auth_time;
            $_SESSION['ops'] = $ops;
            $_SESSION['login'] = $login;
            $_SESSION['persist']='on';
        } else {
            session_destroy();
        }
        log_debug("{id_token : ".$id_token."}");

        echo $id_token;//"{id_token : ".$id_token."}";//send_auth_response($rpep, $response_params, $response_mode);
    }
    catch(OidcException $e) {
        log_error("handle_auth exception : %s", $e->getTraceAsString());
        send_error($error_page, $e->error_code, $e->desc, NULL, $state, $response_mode);
    }
    catch(Exception $e) {
        log_error("handle_auth exception : %s", $e->getTraceAsString());
        send_error($error_page, 'invalid_request', $e->getMessage(), NULL, $state, $response_mode);
    }

}
?>