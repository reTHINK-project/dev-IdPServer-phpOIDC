<?php
/**
 * Copyright 2013 Nomura Research Institute, Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

include_once("abconstants.php");
include_once('libjsoncrypto.php');
include_once("base64url.php");
include_once('libdb.php');
include_once('logging.php');

error_reporting(E_ERROR | E_WARNING | E_PARSE);

logw_debug("Request: %s\nInput: %s", count($_REQUEST) ? print_r($_REQUEST, true) : '[ ]', file_get_contents('php://input'));

$g_auth_response='';
$g_userinfo_request = '';
$g_userinfo_response = '';
$g_id_request = '';
$g_id_response = '';
$g_error = NULL;
$g_info = NULL;
$g_scripts = '';
$g_forms = '';
$g_headers = array();


$session_path = session_save_path() . RP_PATH;
if(!file_exists($session_path))
    mkdir($session_path);
session_save_path($session_path);
session_start();


if(array_key_exists('debug', $_REQUEST)) {
    if($_REQUEST['debug'] == '1')
        $_SESSION['debug'] = true;
    else
        $_SESSION['debug'] = false;
}



if($_SERVER['PATH_INFO'] == '/callback') {
    $showResponse = true;
    handle_callback();
} elseif($_SERVER['PATH_INFO'] == '/logoutcb') {
    $showResponse = false;
    handle_logout_callback();
} elseif($_SERVER['PATH_INFO'] == '/implicit') {
    $showResponse = true;
    handle_implicit_callback();
}
elseif($_SERVER['PATH_INFO'] == '/start')
    handle_start();
elseif($_SERVER['PATH_INFO'] == '/reqfile')
    handle_reqfile();
elseif($_SERVER['PATH_INFO'] == '/sector_id') {
    handle_sector_id();
    exit;
}

    

header('Content-Type: text/html; charset=utf-8');
?>

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
<title>OpenID Connect Core Draft 17 RP</title>
<meta name = "viewport" content = "width = device-width, initial-scale = 1, user-scalable = yes">

<style type="text/css" title="currentStyle">
  @import "<?php echo RP_PATH?>/media/css/demo_page.css";
  @import "<?php echo RP_PATH?>/media/css/demo_table.css";
</style>
<link type="text/css" href="<?php echo RP_PATH?>/css/smoothness/jquery-ui-1.8.6.custom.css" rel="stylesheet" />
<script type="text/javascript" src="<?php echo RP_PATH?>/js/jquery-1.4.2.min.js"></script>
<script type="text/javascript" src="<?php echo RP_PATH?>/js/jquery-ui-1.8.6.custom.min.js"></script>
<script type="text/javascript" language="javascript" src="<?php echo RP_PATH?>/media/js/jquery.dataTables.js"></script>
<script type='text/javascript' charset="utf-8">//<![CDATA[
  
<?php 
    echo $g_scripts;
?>

    
  $(document).ready(function() {
    
            $('#outer-tabs').tabs();
    
            <?php if ($g_userinfo_response)  { ?>
            var tableObj = document.getElementById('userinfotable');
            tableObj.style.visibility = 'visible'
            
            $('#userinfotable').dataTable(
                { "iDisplayLength": 50
                }
            );
            <?php } ?>

            <?php if ($g_id_response)  { ?>
            var tableObj1 = document.getElementById('idtokentable');
            tableObj1.style.visibility = 'visible'
            $('#idtokentable').dataTable(
                { "iDisplayLength": 50
                }
            );
            <?php } ?>
    }
  );
  

    function startRPTimers() {
        window.frames['rpFrame'].setTimer();
    }
    
    function stopRPTimers() {
        window.frames['rpFrame'].clearTimer();
    }

  
//]]></script>

</head>
<body style='margin:5px' id='dt_example' <?php echo $g_doLoad ?>>
<img src="<?php echo RP_PATH?>/openid_connect.png" style="width:100%">

<div style="background-color:#dddddd;">
OpenID Connect Core Draft 17
<form name='op_form' method='post' action='<?php echo RP_INDEX_PAGE ?>/start'>
Select your OP : &nbsp;
<select size="1" name='provider'>
<option selected value=''>Select OP</option>\n";    
<?php
$providers = db_get_providers();
foreach($providers as $provider) {
    if($_SESSION['provider_name'] == $provider['name'])
        $selected = 'selected';
    else
        $selected = '';
    echo "<option {$selected}>" . $provider['name'] . "</option>\n";    
}
?>
</select> <br/>
or Enter OP URL : <input type='text' name='identifier' value=''>
<?php
    echo generate_tab_html();
?>


<input type='submit' name="submit" value="Connect">&nbsp;&nbsp;<?php if(isset($_SESSION['session_state']) && isset($_SESSION['provider']['check_session_iframe'])) { ?><input type='submit' name="submit" value="Logout"> <?php } ?>
<span style="float:right">
<a href="<?php echo RP_PATH?>/">RP Top</a>
</span>
</form>
</div>

<div id='error' class='error'>
<?php
$g_error = $g_error ? $g_error : $_REQUEST['error'];
if($g_error) {
    echo "<pre>\n";
    echo $g_error . " :  ";
    echo $_REQUEST['error_description'] . "</pre>\n";
}
?>
</div>
<?php
if($g_info) {
    echo "<br/>\n<pre>" . $g_info . "</pre>\n";
}

$u=$g_userinfo_response;
$pict = $u['picture'];
if(!$pict) {
  $pict = RP_PATH . '/nowprinting350x350.gif';
}



if($showResponse){
?>
<div style="width:50%;background-color:#dddddd;border:1px solid #888888;
margin-left:auto;margin-right:auto;text-align:center">
<img id='idProfileImage' src="<?=$pict?>" style="text-align:center">
</div>

<div id='userinforesponse' style='visibility: <?php echo ($g_userinfo_response ? 'visible' : 'hidden'); ?>' >
<h1>Welcome <span id='idUserName'><?php echo $g_userinfo_response['name'] ?></span> </h1>
<h3> UserInfo Response </h3>

  <div id='container'>
      <div class="full_width big">
      </div>
<div id='demo'>
    <table cellspacing='0' cellpadding='0' class="display" id="userinfotable" style="visibility:hidden">
        <thead>
            <tr>
                <th>Name</th>
                <th>Value</th>
            </tr>
        </thead>
        <tbody>
            <?php
            $i = false;
            if(is_array($g_userinfo_response)) {
                log_debug('UserInfo  = %s', print_r($g_userinfo_response, true));
                foreach($g_userinfo_response as $key => $value) {
                    if($value == '')
                        continue;
                    if($i)
                        $class = 'gradeU';
                    else
                        $class = 'gradeU';
                    $i = !$i;
                        echo "<tr class='{$class}'>\n    <td>{$key}</td><td>{$value}</td></tr>\n";
                }
            }
            ?>

        </tbody>
    </table>
</div>
</div>

</div>


<div id='idtokenresponse' style='visibility: <?php echo ($g_id_response || $g_check_id_response ? 'visible' : 'hidden'); ?>' >

<p/><p/>
<h3> ID_Token Response </h3>

  <div id='container'>
      <div class="full_width big">
      </div>
<div id='demo'>
    <table cellspacing='0' cellpadding='0' class="display" id="idtokentable" style="visibility:hidden">
        <thead>
            <tr>
                <th>Name</th>
                <th>Value</th>
            </tr>
        </thead>
        <tbody>
            <?php
            $i = false;
            if(is_array($g_id_response)) {
                log_debug('ID Token = %s', print_r($g_id_response, true));
                foreach($g_id_response as $key => $value) {
                    if($value == '')
                        continue;
                    if($i)
                        $class = 'gradeU';
                    else
                        $class = 'gradeU';
                    $i = !$i;
                        echo "<tr class='{$class}'>\n    <td>{$key}</td><td>{$value}</td></tr>\n";
                }
            }
            ?>

        </tbody>
    </table>

</div>
</div>

</div>

<?php

}

if($g_forms)
    echo $g_forms;



function handle_implicit() {
global $g_scripts, $g_forms, $g_doLoad;

$post = RP_INDEX_PAGE . '/implicit';

$html = <<<EOF
        function doLoad() {
            var foundCode = false;
            var params = window.location.href.split(/\?|#/);
            var num_params = params.length;
            var j;
            for(j = 0; j < num_params; ++j) {
                var fragment = params[j];
                var frags = fragment.split('&');
                var i, piece;
                
                for(i = 0; i < frags.length; i++) {
                    var pieces = frags[i].split('=');
                    var key, val;
                    key = pieces[0];
                    val = pieces[1];
                    if(key == 'access_token') {
                        document.forms['form1'].access_token.value = decodeURIComponent(val);
                    } else if(key == 'code') {
                        document.forms['form1'].code.value = decodeURIComponent(val);
                        foundCode = true;
                    } else if(key == 'state') {
                        document.forms['form1'].state.value = decodeURIComponent(val);
                    } else if(key == 'id_token') {
                        document.forms['form1'].id_token.value = decodeURIComponent(val);
                    } else if(key == 'session_state') {
                        document.forms['form1'].session_state.value = decodeURIComponent(val);
                    } else if(key == 'error') {
                        document.forms['form1'].error.value = decodeURIComponent(val);
                    } else if(key == 'error_description') {
                        document.forms['form1'].error_description.value = decodeURIComponent(val);
                    }
                }
            }    

            document.forms['form1'].submit();

        }
        

EOF;

$forms = <<<EOF
    <form method='POST' name='form1' action='$post'>
        <input type='hidden' name='code' value='' size="100">
        <input type='hidden' name='access_token' value='' size="100">
        <input type='hidden' name='state' value='' size="100">
        <input type='hidden' name='id_token' value='' size="100">
        <input type='hidden' name='session_state' value='' size="100">
        <input type='hidden' name='error' value='' size="100">
        <input type='hidden' name='error_description' value='' size="100">
    </form>
EOF;

    $g_doLoad = "onload=doLoad()";
    $g_scripts .= $html;
    $g_forms .= $forms;
}


function handle_implicit_callback() {
    global $g_error, $g_info;

    $code = $_REQUEST['code'];
    $token = $_REQUEST['access_token'];
    if($_REQUEST['error'])
        return;

    if($code) {
        handle_callback();
        return;
    }
    $id_token = $_REQUEST['id_token'];
    if(!$token && !$id_token) {
        $g_error .= "No Token or ID Token";
        return;
    }
    $userinfo_ep = $_SESSION['provider']['userinfo_endpoint'];
    if($token) {
        get_userinfo($userinfo_ep, $token);
    }
    if($id_token) {
        $unpacked_id_token = rp_decrypt_verify_id_token($id_token);
        $bit_length = substr($unpacked_id_token['jws'][0]['alg'], 2);
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
        if($unpacked_id_token['jws'][1]['at_hash']) {
            $g_info .= "ID Token contains at_hash\n";
            if(!$token)
                $g_error .= "Access Token not found with ID Token response\n";
            else {
                if(base64url_encode(substr(hash($hash_alg, $token, true), 0, $hash_length)) == $unpacked_id_token['jws'][1]['at_hash'])
                    $g_info .= "Access Token Hash Verified\n";
                else
                    $g_error .= "Access Token Hash Verification Failed for access token : {$token}\n";
            }
        }

        if($unpacked_id_token['jws'][1]['c_hash']) {
            $g_info .= "ID Token contains c_hash\n";
            if(!$code)
                $g_error .= "Code not found with ID Token response\n";
            else {
                if(base64url_encode(substr(hash($hash_alg, $code, true), 0, $hash_length)) == $unpacked_id_token['jws'][1]['c_hash'])
                    $g_info .= "Code Hash Verified\n";
                else
                    $g_error .= "Code Hash Verification Failed for code {$code}\n";
            }
        }
    }

}


function rp2op_jwt_sign_encrypt($provider, $data, $sig_alg, $enc_algs = NULL) {
    try {
        if(!$provider)
            throw new Exception('No provider for crypto');

        $supported_sig_algs = array('HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512');
        $supported_enc_cek_algs = array('RSA1_5', 'RSA-OAEP');
        $supported_enc_plaintext_algs = array('A128GCM', 'A256GCM', 'A128CBC-HS256', 'A256CBC-HS512');
        if($sig_alg && in_array($sig_alg, $supported_sig_algs)) {
            log_debug("Using Sig Alg %s", $sig_alg);
            $sig_param['alg'] = $sig_alg;
            if(substr($sig_alg, 0, 2) == 'HS') {
                $sig_key = $provider['client_secret'];
            } elseif(substr($sig_alg, 0, 2) == 'RS') {
                $sig_param['jku'] = RP_JWK_URL;
                $sig_param['kid'] = RP_SIG_KID;
                $sig_key = array('key_file' => RP_SIG_PKEY, 'password' => RP_SIG_PKEY_PASSPHRASE);
            }
            $jwt = jwt_sign($data, $sig_param, $sig_key);
            if(!$jwt)
                throw new Exception('Unable to sign data');

            if($enc_algs) {
                list($cek_alg, $plaintext_alg) = explode(' ', $enc_algs);
                if($cek_alg && $plaintext_alg) {
                    if(!in_array($cek_alg, $supported_enc_cek_algs))
                        throw new Exception("Unsupported CEK alg {$cek_alg}");
                    if(!in_array($plaintext_alg, $supported_enc_plaintext_algs))
                        throw new Exception("Unsupported plaintext alg {$plaintext_alg}");
                    $jwk_uri = '';
                    $encryption_keys = NULL;
                    if($provider['jwks_uri']) {
                        $jwk = get_url($provider['jwks_uri']);
                        if($jwk) {
                            $jwk_uri = $provider['jwks_uri'];
                            $encryption_keys = jwk_get_keys($jwk, 'RSA', 'enc', NULL);
                            if(!$encryption_keys || !count($encryption_keys))
                                $encryption_keys = NULL;
                        }
                    }
                    if(!$encryption_keys)
                        throw new Exception('Unable to retrieve JWK for encryption');
                    $header_params = array('jku' => $jwk_uri);
                    if(isset($encryption_keys[0]['kid']))
                        $header_params['kid'] = $encryption_keys[0]['kid'];
                    $jwt = jwt_encrypt2($jwt, $encryption_keys[0], false, NULL, $header_params, NULL, $cek_alg, $plaintext_alg, false);
                    if(!$jwt)
                        throw new Exception('Unable to encrypt data');
                } else
                    throw new Exception('Missing CEK and Plaintext algs');
            }
            return $jwt;
        } else
            throw new Exception("Unsupported Sig Alg {$sig_alg}");

    }
    catch(Exception $e) {
        log_error('%s', $e->getMessage());
        return null;
    }
}

function handle_callback() {
  global $g_error, $g_info;

  try {
      if($_REQUEST['error'])
          return;
      $code = $_REQUEST['code'];
      $token = $_REQUEST['access_token'];
      $state = $_REQUEST['state'];
      $id_token = $_REQUEST['id_token'];
      if(isset($_REQUEST['session_state']))
          $_SESSION['session_state'] = $_REQUEST['session_state'];
      else
          unset($_SESSION['session_state']);

      if(!$code) {
          if($_SERVER['REQUEST_METHOD'] == 'POST') {
              handle_implicit_callback();
          } else
              handle_implicit();
          return;
      }
      $client_id = $_SESSION['provider']['client_id'];
      $client_secret = $_SESSION['provider']['client_secret'];
      $token_ep = $_SESSION['provider']['token_endpoint'];
      $userinfo_ep = $_SESSION['provider']['userinfo_endpoint'];
      $client_redirect_uri = RP_REDIRECT_URI;

      $url = $token_ep;

      $data = array( 'client_id' => $client_id,
          'code' => $code,
          'redirect_uri' => $client_redirect_uri,
          'grant_type' => 'authorization_code',
          'code_verifier' => $_SESSION['code_verifier']
      );
      $curl_options = array();

      $token_endpoint_auth_method = $_SESSION['provider']['token_endpoint_auth_method'];
      $token_endpoint_auth_signing_alg = $_SESSION['provider']['token_endpoint_auth_signing_alg'];
      log_debug("Token Endpoint Auth Method : %s alg : %s", $token_endpoint_auth_method, $token_endpoint_auth_signing_alg);
      switch($token_endpoint_auth_method) {
          case 'client_secret_post' :
              $data['client_id'] = $client_id;
              $data['client_secret'] = $client_secret;
              break;

          case 'client_secret_jwt' :
              $client_assertion = array(
                  'iss' => $client_id,
                  'sub' => $client_id,
                  'aud' => $token_ep,
                  'jti' => bin2hex(mcrypt_create_iv(16, MCRYPT_DEV_URANDOM )),
                  'exp' => time() + (5*60),
                  'iat' => time()
              );
              if(!$token_endpoint_auth_signing_alg)
                  $token_endpoint_auth_signing_alg = 'HS256';
              $token_endpoint_auth_signing_algs_supported = is_array($_SESSION['provider']['token_endpoint_auth_signing_alg_values_supported']) ? $_SESSION['provider']['token_endpoint_auth_signing_alg_values_supported'] : explode('|', $_SESSION['provider']['token_endpoint_auth_signing_alg_values_supported']);
              if(!in_array($token_endpoint_auth_signing_alg, $token_endpoint_auth_signing_algs_supported)) {
                  $g_error = "Token Endpoint Auth Sig Alg {$token_endpoint_auth_signing_alg} is not supported.";
                  return NULL;
              }
              $jwt = rp2op_jwt_sign_encrypt($_SESSION['provider'], $client_assertion, $token_endpoint_auth_signing_alg);
              if(!$jwt) {
                  $g_error .= 'Unable to sign client_secret_jwt';
                  log_error($g_error);
              }
              $data['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
              $data['client_assertion'] = $jwt;
              break;

          case 'private_key_jwt' :
              $client_assertion = array(
                  'iss' => $client_id,
                  'sub' => $client_id,
                  'aud' => $token_ep,
                  'jti' => bin2hex(mcrypt_create_iv(16, MCRYPT_DEV_URANDOM )),
                  'exp' => time() + (5*60),
                  'iat' => time()
              );

              if(!$token_endpoint_auth_signing_alg)
                  $token_endpoint_auth_signing_alg = 'RS256';
              $token_endpoint_auth_signing_algs_supported = is_array($_SESSION['provider']['token_endpoint_auth_signing_alg_values_supported']) ? $_SESSION['provider']['token_endpoint_auth_signing_alg_values_supported'] : explode('|', $_SESSION['provider']['token_endpoint_auth_signing_alg_values_supported']);
              if(!in_array($token_endpoint_auth_signing_alg, $token_endpoint_auth_signing_algs_supported)) {
                  $g_error = "Token Endpoint Auth Sig Alg {$token_endpoint_auth_signing_alg} is not supported.";
                  return NULL;
              }
              $jwt = rp2op_jwt_sign_encrypt($_SESSION['provider'], $client_assertion, $token_endpoint_auth_signing_alg);
              if(!$jwt) {
                  $g_error .= 'Unable to sign private_key_jwt';
                  log_error($g_error);
              }
              $data['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
              $data['client_assertion'] = $jwt;
              break;

          case '':
          case 'client_secret_basic' :
          default :
              $curl_options[CURLOPT_HTTPAUTH] = CURLAUTH_BASIC;
              $curl_options[CURLOPT_USERPWD] = "{$client_id}:{$client_secret}";
              break;
      }


      list($status_code, $data_content_type, $req_out, $response_headers, $data_responseText) = curl_fetch_url($url, NULL, $curl_options, true, $data);
      if($status_code != 200) {
          $g_error .= "Unable to get Access Token.\n{$req_out}\n{$response_headers}\n{$data_responseText}";
          log_error($g_error);
          return;
      } elseif(strpos($data_content_type, 'application/json') !== false) {
          $obj = json_decode($data_responseText, true);
          if(!$obj) {
              $g_error .= "Unable to get access token.\n{$req_out}\n{$response_headers}\n{$data_responseText}";
              log_error($g_error);
              return;
          }
          if(isset($obj['access_token'])) {
              get_userinfo($userinfo_ep, $obj['access_token']);
          } else
              log_debug("Token Endpoint - %s\n%s\n%s", $req_out, $response_headers, $data_responseText);
          if(!$id_token) {
              $id_token = $obj['id_token'];
              $g_info .= "Using ID Token from Token Endpoint Response\n";
          } else {
              $g_info .= "Using ID Token from User-Agent\n";
          }
          if(isset($id_token)) {
              $g_info .= "{$id_token}\n";
              $unpacked_id_token = rp_decrypt_verify_id_token($id_token);
              $bit_length = substr($unpacked_id_token['jws'][0]['alg'], 2);
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
              if($unpacked_id_token['jws'][1]['at_hash']) {
                  $g_info .= "ID Token contains at_hash\n";
                  if(!$token)
                      $g_error .= "Access Token not found with ID Token response\n";
                  else {
                      if(base64url_encode(substr(hash($hash_alg, $token, true), 0, $hash_length)) == $unpacked_id_token['jws'][1]['at_hash'])
                          $g_info .= "Access Token Hash Verified\n";
                      else {
                          $g_error .= "Access Token Hash Verification Failed for access token : {$token}.\n";
                      }
                  }
              }

              if($unpacked_id_token['jws'][1]['c_hash']) {
                  $g_info .= "ID Token contains c_hash\n";
                  if(!$code)
                      $g_error .= "Code not found with ID Token response\n";
                  else {
                      if(base64url_encode(substr(hash($hash_alg, $code, true), 0, $hash_length)) == $unpacked_id_token['jws'][1]['c_hash'])
                          $g_info .= "Code Hash Verified\n";
                      else
                          $g_error .= "Code Hash Verification Failed for code {$code}\n";
                  }
              }
          }
      } else {
          $g_error .= "Unable to get Access Token.\n{$req_out}\n{$response_headers}\n{$data_responseText}";
          log_error($g_error);
          return;
      }
  }
  catch(Exception $e) {
      log_error("handle_callback exception : %s", $e->getMessage());
  }
}


function post_process_userinfo(&$userinfo_response) {
    global $g_error;
    $aggregated_claims = array();
    $distributed_claims = array();

    if(isset($userinfo_response['address']) && is_array($userinfo_response['address'])) {
        if(isset($userinfo_response['address']['formatted']))
            $userinfo_response['address'] = $userinfo_response['address']['formatted'];
        else
            $userinfo_response['address'] = "{$userinfo_response['address']['street_address']}\n{$userinfo_response['address']['locality']}, {$userinfo_response['address']['region']} {$userinfo_response['address']['postal_code']}\n{$userinfo_response['address']['country']}";
    }
    if(isset($userinfo_response['_claim_names'])) {
        if(isset($userinfo_response['_claim_sources'])) {
        }
        else
            $g_error .= "_claim_names exist but no _claim_sources";
            
        $sources = array_unique($userinfo_response['_claim_names']);
        log_debug('unique sources = %s', print_r($sources, true));
        log_debug('sources = %s', print_r($userinfo_response['_claim_names'], true));
        foreach($sources as $claim => $source) {
            log_info('source = %s', $source);
            
            $keys = array_keys($userinfo_response['_claim_names'], $source);
            log_debug("claims with source %s = %s", $source, print_r($keys, true));
            
            if($userinfo_response['_claim_sources'][$source]) {
                if(isset($userinfo_response['_claim_sources'][$source]['JWT'])) {
                    log_debug("aggregated claims using %s as claim_source %s", $source, print_r($keys, true));
                    $temp_aggregated_claims = rp_decrypt_verify_jwt($userinfo_response['_claim_sources'][$source]['JWT']);
                    $diff = array_diff($keys, array_keys($temp_aggregated_claims));
                    if(count($diff))
                        $g_error .= 'aggregated claims not provided ' . print_r($diff, true);
                    log_info('Aggregated claims = %s', print_r($temp_aggregated_claims, true));
                    $aggregated_claims = array_merge($aggregated_claims, $temp_aggregated_claims);                    
                } elseif(isset($userinfo_response['_claim_sources'][$source]['endpoint'])) {
                    log_info("distributed claims using %s as claim_source %s", $source,print_r($keys, true));
                    if(isset($userinfo_response['_claim_sources'][$source]['access_token'])) {
                        $temp_distributed_claims = get_endpoint_claims($userinfo_response['_claim_sources'][$source]['endpoint'], $userinfo_response['_claim_sources'][$source]['access_token']);
                        $diff = array_diff($keys, array_keys($temp_distributed_claims));
                        if(count($diff))
                            $g_error .= 'distributed claims not provided ' . print_r($diff, true);                    
                        log_info('Distributed claims = %s', print_r($temp_distributed_claims, true));
                        $distributed_claims = array_merge($distributed_claims, $temp_distributed_claims);                    
                    } else
                        $g_error .= "no access token provided for {$source} {$userinfo_response['_claim_sources'][$source]['endpoint']}";
                }
            }
        }
       $userinfo_response['_claim_names'] = print_r($userinfo_response['_claim_names'], true);
        if(isset($userinfo_response['_claim_sources'])) {
            $userinfo_response['_claim_sources'] = print_r($userinfo_response['_claim_sources'], true);
        }
        $userinfo_response = array_merge($userinfo_response, $aggregated_claims, $distributed_claims);
    }


}

function get_endpoint_claims($endpoint, $token) {
    global $g_headers, $g_error, $g_info;
    $is_post = false;
    $headers = NULL;
    $data = NULL;
    $query_params = array();
    $curl_options = array();

    $method = $_SESSION['bearer'] ? $_SESSION['bearer'] : 'post';
    switch($method) {
        case 'get':
            $query_params['access_token'] = $token;
            break;
        
        case 'post':
            $is_post = true;
            $data = array('access_token' => $token);
            break;
            
        case 'bearer':
            $headers = array("Authorization: Bearer {$token}");
        default :
            break;
    }
    $url = $endpoint . (count($query_params)) ? '?' . http_build_query($query_params) : '';
    list($code, $data_content_type, $req_out, $response_headers, $data_responseText) = curl_fetch_url($url, $headers, $curl_options, $is_post, $data);

    if($code != 200) {
        $g_error .= "Unable to get Endpoint Info.\n{$req_out}\n{$response_headers}\n{$data_responseText}";
        log_error($g_error);
        return;
    } elseif(strpos($data_content_type, 'application/json') !== false) {
        $endpoint_info = json_decode($data_responseText, true);
        if(!$endpoint_info) {
            $g_error .= "Unable to get Endpoint.\n{$req_out}\n{$response_headers}\n{$data_responseText}";
            log_error($g_error);
        }
        
    } elseif(strpos($data_content_type, 'application/jwt') !== false) {
        $jwt_parts = jwt_to_array($data_responseText);
        if(isset($jwt_parts[0]['enc'])) { // encrypted
            $g_info .= "Encrypted Endpoint Info {$jwt_parts[0]['enc']} {$jwt_parts[0]['alg']}\n";
            $signed_jwt = jwt_decrypt($data_responseText, RP_ENC_PKEY, true, RP_ENC_PKEY_PASSPHRASE);
            if(!$signed_jwt) {
                $g_error .= "Unable to decrypt UserInfo response";
                log_error($g_error);
                return;
            }
        } else { // signed 
            $signed_jwt = $data_responseText;
            $g_info .= "Signed Endpoint {$jwt_parts[0]['alg']}\n";
        }

        if($signed_jwt) {
            list($header, $payload, $sig) = jwt_to_array($signed_jwt);
            if(substr($header['alg'], 0, 2) == 'HS') {
                $verified = jwt_verify($signed_jwt, $_SESSION['provider']['client_secret']);
            } elseif(substr($header['alg'], 0, 2) == 'RS') {
                $pubkeys = array();
                if($_SESSION['provider']['jwks_uri'])
                    $pubkeys['jku'] = $_SESSION['provider']['jwks_uri'];
                $verified = jwt_verify($signed_jwt, $pubkeys);
            } elseif($header['alg'] == 'none')
                $verified = true;
            log_info("Endpoint Info Signature Verification = %d", $verified);
            if($verified) {
                $endpoint_info = $payload;
                $g_info .= "Endpoint Info Signature Verified\n";
            } else
                $g_info .= "Endpoint Signature Verification Failed\n";
        }
    } else {
        $g_error .= "Unable to get Endpoint.\n{$req_out}\n{$response_headers}\n{$data_responseText}";
        log_error($g_error);
    }
    return $endpoint_info;    
}    

function get_userinfo($userinfo_ep, $token) {
    global $g_userinfo_request, $g_userinfo_response, $g_error, $g_info;
    $is_post = false;
    $headers = NULL;
    $data = NULL;
    $query_params = array();
    $curl_options = array();
    $method = $_SESSION['bearer'] ? $_SESSION['bearer'] : 'post';
    switch($method) {
        case 'get':
            $query_params['access_token'] = $token;
            break;
        
        case 'post':
            $is_post = true;
            $data = array('access_token' => $token);
            break;
            
        case 'bearer':
            $headers = array("Authorization: Bearer {$token}");
        default :
            break;
    }
    $url = $userinfo_ep . ( count($query_params) ? '?' . http_build_query($query_params) : '');
    list($code, $data_content_type, $req_out, $response_headers, $data_responseText) = curl_fetch_url($url, $headers, $curl_options, $is_post, $data);
    $g_userinfo_request=$req_out;

    if($code != 200) {
        $g_error .= "Unable to get UserInfo.\n{$req_out}\n{$response_headers}\n{$data_responseText}";
        log_error('%s', $g_error);
        return;
    } elseif(strpos($data_content_type, 'application/json') !== false) {
        $userinfo = json_decode($data_responseText, true);
        post_process_userinfo($userinfo);
        $g_userinfo_response = $userinfo;
        if(!$userinfo) {
            $g_error .= "Unable to get UserInfo.\n{$req_out}\n{$response_headers}\n{$data_responseText}";
            log_error('%s', $g_error);
        }
    } elseif(strpos($data_content_type, 'application/jwt') !== false) {
        $jwt_parts = jwt_to_array($data_responseText);
        if(isset($jwt_parts[0]['enc'])) { // encrypted
            $g_info .= "Encrypted UserInfo {$jwt_parts[0]['enc']} {$jwt_parts[0]['alg']} {$jwt_parts[0]['int']}\n";
            $signed_jwt = jwt_decrypt($data_responseText, RP_ENC_PKEY, true, RP_ENC_PKEY_PASSPHRASE);
            if(!$signed_jwt) {
                $g_error .= "Unable to decrypt UserInfo response";
                log_error('%s', $g_error);
                return;
            }else {
                if(!$_SESSION['provider']['userinfo_signed_response_alg']) {
                    $g_info .= "UserInfo is Unsigned\n";
                    $g_userinfo_response = json_decode($signed_jwt, true);
                    post_process_userinfo($g_userinfo_response);
                    $signed_jwt = NULL;
                }
            }
        } else { // signed 
            $signed_jwt = $data_responseText;
            $g_info .= "Signed UserInfo {$jwt_parts[0]['alg']}\n";
        }

        if($signed_jwt) {
            list($header, $payload, $sig) = jwt_to_array($signed_jwt);
            if(substr($header['alg'], 0, 2) == 'HS') {
                $verified = jwt_verify($signed_jwt, $_SESSION['provider']['client_secret']);
            } elseif(substr($header['alg'], 0, 2) == 'RS') {
                $pubkeys = array();
                if($_SESSION['provider']['jwks_uri'])
                    $pubkeys['jku'] = $_SESSION['provider']['jwks_uri'];
                $verified = jwt_verify($signed_jwt, $pubkeys);
            } elseif($header['alg'] == 'none')
                $verified = true;
            log_info("Signature Verification = %d", $verified);
            if($verified) {
                post_process_userinfo($payload);
                $g_userinfo_response = $payload;
                $g_info .= "UserInfo Signature Verified\n";
            } else
                $g_info .= "UserInfo Signature Verification Failed\n";
        }
    } else {
        $g_error .= "Unable to get UserInfo.\n{$req_out}\n{$response_headers}\n{$data_responseText}";
        log_error('%s', $g_error);
    }    
}


function rp_decrypt_verify_jwt($jwt) {
    global $g_info, $g_error;
    $response = array();
    
    $jwt_parts = jwt_to_array($jwt);
    if(isset($jwt_parts[0]['enc'])) { // encrypted
        $g_info .= "Encrypted JWT - {$jwt_parts[0]['enc']} {$jwt_parts[0]['alg']} {$jwt_parts[0]['int']}\n";
        $signed_jwt = jwt_decrypt($jwt, RP_ENC_PKEY, true, RP_ENC_PKEY_PASSPHRASE);
        if(!$signed_jwt) {
            $g_error .= "Unable to decrypt JWT";
            log_error('%s', $g_error);
            return NULL;
        }
    } else { // signed 
        $signed_jwt = $jwt;
        $g_info .= "Signed JWT {$jwt_parts[0]['alg']}\n";
    }

    if($signed_jwt) {
        list($header, $payload, $sig) = jwt_to_array($signed_jwt);
        if(substr($header['alg'], 0, 2) == 'HS') {
            $verified = jwt_verify($signed_jwt, $_SESSION['provider']['client_secret']);
        } elseif(substr($header['alg'], 0, 2) == 'RS') {
            $pubkeys = array();
            if($_SESSION['provider']['jwks_uri'])
                $pubkeys['jku'] = $_SESSION['provider']['jwks_uri'];
            $verified = jwt_verify($signed_jwt, $pubkeys);
        } elseif($header['alg'] == 'none')
            $verified = true;
        log_info("Signature Verification = $verified");
        if($verified) {
            $response = $payload;
            $g_info .= "JWT Signature Verified\n";
        } else
            $g_info .= "JWT Signature Verification Failed\n";
    }
    return $response;
}

function rp_decrypt_verify_id_token($id_token) {
    global $g_id_response, $g_info, $g_error;
    $response = array();
    
    
    $jwt_parts = jwt_to_array($id_token);
    if(isset($jwt_parts[0]['enc'])) { // encrypted
        $g_info .= "Encrypted ID Token - {$jwt_parts[0]['enc']} {$jwt_parts[0]['alg']} {$jwt_parts[0]['int']}\n";
        $response['jwe'] = $jwt_parts;
        $signed_jwt = jwt_decrypt($id_token, RP_ENC_PKEY, true, RP_ENC_PKEY_PASSPHRASE);
        if(!$signed_jwt) {
            $g_error .= "Unable to decrypt ID Token response";
            log_error('%s', $g_error);
            return;
        }
    } else { // signed 
        $signed_jwt = $id_token;
        $g_info .= "Signed ID Token {$jwt_parts[0]['alg']}\n";
    }

    if($signed_jwt) {
        list($header, $payload, $sig) = jwt_to_array($signed_jwt);
        $g_info .= "Signed ID Token {$header['alg']}\n";
        $response['jws'] = array($header, $payload, $sig);
        if(substr($header['alg'], 0, 2) == 'HS') {
            $verified = jwt_verify($signed_jwt, $_SESSION['provider']['client_secret']);
        } elseif(substr($header['alg'], 0, 2) == 'RS') {
            $pubkeys = array();
            if($_SESSION['provider']['jwks_uri'])
                $pubkeys['jku'] = $_SESSION['provider']['jwks_uri'];
            $verified = jwt_verify($signed_jwt, $pubkeys);
        } elseif($header['alg'] == 'none')
            $verified = true;
        log_info("Signature Verification = %d", $verified);
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
            $g_info .= "ID Token Signature Verified\n";
            $_SESSION['id_token'] = $signed_jwt;
        } else
            $g_info .= "ID Token Signature Verification Failed\n";
    }
    return $response;
}

function doDiscovery($url) {
    global $g_error;
    list($code, $data_content_type, $req_out, $response_headers, $data_responseText) = curl_fetch_url($url);
    if($code != 200) {
        $g_error .= "Unable to get well-known config.\n{$req_out}\n{$response_headers}\n{$data_responseText}";
        log_error('%s', $g_error);
        return NULL;
    }
    elseif(strpos($data_content_type,'application/json') !== false) {
        $discovery = json_decode($data_responseText, true);
        if(!$discovery) {
            $g_error .= "Unable to get well-known config.\n{$req_out}\n{$response_headers}\n{$data_responseText}";
            log_error('%s', $g_error);
            return NULL;
        }
        if(!isset($discovery['token_endpoint_auth_methods_supported'])) {
            $discovery['token_endpoint_auth_methods_supported'] = array('client_secret_basic');
        }
//        $discovery['url'] = $issuer_url;
        log_info("Discovery URL = %s", $discovery['url']);
        return $discovery;
    } else {
        $g_error .= "Unable to get well-known config.\n{$req_out}\n{$response_headers}\n{$data_responseText}";
        log_error('%s', $g_error);
    }

}

function saveHeaders($ch, $str) {
    global $g_headers;
    $g_headers[$ch] .= $str;
    return strlen($str);
}


function webfinger_get_provider_info($identifier) {
    global $g_error;

    try {
        $is_post = false;
        $headers = NULL;
        $data = NULL;
        $curl_options = array();
        $issuer_url = NULL;

        $at = strpos($identifier, '@');
        if($at !== false) {
            if($at == 0)    // XRI
            return NULL;
            // process email address
            $host = substr($identifier, $at + 1);
            $issuer = RP_PROTOCOL . "$host";
            $issuer_url = $issuer;
            $principal = 'acct:' . $identifier;
            log_info("RP - EMAIL principal = %s host = %s issuer = %s", $principal, $host, $issuer);
        } else { // process URL
            $scheme = strtolower(substr($identifier, 0, 4));
            if($scheme != 'http')
                $identifier = RP_PROTOCOL . "{$identifier}";

            $pos = strpos($identifier, '#');
            if($pos !== false)
                $identifier = substr($identifier, 0, $pos);
            $parts = parse_url($identifier);
            if(!$parts)
                return NULL;
            $host = $parts['host'];
            $port = $parts['port'] ? ':' . $parts['port'] : '';
            $issuer = RP_PROTOCOL . "{$host}{$port}";
            $issuer_url = $issuer;
            if(isset($parts['path']) && $parts['path'] == '/')
                $principal = $issuer;
            else
                $principal = $identifier;
            if(substr($identifier, -32) == '.well-known/openid-configuration') {
                $p_info =  doDiscovery($identifier);
                $p_info['url'] = substr($identifier, 0, strlen($identifier) - 32);
                return $p_info;
            }
        }
        $query_params = Array( 'resource' => $principal, 'rel' => 'http://openid.net/specs/connect/1.0/issuer');
        $headers = array('Accept: application/json');
        $url = $issuer . '/.well-known/webfinger?' . http_build_query($query_params);
        while(true) {
            list($code, $data_content_type, $req_out, $response_headers, $data_responseText) = curl_fetch_url($url, $headers, $curl_options, $is_post, $data);
            if($code != 200) {
                $g_error .= "Unable to perform WebFinger discovery.\n{$req_out}\n{$response_headers}\n{$data_responseText}";
                throw new Exception($g_error);
            } elseif((strpos($data_content_type,'application/jrd+json') !== false) || (strpos($data_content_type,'application/json') !== false)) {
                $swd = json_decode($data_responseText, true);
                if(!$swd) {
                    $g_error .= "Unable to perform WebFinger discovery.\n{$req_out}\n{$response_headers}\n{$data_responseText}";
                    throw new Exception($g_error);
                }
                if(!isset($swd['links'])) {
                    $g_error .= 'No links in document returned';
                    throw new Exception($g_error);
                }
                $link = null;
                foreach($swd['links'] as $temp_link) {
                    if($temp_link['rel'] == 'http://openid.net/specs/connect/1.0/issuer' && isset($temp_link['href'])) {
                        $link = $temp_link;
                    }
                }
                if(!$link) {
                    $g_error .= "No Issuer Link.\n{$req_out}\n{$response_headers}\n{$data_responseText}";
                    throw new Exception($g_error);
                }

                if(isset($link['href'])) {
                    $url = $link['href'] . '/.well-known/openid-configuration';
                    $p_info = doDiscovery($url);
                    if($p_info)
                        $p_info['url'] = $issuer_url;
                    return $p_info;
                }
            } else {
                $g_error .= "Unable to perform WebFinger discovery.\n{$req_out}\n{$response_headers}\n{$data_responseText}";
                throw new Exception($g_error);
            }
            break;
        }
    } catch(Exception $e) {
        log_error("webfinger_get_provider_info exception : %s", $e->getMessage());
    }
    return null;

}



function register_client($url, $options = array()) {
    global $g_error;

    try {
        $is_post = true;
        $headers = NULL;
        $curl_options = array();
        $request_uris = array();
        for($i = 1; $i < 2; $i++) {
            $request_uris[] = RP_INDEX_PAGE . sprintf("/reqfile?fileid=%010d", $i);
        }

        $data = array(
            'contacts' => array('me@example.com'),
            'application_type' => 'web',
            'client_name' => 'ABRP-17',
            'logo_uri' => RP_URL . '/media/logo.png',
            'redirect_uris' => array(RP_REDIRECT_URI, RP_AUTHCHECK_REDIRECT_URI),
            'post_logout_redirect_uris' => array(RP_POST_LOGOUT_REDIRECT_URI),
            'jwks_uri' => RP_JWK_URL,
//            'jwks' => json_decode($jwks),
//            'sector_identifier_uri' => RP_INDEX_PAGE . '/sector_id',
            'policy_uri' => RP_INDEX_PAGE . '/policy',
//            'request_uris' => $request_uris,
            'grant_types' => array('authorization_code', 'implicit'),
            'response_types' => array('code', 'token', 'id_token', 'code token', 'code id_token', 'id_token token', 'code id_token token')
        );

        $curl_options[CURLOPT_POSTFIELDS] = pretty_json(json_encode(array_merge($data, $options)));
        $curl_options[CURLOPT_HTTPHEADER] = array('Content-Type: application/json');
        list($code, $data_content_type, $req_out, $response_headers, $data_responseText) = curl_fetch_url($url, $headers, $curl_options, $is_post);
        if($code != 200) {
            $g_error .= "Unable to register client.\n{$req_out}\n{$response_headers}\n{$data_responseText}";
            throw new Exception($g_error);
        } elseif(strpos($data_content_type,'application/json') !== false) {
            $client_info = json_decode($data_responseText, true);
            if(!$client_info) {
                $g_error .= "Unable to register client.\n{$req_out}\n{$response_headers}\n{$data_responseText}";
                throw new Exception($g_error);
            }
            return $client_info;
        } else {
            $g_error .= "Unable to register client.\n{$req_out}\n{$response_headers}\n{$data_responseText}";
            throw new Exception($g_error);
        }
    } catch(Exception $e) {
        log_error("register_client exception : %s", $e->getMessage());
    }
    return NULL;
}


function read_client_info($url, $access_token){
    global $g_error;
    $is_post = false;
    $headers = NULL;
    $data = NULL;
    $curl_options = array(CURLOPT_HTTPHEADER => array("Authorization: Bearer {$access_token}"));

    list($code, $data_content_type, $req_out, $response_headers, $data_responseText) = curl_fetch_url($url, $headers, $curl_options, $is_post, $data);
    if($code != 200) {
        $g_error .= "Unable to read client.\n{$req_out}\n{$response_headers}\n{$data_responseText}";
        log_error('%s', $g_error);
        return NULL;
    } elseif(strpos($data_content_type,'application/json') !== false) {
        $client_info = json_decode($data_responseText, true);
        if(!$client_info) {
            $g_error .= "Unable to update client.\n{$req_out}\n{$response_headers}\n{$data_responseText}";
            log_error('%s', $g_error);
            return NULL;
        }
        return $client_info;
    } else {
        $g_error .= "Unable to update client.\n{$req_out}\n{$response_headers}\n{$data_responseText}";
        log_error('%s', $g_error);
    }
    return NULL;
}

function remember_session_form_options($request) {
    $r = $request;
    $options = array(
                        'response_type',
                        'request_method',
//                        'request_get',
//                        'request_object',
//                        'request_file',
                        'request_option',
                        'response_mode',
                        'page',
                        'prompt_none',
                        'prompt_login',
                        'prompt_consent',
                        'prompt_select_account',
                        'scope_openid',
                        'scope_profile',
                        'scope_email',
                        'scope_address',
                        'scope_phone',                        
                        'scope_offline_access',                        
                        'bearer',
                        'token_endpoint_auth_method',
                        'token_endpoint_auth_signing_alg',
                        'subject_type',
                        'request_object_signing_alg',
                        'request_object_encrypted_response_alg',
                        'request_object_encrypted_response_enc',
                        'userinfo_signed_response_alg',
                        'userinfo_encrypted_response_alg',
                        'userinfo_encrypted_response_enc',
                        'id_token_signed_response_alg',
                        'id_token_encrypted_response_alg',
                        'id_token_encrypted_response_enc',
                        'default_max_age',
                        'require_auth_time',
                        'default_acr_values',
                        'login_hint'
                   );
                    
    foreach($options as $r_key) {
        $_SESSION[$r_key] = $r[$r_key];
    }
    $_SESSION['provider_name'] = $request['provider'];
}

function check_client_update_options($request, $discovery_info) {
    global $g_error;
    $r = $request;
    $d = $discovery_info;

    $response_type = explode(' ', $r['response_type']);
    asort($response_type);
    $response_type = implode(' ', $response_type);

    $sorted_response_types_supported = array();
    if(is_array($d['response_types_supported']))
        $response_types_supported = $d['response_types_supported'];
    else
        $response_types_supported = explode('|', $d['response_types_supported']);
    foreach($response_types_supported as $supported_type) {
        $type = explode(' ', $supported_type);
        asort($type);
        $type = implode(' ', $type);
        $sorted_response_types_supported[] = $type;
    }
  
//    $response_type = explode(' ', $r['response_type']);
//    asort($response_type);
//    $response_type = implode(' ', $response_type);
//    
//    $sorted_response_types_supported = array();
//    $response_types_supported = $d['response_types_supported'];
//    foreach($d['response_types_supported'] as $supported_type) {
//        $type = explode(' ', $supported_type);
//        asort($type);
//        $type = implode(' ', $type);
//        $sorted_response_types_supported[] = $type;
//    }
    if(!in_array($response_type, $sorted_response_types_supported)) {
        $g_error .= "Response Type {$response_type} is not supported.";
        return false;
    }
    
    $options = array(
//                        'response_type' => array('Response Type', 'response_types_supported'),
                        'token_endpoint_auth_method' => array('Token Endpoint Auth Method', 'token_endpoint_auth_methods_supported'),
                        'token_endpoint_auth_signing_alg' => array('Token Endpoint Auth Sig Alg', 'token_endpoint_auth_signing_alg_values_supported'),
                        'subject_type' => array('Subject Type', 'subject_types_supported'),
                        'request_object_signing_alg' => array('Request Object Sig Alg', 'request_object_signing_alg_values_supported'),
                        'userinfo_signed_response_alg' => array('UserInfo Sig Alg', 'userinfo_signing_alg_values_supported'),
                        'id_token_signed_response_alg' => array('ID Token Sig Alg', 'id_token_signing_alg_values_supported'),
                    );
    
    foreach($options as $r_key => $value) {
        list($text, $d_key) = $value;
        if(is_array($d[$d_key]))
            $dkey = $d[$d_key];
        else
            $dkey = explode('|', $d[$d_key]);
        if($r[$r_key] && (!isset($d[$d_key]) || !in_array($r[$r_key], $dkey))) {
            $g_error .= "{$text} {$r[$r_key]} is not supported.";
            log_error($g_error);
//            return false;
        }
    }
    
    if($r['token_endpoint_auth_method']) {
        if($r['token_endpoint_auth_method'] == 'client_secret_jwt') {
            if(!$r['token_endpoint_auth_signing_alg'])
                $r['token_endpoint_auth_signing_alg'] = 'HS256';
            if(substr($r['token_endpoint_auth_signing_alg'], 0, 2) != 'HS')
                $g_error = "Token Endpoint Auth Type client_secret_jwt requires a HMAC signing algorithm, not {$r['token_endpoint_auth_signing_alg']}";
        } elseif($r['token_endpoint_auth_method'] == 'private_key_jwt') {
            if(!$r['token_endpoint_auth_signing_alg'])
                $r['token_endpoint_auth_signing_alg'] = 'RS256';
            if(substr($r['token_endpoint_auth_signing_alg'], 0, 2) != 'RS')
                $g_error = "Token Endpoint Auth Type client_secret_jwt requires a RSA signing algorithm, not {$r['token_endpoint_auth_signing_alg']}";
        }
        if($g_error)
            return false;
    }
    
    $options = array(
                        'request_object_signing_alg' => array(
                                                                    array('request_object_encrypted_response_alg', 'Request Object Encryption Alg', 'request_object_encryption_alg_values_supported'),
                                                                    array('request_object_encrypted_response_enc', 'Request Object Encryption Enc', 'request_object_encryption_enc_values_supported')
                                                                ),
                        'userinfo_signed_response_alg' => array(
                                                                    array('userinfo_encrypted_response_alg', 'UserInfo Encryption Alg', 'userinfo_encryption_alg_values_supported'),
                                                                    array('userinfo_encrypted_response_enc', 'UserInfo Encryption Enc', 'userinfo_encryption_enc_values_supported')
                                                                ),
                        'id_token_signed_response_alg' => array(
                                                                    array('id_token_encrypted_response_alg', 'ID Token Encryption Alg', 'id_token_encryption_alg_values_supported'),
                                                                    array('id_token_encrypted_response_enc', 'ID Token Encryption Enc', 'id_token_encryption_enc_values_supported')
                                                                )
                    );

    foreach($options as $r_key => $value) {
        list($v1, $v2, $v3) = $value;
        if($r[$r_key] && $r[$v1[0]] && $r[$v2[0]]) {
            if(!in_array($r[$v1[0]], $d[$v1[2]])) {
                $g_error .= "{$v1[1]} {$r[$v1[0]]} is not supported.";
                return false;
            }
            if(!in_array($r[$v2[0]], $d[$v2[2]])) {
                $g_error .= "{$v2[1]} {$r[$v2[0]]} is not supported.";
                return false;
            }
            if($r[$v3[0]] && !in_array($r[$v3[0]], $d[$v3[2]])) {
                $g_error .= "{$v3[1]} {$r[$v3[0]]} is not supported.";
                return false;
            }
        }
    }
    return true;
}

function get_update_options($request, $provider_info = array()) {
    global $g_error;
    $r = $request;
    $p = $provider_info;

    $options = array(
                        'token_endpoint_auth_method',
                        'token_endpoint_auth_signing_alg',
                        'subject_type',
                        'request_object_signing_alg',
                        'request_object_encrypted_response_alg',
                        'request_object_encrypted_response_enc',
                        'userinfo_signed_response_alg',
                        'userinfo_encrypted_response_alg',
                        'userinfo_encrypted_response_enc',
                        'id_token_signed_response_alg',
                        'id_token_encrypted_response_alg',
                        'id_token_encrypted_response_enc',
                        'default_max_age',
                        'require_auth_time',
                        'default_acr_values'
                    );


    $update = array();
    
    // returns all options
    foreach($options as $option) {
        $update[$option] = $r[$option] ? $r[$option] : NULL;
    }

    if($update['require_auth_time']) {
        if($update['require_auth_time'] == 'true')
            $update['require_auth_time'] = true;
        else
            $update['require_auth_time'] = false;
    }

    if($update['default_acr_values']) {
        $update['default_acr_values'] = explode(' ', $update['default_acr_values']);
    }

    
    return $update;
}


function handle_logout() {
    $id_token = isset($_SESSION['id_token']) ? $_SESSION['id_token'] : '';
    $end_session_endpoint = isset($_SESSION['provider']['end_session_endpoint']) ? $_SESSION['provider']['end_session_endpoint'] : '';
    $params = array('post_logout_redirect_uri' => RP_INDEX_PAGE . '/logoutcb');
    unset($_SESSION['id_token']);
    unset($_SESSION['session_state']);
    if($end_session_endpoint) {
        if($id_token)
            $params['id_token_hint'] = $id_token;
        $url = $end_session_endpoint . '?' . http_build_query($params);
        header("Location: $url");
    }
}


function handle_logout_callback() {
    global $g_info;
    $g_info .= 'You are logged out.';
}


function handle_start() {
    global $g_error;
    $update = false;
    if($_REQUEST['submit'] == 'Logout') {
        handle_logout();
        exit;
    }

    unset($_SESSION['id_token']);
    unset($_SESSION['session_state']);
    unset($_SESSION['code_verifier']);

    remember_session_form_options($_REQUEST);
    log_debug("handle_start : %s", print_r($_REQUEST, true));
    $provider = $_REQUEST['provider'];
    $identifier = $_REQUEST['identifier'];
    if(!$provider && !$identifier) {
        $g_error .= "No Identity Provider";
        return;
    }
    if($identifier) {
        $discovery = webfinger_get_provider_info($identifier);
        if(!$discovery) {
            $g_error .= "Unable to perform discovery";
            return;
        }
        if(!check_client_update_options($_REQUEST, $discovery))
            return;
        
        $db_provider = db_get_provider_by_url($discovery['url']);
        $provider = $db_provider;
        if(!$provider || !(isset($provider['client_id']) && isset($provider['client_secret']))) {
            if(!isset($discovery['registration_endpoint'])) {
                $g_error .= "Provider not found in db for {$discovery['issuer']} and no registration endpoint";
                return;
            }
            $client_options = get_update_options($_REQUEST);
            $client_info = register_client($discovery['registration_endpoint'], $client_options);
            if(!$client_info) {
                $g_error .= "Unable to register client";
                return;
            }
            $provider = array_merge(
                                     array(
                                            'name' => $discovery['issuer'],
                                            'url' => $discovery['url'],
                                            'issuer' => $discovery['issuer'],
                                            'client_id' => $client_info['client_id'],
                                            'client_id_issued_at' => $client_info['client_id_issued_at'],
                                            'client_secret' => $client_info['client_secret'],
                                            'registration_access_token' => $client_info['registration_access_token'],
                                            'registration_client_uri' => $client_info['registration_client_uri'],
                                            'client_secret_expires_at' => $client_info['client_secret_expires_at']
                                          ),
                                    $client_options
                                   );
            db_save_provider($discovery['issuer'], $provider);
            $provider = array_merge($provider, $client_info);
            $provider = array_merge($provider, $discovery);
        } else {
            $provider->delete();
            if(!isset($discovery['registration_endpoint'])) {
                $g_error .= "Provider not found in db for {$discovery['issuer']} and no registration endpoint";
                return;
            }
            $client_options = get_update_options($_REQUEST);
            $client_info = register_client($discovery['registration_endpoint'], $client_options);
            if(!$client_info) {
                $g_error .= "Unable to register client";
                return;
            }
            $provider = array_merge(
                                     array(
                                            'name' => $discovery['issuer'],
                                            'url' => $discovery['url'],
                                            'issuer' => $discovery['issuer'],
                                            'client_id' => $client_info['client_id'],
                                            'client_id_issued_at' => $client_info['client_id_issued_at'],
                                            'client_secret' => $client_info['client_secret'],
                                            'registration_access_token' => $client_info['registration_access_token'],
                                            'registration_client_uri' => $client_info['registration_client_uri'],
                                            'client_secret_expires_at' => $client_info['client_secret_expires_at']
                                          ),
                                    $client_options
                                   );
            db_save_provider($discovery['issuer'], $provider);
            $provider = array_merge($provider, $client_info);
            $provider = array_merge($provider, $discovery);
        }
        
    } elseif($provider) {
        $db_provider = db_get_provider($provider);
        if(!$db_provider) {
            $g_error .= "Unregistered Identity Provider";
            return;
        }

        $p_info = $db_provider->toArray();
        if($p_info['authorization_endpoint']) {
            $provider = $p_info;
            if(!$provider['client_id'] || !$provider['client_secret']) {
                $client_options = get_update_options($_REQUEST);
                log_debug('update options = %s', print_r($client_options, true));
                $client_info = register_client($provider['registration_endpoint'], $client_options);
                if(!$client_info) {
                    $g_error .= "Unable to register client";
                    return;
                }
                $provider = array_merge(
                                         array(
                                                'client_id' => $client_info['client_id'],
                                                'client_secret' => $client_info['client_secret']
                                              ),
                                        $client_options
                                       );
                db_save_provider($db_provider['name'], $provider);
            }
            if($p_info['name'] == RP_PROTOCOL . 'self-issued.me') {
                $provider['client_id'] = RP_REDIRECT_URI;
                $provider['client_secret'] = '';
            }
        } else {
            $provider_url = $p_info['url'];
            log_info("Provider URL = %s", $provider_url);
            $discovery = webfinger_get_provider_info($p_info['url']);

            if(!check_client_update_options($_REQUEST, $discovery))
                return;

             if(!isset($discovery['registration_endpoint'])) {
                $g_error .= "Provider not found in db for {$discovery['issuer']} and no registration endpoint";
                return;
            }
            $client_options = get_update_options($_REQUEST);
            $client_info = register_client($discovery['registration_endpoint'], $client_options);
            log_debug('update options = %s', print_r($client_options, true));
            if(!$client_info) {
                $g_error .= "Unable to register client";
                return;
            }
            $provider = array_merge(
                                     array(
                                            'name' => $discovery['issuer'],
                                            'url' => $discovery['url'],
                                            'issuer' => $discovery['issuer'],
                                            'client_id' => $client_info['client_id'],
                                            'client_id_issued_at' => $client_info['client_id_issued_at'],
                                            'client_secret' => $client_info['client_secret'],
                                            'registration_access_token' => $client_info['registration_access_token'],
                                            'registration_client_uri' => $client_info['registration_client_uri'],
                                            'client_secret_expires_at' => $client_info['client_secret_expires_at']
                                          ),
                                    $client_options
                                   );
            $db_provider->delete();
            db_save_provider($discovery['issuer'], $provider);
            $provider = array_merge($provider, $client_info);
            $provider = array_merge($provider, $discovery);
        }
    }
    
    $_SESSION['provider'] = $provider;
    log_debug('final provider info %s', print_r($provider, true));
    $state = bin2hex(mcrypt_create_iv(16, MCRYPT_DEV_URANDOM ));
    $nonce = bin2hex(mcrypt_create_iv(16, MCRYPT_DEV_URANDOM ));
    $response_type = '';
    if($_REQUEST['response_type'])
        $response_type = $_REQUEST['response_type'];
    if(!$response_type) {
        if($_REQUEST['response_type1'])
            $response_type = $_REQUEST['response_type1'];
    }
    if(!$response_type) {
        $g_error = 'No response type';
        return;
    }
    $query_params = array(
                            'state' => $state,
                            'redirect_uri' => RP_REDIRECT_URI,
                            'response_type' => $response_type,
                            'client_id' => $provider['client_id'],
                            'nonce' => $nonce
                         );
    $scope_types = array('openid', 'profile', 'email', 'address', 'phone', 'offline_access');
    $scopes = array();
    foreach($scope_types as $scope_type) {
        $param_name = 'scope_' . $scope_type;
        if($_REQUEST[$param_name] == 'on') {
            $scopes[] = $scope_type;
        }
    }
    if(isset($provider['scopes_supported'])) {
        $provider_scopes = $provider['scopes_supported'];
        if(!is_array($provider_scopes))
            $provider_scopes = explode(' ', $provider_scopes);
        log_debug('provider scopes = %s', print_r($provider_scopes, true));
        $diff = array_diff($provider_scopes, $scope_types);
        log_debug('diff = %s', print_r($diff, true));
        if(isset($db_provider) && isset($db_provider['authorization_endpoint']))
            $provider_scopes = $diff;
        else
            $provider_scopes = array();
    }
    else
        $provider_scopes = array();
    $unique_scopes = array_unique(array_merge($scopes, $provider_scopes), SORT_STRING );    
    $query_params['scope'] = implode(' ', $unique_scopes);
    log_debug('scopes = %s', print_r($query_params['scope'], true));

    $code_verifier = base64url_encode(mcrypt_create_iv(32, MCRYPT_DEV_URANDOM));
    $_SESSION['code_verifier'] = $code_verifier;
    $code_challenge = base64url_encode(hash('sha256', $code_verifier, true));
    $query_params['code_challenge_method'] = 'S256';
    $query_params['code_challenge'] = $code_challenge;
    log_debug("code verifier : %s challenge : %s method : %s", $code_verifier, $code_challenge, $query_params['code_challenge_method']);

    if($_REQUEST['response_mode'])
        $query_params['response_mode'] = $_REQUEST['response_mode'];

    if($_REQUEST['page'])
        $query_params['page'] = $_REQUEST['page'];
    $prompt_types = array('none', 'login', 'consent', 'select_account');
    $prompt = array();
    foreach($prompt_types as $prompt_type) {
        $param_name = 'prompt_' . $prompt_type;
        if($_REQUEST[$param_name] == 'on') {
            $prompt[] = $prompt_type;
        }
    }
    if(count($prompt))
        $query_params['prompt'] = implode(' ', $prompt);
    
    if($_REQUEST['id_token'])
        $query_params['id_token_hint'] = $_REQUEST['id_token'];

    if($_REQUEST['login_hint'])
        $query_params['login_hint'] = $_REQUEST['login_hint'];

    $custom_params = array();
    if($_REQUEST['request_option']) {
//        $custom_query = array();
        if(strstr($_REQUEST['request_option'], 'Custom') !== false) {
            switch($_REQUEST['request_option']) {
                case 'Custom 19' :
                    $custom_params['claims'] =  array(
                                                            'userinfo' => array(
                                                                                'name' => array('essential' => true)
                                                                             )
                                                       );
                break;
                
                case 'Custom 20' :
                    $custom_params['claims'] =  array(
                                                            'userinfo' => array(
                                                                                'email' => NULL,
                                                                                'picture' => NULL
                                                                             )
                                                       );
                break;

                case 'Custom 21' :
                    $custom_params['claims'] =  array(
                                                            'userinfo' => array(
                                                                                'name' => array('essential' => true),
                                                                                'email' => NULL,
                                                                                'picture' => NULL
                                                                              ),
                                                       );
                break;
                
                case 'Custom 22' :
                    $custom_params['claims'] =  array(
                                                            'id_token' => array(
                                                                                'auth_time' => array('essential' => true)
                                                                              )
                                                       );
                break;

                case 'Custom 23' :
                    $custom_params['claims'] =  array(
                                                            'id_token' => array(
                                                                                'acr' => array('values' => array('0', '1', '2'),
                                                                                               'essential' => true
                                                                                              )
                                                                              )
                                                       );
                break;

                case 'Custom 24' :
                    $custom_params['claims'] =  array(
                                                            'id_token' => array(
                                                                                'acr' => array( 'values' => array('0', '1', '2')
                                                                                              )
                                                                              )
                                                       );
                break;

                case 'Custom 25a' :
                    $query_params['max_age'] =  1;
                break;

                case 'Custom 25b' :
                    $query_params['max_age'] =  10;
                break;
                
                case 'Custom Dist' :
                    $custom_params['claims'] =  array(
                                                            'userinfo' => array(
                                                                                'name' => array('essential' => true),
                                                                                'email' => NULL,
                                                                                'picture' => NULL,
                                                                                'undergrad_school' => array('essential' => true),
                                                                                'graduate_school' => array('essential' => true),
                                                                                'undergrad_degrees' => array('essential' => true),
                                                                                'graduate_degrees' => array('essential' => true)
                                                                             )
                                                       );
                    break;

                case 'Custom Req 1' :
                    $query_params['max_age'] =  1*60;
                    $custom_params['claims'] =  array(
                                                            'userinfo' => array(
                                                                                'name' => array('essential' => true),
                                                                                'given_name' => array('essential' => true),
                                                                                'family_name' => array('essential' => true),
                                                                                'middle_name' => array('essential' => true),
        //                                                                        'email' => array('essential' => true),
        //                                                                        'verified' => array('essential' => true),
        //                                                                        'gender' => array('essential' => true),
        //                                                                        'birthday' => array('essential' => true),
        //                                                                        'phone_number' => array('essential' => true),
                                                                                'address' => array('essential' => true),
                                                                                'nickname' => NULL,
                                                                                'profile' => NULL,
                                                                                'given_name#ja-Kana-JP' => NULL,
                                                                                'given_name#ja_Hani-JP' => NULL,
        //                                                                        'picture' => NULL,
        //                                                                        'website' => NULL,
        //                                                                        'high_school' => array('essential' => true),
        //                                                                        'elementary_school' => NULL,
        //                                                                        'undergrad_school' => array('essential' => true),
        //                                                                        'graduate_school' => array('essential' => true),
        //                                                                        'undergrad_school#ja-Kana-JP' => array('essential' => true),
        //                                                                        'graduate_school#ja-Kana-JP' => array('essential' => true),
        //                                                                        'undergrad_school#ja_Hani-JP' => array('essential' => true),
        //                                                                        'graduate_school#ja_Hani-JP' => array('essential' => true),
        //                                                                        'middle_school' => NULL
                                                                              ),
                                                            'id_token' => array(
                                                                                'given_name' => array('essential' => true),
                                                                                'family_name' => array('essential' => true),
                                                                                'email' => array('essential' => true),
                                                                                'gender' => array('essential' => true),
                                                                                'address' => array('essential' => true),
                                                                                'auth_time' => array('essential' => true),
                                                                              )
                                                       );
                    break;

                case 'Custom Req 2' :
                    $query_params['max_age'] =  1*60;
                    $custom_params['claims'] =  array(
                                                            'userinfo' => array(
                                                                                'name' => array('essential' => true),
                                                                              ),
                                                            'id_token' => array(
                                                                                'auth_time' => array('essential' => true),
                                                                              ),
                                                       );
                    break;
                    
                default:
                    break;
            }
        }

    }

    $request_method = $_REQUEST['request_method'];    
    if($_REQUEST['request_option']) {
        if($request_method == 'GET') {
            if(count($custom_params)) {
                $query_params['claims'] = json_encode($custom_params['claims']);
            }
        } else {
            if(strstr($request_method, 'Request File') !== false) {
                $fileid = bin2hex(mcrypt_create_iv(32, MCRYPT_DEV_URANDOM ));
                // $query_params['request_uri'] = RP_INDEX_PAGE . "/reqfile?fileid={$fileid}";
            } else
                $fileid = NULL;

            $sig_param = Array('alg' => 'none');
            if($_REQUEST['request_object_signing_alg'])
                $sig_param['alg'] = $_REQUEST['request_object_signing_alg'];
            if(substr($sig_param['alg'], 0, 2) == 'HS') {
                $sig_key = $provider['client_secret'];
            } elseif(substr($sig_param['alg'], 0, 2) == 'RS') {
                $sig_param['jku'] = RP_JWK_URL;
                $sig_param['kid'] = RP_SIG_KID;
                $sig_key = array('key_file' => RP_SIG_PKEY, 'password' => RP_SIG_PKEY_PASSPHRASE);
            }
            log_debug("Request Object Using Sig Alg %s", $sig_param['alg']);
            $request_jwt = jwt_sign(array_merge(array_diff_key($query_params, array('id_token' => 0)), $custom_params), $sig_param, $sig_key);
            if(!$request_jwt) {
                $g_error .= 'Unable to sign request object';
                return;
            }
            if($_REQUEST['request_object_encrypted_response_alg'] && $_REQUEST['request_object_encrypted_response_enc']) {
                $supported_cek_algs = array('RSA1_5', 'RSA-OAEP');
                $supported_plaintext_algs = array('A128GCM', 'A256GCM', 'A128CBC-HS256', 'A256CBC-HS512');
                if(!in_array($_REQUEST['request_object_encrypted_response_alg'], $supported_cek_algs)) {
                    $g_error .= "Unsupported Request Object CEK Alg";
                    return;
                }
                if(!in_array($_REQUEST['request_object_encrypted_response_enc'], $supported_plaintext_algs)) {
                    $g_error .= "Unsupported Request Object Plaintext Alg";
                    return;
                }

                $jwk_uri = '';
                $encryption_keys = NULL;
                if($provider['jwks_uri']) {
                    $jwk = get_url($provider['jwks_uri']);
                    if($jwk) {
                        $jwk_uri = $provider['jwks_uri'];
                        $encryption_keys = jwk_get_keys($jwk, 'RSA', 'enc', NULL);
                        if(!$encryption_keys || !count($encryption_keys))
                            $encryption_keys = NULL;
                    }
                }
                if(!$encryption_keys) {
                    $g_error .= 'No JWK key for encryption';
                    return NULL;
                }
                $header_params = array('jku' => $jwk_uri);
                if(isset($encryption_keys[0]['kid']))
                    $header_params['kid'] = $encryption_keys[0]['kid'];

                $encrypted_jwt = jwt_encrypt2($request_jwt, $encryption_keys[0], false, NULL, $header_params, NULL, $_REQUEST['request_object_encrypted_response_alg'], $_REQUEST['request_object_encrypted_response_enc'], false);
                if(!$encrypted_jwt) {
                    $g_error .= "Unable to encrypt request object.";
                    return;
                } else
                    $request_jwt = $encrypted_jwt;
            } else {
//            $custom_query['request'] = $request_jwt;
            }

            // if(isset($query_params['request_uri'])) { // save file to db
            if(isset($fileid)) { // save file to db
                $query_params['request_uri'] = RP_INDEX_PAGE . "/reqfile?fileid={$fileid}";
                $reqfile = array(
                    'type' => $encrypted_jwt ? 1 : 0,
                    'request' => json_encode(array_merge($query_params, $custom_params)),
                    'jwt' => $request_jwt
                );
                log_debug('query_params = %s custom = %s', print_r($query_params, true), print_r($custom_params, true));
                db_save_request_file($fileid, $reqfile);
            } else {
                $query_params['request'] = $request_jwt;
            }
        }
    }
    $url = $provider['authorization_endpoint'] . '?' . http_build_query($query_params);
    log_info("redirect to %s", $url);
    header("Location: $url");
    exit;
}

function make_post_data($pairs) {
    $first = true;
    $result = '';
    foreach($pairs as $key => $value) {
        $result .= ($first ? '' : '&') . urlencode($key) . '=' . urlencode($value);
        $first = false;
    }
    return $result;
}

function get_url($url) {
    global $g_error, $g_headers;
    
    $ch = curl_init();
    $g_headers[$ch] = '';
    $curl_options = array(
                             CURLOPT_URL => $url ,
                             // CURLOPT_HEADER => true,
                             CURLOPT_HEADERFUNCTION => 'saveHeaders',
                             CURLINFO_HEADER_OUT => true,
                             CURLOPT_SSL_VERIFYPEER => false,
                             CURLOPT_SSL_VERIFYHOST => 0,
                             CURLOPT_RETURNTRANSFER => 1
                         );
    curl_setopt_array($ch, $curl_options);
    $data_responseText = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE );
    $data_content_type = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    $req_out = curl_getinfo($ch, CURLINFO_HEADER_OUT);
    $response_headers = $g_headers[$ch];
    unset($g_headers[$ch]);
    curl_close($ch);

    log_debug("GET {$url} - {$req_out}\n{$response_headers}\n{$data_responseText}");
    if($code != 200) {
        if($data_responseText && substr($url, 0, 7) == 'file://')
            return $data_responseText;
        $g_error .= "Unable to fetch URL $url status = {$code}.\n{$req_out}\n{$response_headers}\n{$data_responseText}";
        log_error($g_error);
        return NULL;
    } else {
        log_debug("GOT %s", $data_responseText);
        return $data_responseText;
    }
}



function get_option_html($name, $options, $select) {
    $html = '';
    foreach($options as $option) {
        if($option == $select)
            $select_option = 'selected';
        else
            $select_option = '';
        $html .= "    <option {$select_option}>$option</option>\n";
    }
    return "\n<select size='1' name='{$name}'>\n" . $html . '</select>';
}

function get_checkboxes_html($name, $options) {
    $html = '';
    foreach($options as $option => $option_info) {
        list($default, $display) = $option_info;
        if(!$display)
            $display = $option;
        $option_name = $name . '_' . $option;
        if(array_key_exists($option_name, $_SESSION)) {
            if($_SESSION[$option_name] == 'on')
                $checked = 'checked';
            else
                $checked = '';
        } else {
            if($default)
                $checked = 'checked';
            else
                $checked = '';            
        }
        $html .= "    <input type='checkbox' name='{$option_name}' {$checked}>{$display} &nbsp;&nbsp;&nbsp;\n";
    }
    return $html;
}

function get_text_html($name) {
    return "<input type='text' name='{$name}'>\n";
}



function generate_tab_html() {
$request_method_types = array('GET', 'Request Object', 'Request File');
$request_method_options = get_option_html('request_method', $request_method_types, $_SESSION['request_method']);

$request_options_types = array('', 'Custom 19', 'Custom 20', 'Custom 21', 'Custom 22', 
                         'Custom 23', 'Custom 24', 'Custom 25a', 'Custom 25b', 'Custom Req 1', 'Custom Req 2', 'Custom Dist' );
$request_options_type_options = get_option_html('request_option', $request_options_types, $_SESSION['request_option']);



$response_types = array('code', 'token', 'code id_token', 'token id_token', 'id_token', 'code token id_token');
if($_SESSION['debug'])
    array_unshift($response_types, '');
$response_type_options = get_option_html('response_type', $response_types, $_SESSION['response_type'] ? $_SESSION['response_type'] : 'code' );

$response_modes = array('', 'query', 'fragment', 'form_post');
$response_mode_options = get_option_html('response_mode', $response_modes, $_SESSION['response_mode'] ? $_SESSION['response_mode'] : '');

    $page_types = array('', 'page', 'popup', 'touch', 'wap', 'embedded');
$page_options = get_option_html('page', $page_types, $_SESSION['page']);

$prompt_types = array(
                        'none' => array(0, NULL), 
                        'login' => array(0, NULL), 
                        'consent' => array(0, NULL), 
                        'select_account' => array(0, NULL)
                     );
$prompt_options = get_checkboxes_html('prompt', $prompt_types);

$scope_types = array(
                        'openid' => array(1, NULL), 
                        'profile' => array(1, NULL),
                        'email' => array(1, NULL),
                        'address' => array(1, NULL),
                        'phone' => array(1, NULL),
                        'offline_access' => array(0, NULL));
$scope_options = get_checkboxes_html('scope', $scope_types);


$bearer_token_methods = array('bearer', 'post', 'get');
$bearer_token_options = get_option_html('bearer', $bearer_token_methods, $_SESSION['bearer']);

$sig_algs = array('', 'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512');
$enc_cek_algs = array('', 'RSA1_5', 'RSA-OAEP');
$enc_plaintext_algs = array('', 'A128GCM', 'A256GCM', 'A128CBC-HS256', 'A256CBC-HS512');


$token_endpoint_auth_methods = array('client_secret_post', 'client_secret_basic', 'client_secret_jwt', 'private_key_jwt');
$token_endpoint_auth_method_options = get_option_html('token_endpoint_auth_method', $token_endpoint_auth_methods, $_SESSION['token_endpoint_auth_method']);

$token_endpoint_auth_signing_alg_types = array('', 'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512');
$token_endpoint_auth_signing_alg_type_options = get_option_html('token_endpoint_auth_signing_alg', $token_endpoint_auth_signing_alg_types, $_SESSION['token_endpoint_auth_signing_alg']);

$subject_types = array('public', 'pairwise');
$subject_type_options = get_option_html('subject_type', $subject_types, $_SESSION['subject_type']);

$request_object_signing_alg_options = get_option_html('request_object_signing_alg', $sig_algs, $_SESSION['request_object_signing_alg']);
$userinfo_signed_response_alg_options = get_option_html('userinfo_signed_response_alg', $sig_algs, $_SESSION['userinfo_signed_response_alg']);
$id_token_signed_response_alg_options = get_option_html('id_token_signed_response_alg', $sig_algs, $_SESSION['id_token_signed_response_alg']);
$require_auth_time_options = get_option_html('require_auth_time', array('', 'true', 'false'), $_SESSION['require_auth_time']);

if($_SESSION['enc'] || true) {
    $request_object_encrypted_response_alg_options = get_option_html('request_object_encrypted_response_alg', $enc_cek_algs, $_SESSION['request_object_encrypted_response_alg']);
    $request_object_encrypted_response_enc_options = get_option_html('request_object_encrypted_response_enc', $enc_plaintext_algs, $_SESSION['request_object_encrypted_response_enc']);

    $userinfo_encrypted_response_alg_options = get_option_html('userinfo_encrypted_response_alg', $enc_cek_algs, $_SESSION['userinfo_encrypted_response_alg']);
    $userinfo_encrypted_response_enc_options = get_option_html('userinfo_encrypted_response_enc', $enc_plaintext_algs, $_SESSION['userinfo_encrypted_response_enc']);
    
    $id_token_encrypted_response_alg_options = get_option_html('id_token_encrypted_response_alg', $enc_cek_algs, $_SESSION['id_token_encrypted_response_alg']);
    $id_token_encrypted_response_enc_options = get_option_html('id_token_encrypted_response_enc', $enc_plaintext_algs, $_SESSION['id_token_encrypted_response_enc']);

$req_obj_enc_options = <<<EOF
                    <tr><td colspan='3'><p/></td></tr>
                    <tr><td>Request Object Encryption CEK Alg</td><td>&nbsp;&nbsp;</td>
                        <td>$request_object_encrypted_response_alg_options</td>
                    </tr>
                    <tr><td colspan='3'><p/></td></tr>
                    <tr><td>Request Object Encryption Plaintext Alg</td><td>&nbsp;&nbsp;</td>
                        <td>$request_object_encrypted_response_enc_options</td>
                    </tr>
EOF;

$userinfo_enc_options = <<<EOF
                    <tr><td colspan='3'><p/></td></tr>
                    <tr><td>UserInfo Encryption CEK Alg</td><td>&nbsp;&nbsp;</td>
                        <td>$userinfo_encrypted_response_alg_options</td>
                    </tr>
                    <tr><td colspan='3'><p/></td></tr>
                    <tr><td>UserInfo Encryption Plaintext Alg</td><td>&nbsp;&nbsp;</td>
                        <td>$userinfo_encrypted_response_enc_options</td>
                    </tr>
EOF;

$id_token_enc_options = <<<EOF
                    <tr><td colspan='3'><p/></td></tr>
                    <tr><td>ID Token Encryption CEK Alg</td><td>&nbsp;&nbsp;</td>
                        <td>$id_token_encrypted_response_alg_options</td>
                    </tr>
                    <tr><td colspan='3'><p/></td></tr>
                    <tr><td>ID Token Encryption Plaintext Alg</td><td>&nbsp;&nbsp;</td>
                        <td>$id_token_encrypted_response_enc_options</td>
                    </tr>
EOF;

} else {
    $req_obj_enc_options = $userinfo_enc_options = $id_token_enc_options = '';
}

if($_SESSION['debug']) {
$response_type_input = <<<EOF
                    <tr><td colspan='3'><p/></td></tr>
                    <tr><td>Response Type Text</td><td>&nbsp;&nbsp;</td>
                        <td><input type='text' name='response_type1'></td>
                    </tr>
EOF;
} else
    $response_type_input = '';

$id_token_input = <<<EOF
                    <tr><td colspan='3'><p/></td></tr>
                    <tr><td>ID Token</td><td>&nbsp;&nbsp;</td>
                        <td><input type='text' name='id_token'></td>
                    </tr>
EOF;

$tabs = <<<EOF
    <div id="outer-tabs" style='width:800'>
        <ul>
            <li><a href='#outer-tabs-1'>Request Options</a></li>
            <li><a href='#outer-tabs-2'>Response Options</a></li>
        </ul>
          <div id='outer-tabs-1'>
                <table cellspacing='0' cellpadding='0'>
                    <tr><td>Request Method</td><td>&nbsp;&nbsp;</td>
                        <td>$request_method_options</td>
                    </tr>
                    <tr><td colspan='3'><p/></td></tr>
                    <tr><td>Request Options</td><td>&nbsp;&nbsp;</td>
                        <td>$request_options_type_options</td>
                    </tr>
                    <tr><td colspan='3'><p/></td></tr>
                    <tr><td>Response Type</td><td>&nbsp;&nbsp;</td>
                        <td>$response_type_options</td>
                    </tr>
                    $response_type_input
                    $id_token_input
                    <tr><td colspan='3'><p/></td></tr>
                    <tr><td>Scope</td><td>&nbsp;&nbsp;</td>
                        <td>$scope_options</td>
                    </tr>
                    <tr><td colspan='3'><p/></td></tr>
                    <tr><td>Response Mode</td><td>&nbsp;&nbsp;</td>
                        <td>$response_mode_options</td>
                    </tr>
                    <tr><td colspan='3'><p/></td></tr>
                    <tr><td>Prompt</td><td>&nbsp;&nbsp;</td>
                        <td>$prompt_options</td>
                    </tr>
                    <tr><td colspan='3'><p/></td></tr>
                    <tr><td>Display</td><td>&nbsp;&nbsp;</td>
                        <td>$page_options</td>
                    </tr>
                    <tr><td colspan='3'><p/></td></tr>
                    <tr><td>Bearer Token Transmission Method</td><td>&nbsp;&nbsp;</td>
                        <td>$bearer_token_options</td>
                    </tr>
                    <tr><td colspan='3'><p/></td></tr>
                    <tr><td>Token Endpoint Authentication Type</td><td>&nbsp;&nbsp;</td>
                        <td>$token_endpoint_auth_method_options</td>
                    </tr>
                    <tr><td colspan='3'><p/></td></tr>
                    <tr><td>Token Endpoint Authentication Sig Alg</td><td>&nbsp;&nbsp;</td>
                        <td>$token_endpoint_auth_signing_alg_type_options</td>
                    </tr>
                    <tr><td colspan='3'><p/></td></tr>
                    <tr><td>Request Object Sig Alg</td><td>&nbsp;&nbsp;</td>
                        <td>$request_object_signing_alg_options</td>
                    </tr>
                    $req_obj_enc_options
                    <tr><td colspan='3'><p/></td></tr>
                    <tr><td>Default Max Age</td><td>&nbsp;&nbsp;</td>
                        <td><input type='text' name='default_max_age' value='{$_SESSION['default_max_age']}'></td>
                    </tr>
                    <tr><td colspan='3'><p/></td></tr>
                    <tr><td>Require Auth Time</td><td>&nbsp;&nbsp;</td>
                        <td>$require_auth_time_options</td>
                    </tr>
                    <tr><td colspan='3'><p/></td></tr>
                    <tr><td>Default ACR</td><td>&nbsp;&nbsp;</td>
                        <td><input type='text' name='default_acr_values' value='{$_SESSION['default_acr_values']}'></td>
                    </tr>
                    <tr><td colspan='3'><p/></td></tr>
                    <tr><td>Login Hint</td><td>&nbsp;&nbsp;</td>
                        <td><input type='text' name='login_hint'></td>
                    </tr>
                </table>


          </div>

          <div id='outer-tabs-2'>
                <table cellspacing='0' cellpadding='0'>
                    <tr><td>User ID Type</td><td>&nbsp;&nbsp;</td>
                        <td>$subject_type_options</td>
                    </tr>
                    <tr><td colspan='3'><p/></td></tr>

                    <tr><td>UserInfo Sig Alg</td><td>&nbsp;&nbsp;</td>
                        <td>$userinfo_signed_response_alg_options</td>
                    </tr>
                    $userinfo_enc_options
                    <tr><td colspan='3'><p/></td></tr>
                    
                    <tr><td>ID Token Sig Alg</td><td>&nbsp;&nbsp;</td>
                        <td>$id_token_signed_response_alg_options</td>
                    </tr>
                    $id_token_enc_options
                </table>
          </div>



    </div>

EOF;

  return $tabs;
}


function handle_reqfile() {
    $fileid = $_REQUEST['fileid'];
    if($fileid) {
        $reqfile = db_get_request_file($fileid);
        if($reqfile) {
            header("Content-Type: application/jwt");
            echo $reqfile['jwt'];
        } else {
            header("HTTP/1.0 404 Not Found");
            log_error("fileid %s not found", $fileid);
        }
    }
    exit;
}


function double_quote_string($str) {
    return sprintf("\"%s\"", $str);
}

function handle_sector_id() {
    header("Content-Type: application/json");

    $redirect_uris = implode(",\n", array_map('double_quote_string', array(RP_REDIRECT_URI, RP_AUTHCHECK_REDIRECT_URI)));
    $redirect_uris = <<<EOF
[
$redirect_uris
]
EOF;

    echo $redirect_uris;
}


function curl_fetch_url($url, $headers = NULL, $c_options = NULL, $is_post = false, $post_data = NULL ) {
    global $g_headers;

    $ch = curl_init();
    $g_headers[$ch] = '';
    $curl_options = array(
        CURLOPT_URL => $url ,
        CURLOPT_HEADERFUNCTION => 'saveHeaders',
        CURLINFO_HEADER_OUT => true,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_RETURNTRANSFER => 1
    );
    if(isset($c_options) && is_array($c_options)) {
        foreach($c_options as $key => $value) {
            $curl_options[$key] = $value;
        }
    }
    if(isset($headers) && is_array($headers))
        $curl_options[CURLOPT_HTTPHEADER] = $headers;

    if($is_post) {
        $curl_options[CURLOPT_POST] = true;
        if(isset($post_data) && is_array($post_data))
            $curl_options[CURLOPT_POSTFIELDS] = make_post_data($post_data);
    }
    else
        $curl_options[CURLOPT_HTTPGET] = true;

    curl_setopt_array($ch, $curl_options);
    $data_responseText = curl_exec($ch);
    $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE );
    $data_content_type = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    $req_out = curl_getinfo($ch, CURLINFO_HEADER_OUT);
    $response_headers = $g_headers[$ch];
    unset($g_headers[$ch]);
    curl_close($ch);
    log_debug("curl_fetch_url ==> %s\n%s\n%s", $req_out, $response_headers, $data_responseText);
    return array($status_code, $data_content_type, $req_out, $response_headers, $data_responseText);
}


if(isset($_SESSION['session_state']) && isset($_SESSION['provider']['check_session_iframe'])) {
    $op_frame_url = $_SESSION['provider']['check_session_iframe'];
?>
    <iframe id='opFrame' name='opFrame' width='0' height='0' src='<?php echo $op_frame_url ?>' style='visibility:hidden'>
    </iframe>

    <iframe id='rpFrame' name='rpFrame' width='0' height='0' src='<?php echo RP_PROTOCOL . RP_SERVER_NAME . RP_PORT . RP_PATH?>/rpframe.php' style='visibility:hidden' >
    </iframe>
    <!--
    <input type='button' value='Start' onclick="startRPTimers()"><br/>
    <input type='button' value='Stop' onclick="stopRPTimers()"><br/>
    -->

<?php
} else {
    log_debug('session = %s', print_r($_SESSION, true));
}
?>


</body>
</html>
