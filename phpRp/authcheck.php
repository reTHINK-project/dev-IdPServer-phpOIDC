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

header('Content-Type: text/html; charset=utf-8');

$session_path = session_save_path() . RP_PATH;
if(!file_exists($session_path))
    mkdir($session_path);
session_save_path($session_path);
session_start();


if($_SERVER['PATH_INFO'] == '/authcheckcb') {
    handle_authcheck_cb();
} else {
    handle_authcheck();
    exit;
}


function handle_authcheck() {
    if($_SESSION['provider'] && $_SESSION['provider']['authorization_endpoint'] && $_SESSION['id_token']) {
        $client_id = $_SESSION['provider']['client_id'];
        $state = bin2hex(mcrypt_create_iv(16, MCRYPT_DEV_URANDOM ));
        $nonce = bin2hex(mcrypt_create_iv(16, MCRYPT_DEV_URANDOM ));
        $response_type = 'id_token';
        $scope = 'openid';
        $query_params = array(
                                'client_id' => $client_id,
                                'scope' => $scope,
                                'state' => $state,
                                'redirect_uri' => RP_AUTHCHECK_REDIRECT_URI,
                                'response_type' => $response_type,
                                'nonce' => $nonce, 
                                'prompt' => 'none',
                                'id_token_hint' => $_SESSION['id_token']
                             );
        $url =  $_SESSION['provider']['authorization_endpoint'] . '?' . http_build_query($query_params);
        header("Location: $url");
    }
}


function handle_authcheck_cb() {
    
}




?>

<html>
<head>
<meta http-equiv="content-type" content="text/html;charset=UTF-8" />
<title>RP AuthCheck</title>

<script src='<? echo RP_PATH ?>/js/base64.js'></script>

<script type='text/javascript'>//<![CDATA[
var id_token, state, error, error_description;

console.log('authcheck script at ' + window.location.href);

var hash = window.location.href.indexOf('#');
var query = window.location.href.indexOf('?');
if(query != -1) {
    query = window.location.href.substring(query + 1);
    if(query) {
        var params = query.split('&');
       
        for(var i in params) {
            var parts = params[i].split('=');
            var k, v;
            k = parts[0].toLowerCase();
            v = parts[1];
            switch(k) {
                case 'error' :
                    error = v;
                    break;
                case 'error_description' :
                    error_description = v;
                    break;
            }
        }
        if(error) {
            console.log('got error : ' + error + ' desc : ' + error_description);
            
            if(error == 'interaction_required')
                alert('User is not logged in. Perform logoout action.\nError : ' + error + '\nDesc : ' + error_description);
            else
                alert('Error : ' + error + ' Desc : ' + error_description);
            error = null;
            error_description = null;
        }
    }
}


if(hash != -1) {
console.log('got hash');
    hash = window.location.href.substring(hash + 1);
    if(hash) {
        var id_token, state;
        var fragments = hash.split('&');
       
        for(var i in fragments) {
            var parts = fragments[i].split('=');
            var k, v;
            k = parts[0].toLowerCase();
            v = parts[1];
            switch(k) {
                case 'id_token' :
                    id_token = v;
                    break;
                case 'state' :
                    state = v;
                    break;
                case 'error' :
                    error = v;
                    break;
                    
                case 'error_description' :
                    error_description = v;
                    break;
            }
        }
        if(error) {
            console.log('got error : ' + error + ' desc : ' + error_description);
            if(error == 'interaction_required')
                alert('User is not logged in. Perform logoout action.\nError : ' + error + '\nDesc : ' + error_description);
            else
                alert('Error : ' + error + ' Desc : ' + error_description);
        } else {
            if(id_token) {
                var jws_parts = id_token.split('.');
                var tok = JSON.parse(base64.base64_url_decode(jws_parts[1]));
                console.log('aud = ' + tok['aud'] + ' iss = ' + tok['iss'] + ' ops = ' + tok['ops'] + ' user_id = ' + tok['user_id']);
                if(window.parent.current_userid == tok['user_id']) {
                    alert('User session changed but userid is the same.');
                    window.parent.update_mes(tok['ops']);
                    window.parent.setTimer();
                } else {
                    alert('User session changed. Perform logout action.');
                }
            }
        }
    }
}





//]]></script>
</head>
<body>
</body>
</html>
