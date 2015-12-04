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
header('Content-Type: text/html; charset=utf-8');

$session_path = session_save_path() . RP_PATH;
if(!file_exists($session_path))
    mkdir($session_path);
session_save_path($session_path);
session_start();

$session_state = $_SESSION['session_state'];
$id_token = $_SESSION['id_token'];
if(!$session_state ) {
    log_error('no session_state');
    exit;
}
if(!isset($_SESSION['provider']['client_id'])) {
    log_error('no client_id');
    exit;
} else
    $client_id = $_SESSION['provider']['client_id'];

if(!isset($_SESSION['provider']['check_session_iframe'])) {
    log_error('no check session iframe');
    exit;
}

$url_parts = parse_url($_SESSION['provider']['check_session_iframe']);
$issuer_origin = sprintf("%s://%s%s", $url_parts['scheme'], $url_parts['host'], isset($url_parts['port']) ? ':' . $url_parts['port'] : '');
$client_origin = RP_PROTOCOL . RP_SERVER_NAME . RP_PORT;


?>

<html>
<head>
<meta http-equiv="content-type" content="text/html;charset=UTF-8" />
<title>RP Frame</title>
<script src="https://crypto-js.googlecode.com/svn/tags/3.0.2/build/rollups/sha256.js"></script>
<script src='/<?php echo RP_PATH ?>/js/base64.js'></script>
<script type='text/javascript'>//<![CDATA[

var client_id, rp_origin, opss, salt, timer_id, op_target_origin, current_userid;

client_id = '<?php echo $client_id ?>';
rp_origin = '<?php echo $client_origin ?>';
op_target_origin = '<?php echo $issuer_origin ?>';
current_userid = '<?php echo $user_id ?>';

salt = CryptoJS.lib.WordArray.random(128/8);
console.log('salt = ' + salt);
timer_id = null;


var state = "unchanged";

var mes = "<?php echo $client_id . ' ' . $session_state?>";
console.log('mes = ' + mes);


function update_mes(new_ops)
{
    salt = CryptoJS.lib.WordArray.random(128/8);
    mes = CryptoJS.SHA256(client_id + rp_origin + new_ops + salt) + "." + salt;
    console.log('mes = ' + mes);
}

function check_session()
{
  console.log('check_session');
  var targetOrigin = op_target_origin;
  console.log('session_state = <?php echo $session_state ?>');
  var opFrame = window.parent.document.getElementById("opFrame");
  if(opFrame) {
      var win = opFrame.contentWindow;
      if(win) {
        win.postMessage( mes, targetOrigin);
        console.log('client_id : ' + client_id + ' origin : ' + rp_origin + ' salt : ' + salt);
    }
  } else {
    console.log('no opFrame');
  }

}
function setTimer()
{
  console.log('setTimer');
  check_session();
  clearTimer();
  timer_id = setInterval("check_session()",3*1000);
}

function clearTimer()
{
  if(timer_id) {
      window.clearInterval(timer_id);
      timer_id = null;
      console.log('Cleared timer ID');
  }
}

window.addEventListener("message", receiveMessage, false);

function receiveMessage(e)
{
  var targetOrigin  = op_target_origin;
  if (e.origin !== targetOrigin ){
    console.log(e.origin + ' !== ' + targetOrigin);
    return;
  }
  state = e.data;
  console.log('rpframe received ' + state);
  if(state == 'changed') {
    clearTimer();
    alert("session state changed");
    perform_authcheck();
  }
}

console.log('testing');
setTimer();
console.log('called setTimer');

function perform_authcheck() {
    var frame = document.getElementById('authcheckframe');
    if(frame) {
        frame.src = '<?php echo RP_URL ?>/authcheck.php';
    }
}


//]]></script>
</head>
<body>
    
    <iframe id='authcheckframe' name='authcheckframe' width='0' height='0' style='visibility:hidden' >
    </iframe>
</body>
</html>
