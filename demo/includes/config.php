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
date_default_timezone_set("Europe/Paris");

/**
 * These are the database login details
 */

$wgDBserver         = $_ENV['OPENSHIFT_MYSQL_DB_HOST'];
$wgDBport 			= $_ENV['OPENSHIFT_MYSQL_DB_PORT'];
$wgDBname           = $_ENV['OPENSHIFT_APP_NAME'];
$wgDBuser           = $_ENV['OPENSHIFT_MYSQL_DB_USERNAME'];
$wgDBpassword       = $_ENV['OPENSHIFT_MYSQL_DB_PASSWORD'];

define('HOST', $wgDBserver);     // The host you want to connect to.
define('USER', $wgDBuser);    // The database username.
define('PASSWORD', $wgDBpassword);    // The database password.
define('DATABASE', 'demo');    // The database name.

define('CAN_REGISTER', 'any');
define('DEFAULT_ROLE', 'member');
define('SECURE', 'false');

/*
* Specifies the SP's PATH
* 
*/
define("SP_PATH", '/' . basename(dirname($_SERVER['SCRIPT_FILENAME'])));

$SP_URL="https://oidc-ns.kermit.orange-labs.fr/demo";
$IDP_URL="https://oidc-ns.kermit.orange-labs.fr/phpOp/index.php";

$REDIRECT_URI=$SP_URL."/demoback.php";

$CLIENT_ID="demo";
$CLIENT_SECRET="spsecret";

$RESPONSE_TYPE="code";
$RESPONSE_TYPE_SIGNIN="id_token";
$SCOPE="profile openid email";
$SCOPE_LOGIN="openid";

?>
