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

/* This is only to force HTTPS when no reverse proxying.
if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] != 1) { // force HTTPS
    header('Location: https://' . $_SERVER['SERVER_NAME'] . $_SERVER['REQUEST_URI']);
    exit;
}
*/
?>
<html>
<head>
<title>reTHINK IdP Services</title>
</head>
<body style="background-color:yellow">
<h1>
<a href=https://rethink-project.eu/><img src="img/rethink.png"/></a>Identity Provider</h1>
<p>This server is based on the <a href=http://nat.sakimura.org/>Nat Sakimura</a> PhPOIDC server*</p>
<table border="0">
<tr><td>To have a quick usage demo of client usage** :</td><td> <a href="demo/index.php">Client demo service</a></td></tr>
<tr><td>To have a detailed usage demo of client usage :</td><td> <a href="phpRp/index.php">Complete rp demo</a></td></tr>
<tr><td>To access OIDC APIs : </td><td><a href="phpOp/index.php">Auth server</a></td></tr>
<tr><td>To add a new client application : </td><td><a href="phpOp/register.php">Client registration UI</a></td></tr>
</table>
<br><br>
<font size=2>* <a href=https://bitbucket.org/PEOFIAMP/phpoidc>Source<a></font>
<font size=2>** Authentication using the Authorization Code Flow</font>
</body>
</html>
