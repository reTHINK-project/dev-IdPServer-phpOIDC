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

//include_once("abconstants.php");
//include_once("libjsoncrypto.php");
//include_once('libdb.php');
//include_once('logging.php');
//include_once('OidcException.php');
//include_once('apache_header.php');
//include_once('custom.php');

//error_reporting(E_ERROR | E_WARNING | E_PARSE);

define("DEBUG",0);

//define("OP_ENDPoINT", OP_INDEX_PAGE);


define("TOKEN_TYPE_AUTH_CODE", 0);
define("TOKEN_TYPE_ACCESS",    1);
define("TOKEN_TYPE_REFRESH",   2);


header('Content-Type: text/html; charset=utf8');

  echo '
  <html>
  <head><title>TOTO OP</title>
  <meta name="viewport" content="width=320">
  </head>
  <body style="background-color:#FFEEEE;">
  <h1> OP Config</h1>
  </body>
  </html>';

?>

