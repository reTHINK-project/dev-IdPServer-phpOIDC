<?php

/**
 * Show Login form.
 * @return String HTML Login form.
 */
function custom_loginform($display_name = '', $user_id = '', $client = null, $oplogin=false){
		
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
  <img src="../../../img/rethink.png" />
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

?>