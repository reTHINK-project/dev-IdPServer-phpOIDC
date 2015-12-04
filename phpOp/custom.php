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
  <head><title>' . OP_SERVER_NAME . ' OP</title>
  <meta name="viewport" content="width=320">
  </head>
  <body style="background-color:#FFEEEE;">
  <h1>' . OP_SERVER_NAME . ' OIDC Login</h1>' . "\n  <b>Service " . $logo_uri . ' ask for authentication</b>'.'
  <form method="POST" action="' . $_SERVER['SCRIPT_NAME'] . "/{$login_handler}login\">
  Username:" . $userid_field . '<br />
  Password:<input type="password" name="password" value=""><br />
  <input type="checkbox" name="persist" >Keep me logged in. <br />
  <input type="submit">
  </form>' . "\n  " . $policy_uri . "\n{$tos_uri}" . '
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
  <form method="POST" action="{$_SERVER['SCRIPT_NAME']}/confirm_userinfo">
  <input type="hidden" name="mode" value="ax_confirm">
  <table cellspacing="0" cellpadding="0" width="600">
  <thead><tr><th>Attribute</th><th>Value</th><th>Confirm</th></tr></thead>
  $attributes
  <tr><td colspan="3">&nbsp;</td></tr>
  <thead><tr><td><b>Offline Access Requested</b></td><td>$offline_access</td><td></td></tr></thead>
  <tr><td colspan="3">&nbsp;</td></tr>
  <tr><td colspan="3">&nbsp;</td></tr>
  <tr><td colspan="3"><input type="checkbox" name="agreed" value="1" checked>I Agree to provide the above information. <br/>
  <input type="radio" name="trust" value="once" checked>Trust this site this time only <br />
  <input type="radio" name="trust" value="always" >Trust this site always <br/>
  </td></tr>
  <tr><td colspan="3"><input type="submit" name="confirm" value="confirmed"> </td></tr></table>
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
  <body style="background-color:#FFEEEE;">
  <h1>' . OP_SERVER_NAME . ' AX Confirm</h1>
  <h2><b>'.$client['client_name'].'service </b> requests following AX values...</h2>' . $attribute_form_template . '
  </body>
  </html>
  ';
  return $str;
}



?>