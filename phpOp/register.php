<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<?php
session_start();
?>
<html>
<head>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/2.1.4/jquery.min.js"></script>
<script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/jquery-validate/1.14.0/jquery.validate.min.js"></script>

  <title>Demo Service Provider</title>

<script type="text/javascript">

  function validURL(str) {
  var pattern = new RegExp("((http:\/\/|https:\/\/)(www.)?(([a-zA-Z0-9-]){2,}\.){1,4}([a-zA-Z]){2,6}(\/([a-zA-Z-_\/\.0-9#:?=&;,]*)?)?)",'i'); // fragment locater
  if(!pattern.test(str)) {
    return false;
  } else {
    return true;
  }
}
    //when the dom has loaded setup form validation rules
    $().ready(function($) {
        {
			$.validator.addMethod("urlList", function(value, element) { // Custom method
				var partsArray = value.split('|');
				var result = true;
				for (index = 0; index < partsArray.length & result; ++index) {
					result = result & validURL(partsArray[index]);
				}				
				return result;
			}, "Incorrect URL List");

            //form validation rules
            $("#register-form").validate({
				 rules: {
					redirect_uris: {
						required: true,
						urlList: true
					}
				},
                submitHandler: function(form) {
					var baseUrl = $('#oidc_uri').val();
					var Url = baseUrl + "/registration";
					var toSend = '{ "application_type": "'+$('#application_type').val()+'","redirect_uris":["'+$('#redirect_uris').val()+'"],"client_name":"'+ // Build the JSON
					$('#client_name').val()+'","logo_uri": "'+$('#logo_uri').val()+'", "subject_type":"'+$('#subject_type').val()+'","token_endpoint_auth_method": "'+$('#token_endpoint_auth_method').val()+'"}';
					
					$('#debug').html("Request: "+ Url+"<pre>"+JSON.stringify(toSend,null,4)+"</pre>"); // Display the JSON sent
					
					$.ajax({url:Url, 
						contentType:"application/json", 
						type:"POST",
						async: false,
						data:toSend, 
						dataType:"json",
						success:function(data){
							$('#display').html("Your client has been successfully added "+ "<pre>"+JSON.stringify(data, null, 4)+"</pre>");
							},
						error:function(data){
							$('#display').html("Error: "+ "<pre>"+JSON.stringify(data, null, 4)+"</pre>");
							} 
						});
                }
            });
        }
    });

</script>

</head>
<body>
<div id="content">

<h1>OIDC Client registration</h1>

<!-- HTML form for validation demo -->
<form action="" method="post" id="register-form" novalidate="novalidate">

    <div id="form-content">
        <fieldset>
			<input type="hidden" name="application_type" id="application_type" value="web">
			<input type="hidden" name="subject_type" id="subject_type" value="pairwise">
			<input type="hidden" name="token_endpoint_auth_method"  id="token_endpoint_auth_method" value="client_secret_post">
            <div class="fieldgroup">
                <label for="oidc_uri">OIDC Server URI:</label>
                <input name="oidc_uri" type="url" size=64 value="https://oidc-ns.kermit.orange-labs.fr/phpOp/index.php" id="oidc_uri" required disabled>
            </div>

            <div class="fieldgroup">
                <label for="client_name">Service name:</label>
                <input type="text" minlength=5 name="client_name" id="client_name" required>
            </div>
           <div class="fieldgroup">
                <label for="redirect_uris">Redirect URIs: </label>
                <input name="redirect_uris" type="urlList" size=64 id="redirect_uris" value="
<?php
echo "https://".$_SERVER['HTTP_HOST']."/demo/demoback.php";
?>" required> (url list separated with |)
            </div>

           <div class="fieldgroup">
                <label for="logo_uri">Logo URI:</label>
                <input type="url" size=64 name="logo_uri" id="logo_uri">
            </div>

  
            <div class="fieldgroup">
                <input type="submit" value="Register" class="submit">
            </div>

        </fieldset>
    </div>

</form>
<!-- END HTML form for validation -->
    <div id="display" style="background-color:cc0;">
      </div>
   <div id="debug" style="background-color:red;">
      </div>

</body>
</html>