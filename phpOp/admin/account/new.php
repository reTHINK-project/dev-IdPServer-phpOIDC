<?php
require_once __DIR__ . '/../../PasswordHash.php';

if (isset($_POST['submitted'])) {
foreach($_POST AS $key => $value) { $_POST[$key] = mysql_real_escape_string($value); }
$_POST['crypted_password'] = create_hash($_POST['crypted_password']);
$today = getdate();

$params = array(
	"name" => "",
	"enabled" => "",
	"login" => "",
	"crypted_password" => "",
	"name_ja_kana_jp" => "",
	"name_ja_hani_jp" => "",
	"given_name" => "",
	"given_name_ja_kana_jp" => "",
	"given_name_ja_hani_jp" => "",
	"family_name" => "",
	"family_name_ja_kana_jp" => "",
	"family_name_ja_hani_jp" => "",
	"middle_name" => "",
	"middle_name_ja_kana_jp" => "",
	"middle_name_ja_hani_jp" => "",
	"nickname" => "",
	"preferred_username" => "",
	"profile" => "",
	"picture" => "",
	"website" => "",
	"email" => "",
	"email_verified" => "",
	"gender" => "",
	"birthdate" => "",
	"zoneinfo" => "",
	"locale" => "",
	"phone_number" => "",
	"phone_number_verified" => "",
	"address" => "",
	"updated_at" => $today['mon'].'/'.$today['mday'].'/'.$today['year'],
);
	
	
foreach ($params as $i => $value) {
	if(isset($_POST[$i])) {
		$params = $_POST[$i];
	}      
}



$sql = "INSERT INTO `account` ( `name` ,  `enabled` ,  `login` ,  `crypted_password` ,  `name_ja_kana_jp` ,  `name_ja_hani_jp` ,  `given_name` ,  `given_name_ja_kana_jp` ,  `given_name_ja_hani_jp` ,  `family_name` ,  `family_name_ja_kana_jp` ,  `family_name_ja_hani_jp` ,  `middle_name` ,  `middle_name_ja_kana_jp` ,  `middle_name_ja_hani_jp` ,  `nickname` ,  `preferred_username` ,  `profile` ,  `picture` ,  `website` ,  `email` ,  `email_verified` ,  `gender` ,  `birthdate` ,  `zoneinfo` ,  `locale` ,  `phone_number` ,  `phone_number_verified` ,  `address` ,  `updated_at`  ) VALUES(  '{$params['name']}' ,  '{$params['enabled']}' ,  '{$params['login']}' ,  '{$params['crypted_password']}' ,  '{$params['name_ja_kana_jp']}' ,  '{$params['name_ja_hani_jp']}' ,  '{$params['given_name']}' ,  '{$params['given_name_ja_kana_jp']}' ,  '{$params['given_name_ja_hani_jp']}' ,  '{$params['family_name']}' ,  '{$params['family_name_ja_kana_jp']}' ,  '{$params['family_name_ja_hani_jp']}' ,  '{$params['middle_name']}' ,  '{$params['middle_name_ja_kana_jp']}' ,  '{$params['middle_name_ja_hani_jp']}' ,  '{$params['nickname']}' ,  '{$params['preferred_username']}' ,  '{$params['profile']}' ,  '{$params['picture']}' ,  '{$params['website']}' ,  '{$params['email']}' ,  '{$params['email_verified']}' ,  '{$params['gender']}' ,  '{$params['birthdate']}' ,  '{$params['zoneinfo']}' ,  '{$params['locale']}' ,  '{$params['phone_number']}' ,  '{$params['phone_number_verified']}' ,  '{$params['address']}' ,  '{$params['updated_at']}'  ) ";
mysql_query($sql) or die(mysql_error()); 
echo "Added row.<br />"; 
echo "<a href='index.php?action=list'>Back To Listing</a>";
} 
?>

<form action='' method='POST'>
<div class='table1'>
<table border='1'>
<tr>
<td><b>Field</b></td>
<td><b>Value</b></td>
</tr>    

<tr><td>Name:</td><td><input type='text' name='name'/> </td></tr>
<tr><td>Enabled:</td><td><input type='text' name='enabled'/> </td></tr>
<tr><td>Login:</td><td><input type='text' name='login'/> </td></tr>
<tr><td>Password:</td><td><input type='text' name='crypted_password'/> </td></tr>
<tr><td>Given Name:</td><td><input type='text' name='given_name'/> </td></tr>
<tr><td>Family Name:</td><td><input type='text' name='family_name'/> </td></tr>
<tr><td>Middle Name:</td><td><input type='text' name='middle_name'/> </td></tr>
<tr><td>Nickname:</td><td><input type='text' name='nickname'/> </td></tr>
<tr><td>Preferred Username:</td><td><input type='text' name='preferred_username'/> </td></tr>
<tr><td>Profile:</td><td><input type='text' name='profile'/> </td></tr>
<tr><td>Picture:</td><td><input type='text' name='picture'/> </td></tr>
<tr><td>Website:</td><td><input type='text' name='website'/> </td></tr>
<tr><td>Email:</td><td><input type='text' name='email'/> </td></tr>
<tr><td>Email Verified:</td><td><input type='text' name='email_verified'/> </td></tr>
<tr><td>Gender:</td><td><input type='text' name='gender'/> </td></tr>
<tr><td>Birthdate:</td><td><input type='text' name='birthdate'/> </td></tr>
<tr><td>Zoneinfo:</td><td><input type='text' name='zoneinfo'/> </td></tr>
<tr><td>Locale:</td><td><input type='text' name='locale'/> </td></tr>
<tr><td>Phone Number:</td><td><input type='text' name='phone_number'/> </td></tr>
<tr><td>Phone Number Verified:</td><td><input type='text' name='phone_number_verified'/> </td></tr>
<tr><td>Address:</td><td><input type='text' name='address'/> </td></tr>
</table>
</div>
    <br/><br/>
    <p><input type='submit' value='Add Row' /><input type='hidden' value='1' name='submitted' />

</form> 
