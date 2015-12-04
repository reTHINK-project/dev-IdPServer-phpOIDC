<?php
include_once 'includes/functions.php';
include_once 'includes/dbfront.php';
sec_session_start ();
setlocale(LC_ALL, 'fr_FR');
$pdo=connect();
$session_path = session_save_path() . SP_PATH;
if(!file_exists($session_path))
    mkdir($session_path);
session_save_path($session_path);

// delete user function, then redirect to index.php
if( isset($_GET['delete']) ) {
	$id = $_GET['delete'];
	deleteUser($pdo, $id);
	header("Location: index.php");
	return;
}
// delete session function, then redirect to index.php
if( isset($_GET['logout']) ) {
	clearSession();
	header("Location: index.php");
	return;
}
?>

<!DOCTYPE html>
<html>
  <head><title>Demo Service Provider</title>
<h1>Welcome to Demo Service</h1><br>
  <meta name="viewport" content="width=320">
  </head>
  <body>
<?php
if (!isset($_SESSION['USER']))// add link to enroll users
{
	echo 'No session, please login (use of OIDC server)
	<br><br><form method="link" action="'.$SP_URL.'/demo.php"> <input type="submit" value="Login"></form>';
}
else
{
	echo 'Welcome '.$_SESSION['USER']['firstName']
	.'<br><br><form method="get" action="'.$SP_URL.'/index.php">
	<input type="hidden" name="logout"><input type="submit" value="Logout"></form>';
}
//a href="'.$SP_URL.'/ardeco.php">Sign in with OIDC</a>&nbsp<br>';


// get all users from database
$users = getAllUsers($pdo);
$nbUser = count($users);

// display users
if($nbUser<1) {
	echo "No users enrolled";
} else {
echo '<br><br>List of registered users<br>';
	for( $i=0; $i<count($users); $i++ ) {
		$user = $users[$i];
		$id   = $user['id'];
		// add a link to each user to delete from database
		echo "User : ".$user['firstName']." ".$user['lastName'].' <a href="index.php?delete='.$id.'">delete</a><br>';
	}
}

?>
  </body>
</html>
