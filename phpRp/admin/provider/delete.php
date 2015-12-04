<? 
$id = (int) $_GET['id'];
mysql_query("DELETE FROM `provider` WHERE `id` = '$id' ") ;
echo (mysql_affected_rows()) ? "Row deleted.<br /> " : "Nothing deleted.<br /> "; 
?> 

<a href='index.php?acton=list'>Back To Listing</a>