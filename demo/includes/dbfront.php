<?php

function addUser($pdo, $sub, $email, $firstName, $lastName) {
  $p='INSERT INTO users (sub,email,firstName,lastName)
  		VALUES (:sub,:email,:firstName,:lastName)';
  $stmt=$pdo->prepare($p);
  $stmt->bindParam(':sub',$sub);
  $stmt->bindParam(':email',$email);
  $stmt->bindParam(':firstName',$firstName);
  $stmt->bindParam(':lastName',$lastName);
  $stmt->execute();
}

function deleteUser($pdo, $id) {
	$p='DELETE FROM users WHERE id = :id';
	$stmt = $pdo->prepare($p);
	$stmt->bindParam(':id', $id);

	return $stmt->execute();
}

function getAllUsers($pdo) {
  $p='select * FROM users';
  $stmt=$pdo->prepare($p);
  $stmt->execute();
  
  $result = array();
  while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
  	$result[] = $row;
  }
  return $result;
}

function getUser($pdo,$sub) {
  $p='select * FROM users where sub = :sub';
  $stmt=$pdo->prepare($p);
  $stmt->bindParam(':sub',$sub);
  $stmt->execute();
  $result = $stmt->fetch(PDO::FETCH_ASSOC);
  return $result;
} 
