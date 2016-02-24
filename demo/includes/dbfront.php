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
