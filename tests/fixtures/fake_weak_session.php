<?php
session_start();
$id = md5(time());
$_SESSION['session_id'] = $id;
setcookie('PHPSESSID', md5(rand()), time() + 3600);
?>