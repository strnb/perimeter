<?php
$ip = $_GET['ip'];
$output = shell_exec('ping -c 4 ' . $ip);
echo $output;
?>