<?php 

// start the session
session_start();
$included = false;

// if auth_username has already been defined, then load the appropriate config file
if ($_SESSION['auth_username']) {
	$config = './config/' . $_SESSION['auth_username'] . '.php';
	if (file_exists($config)) {
		require($config);
		$included = true;
	} else {
		$_SESSION = array();
	}
}

if (!$included) {
	require('./multi_user.php'); // load multi user config
}

require_once ('./phpmyid.php');
exit;
