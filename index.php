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

	/*
	This is designed to full phpMyID into thinking that there is a single user.  These details will never work as the password isn't hashed - however, when phpMyID is trying to authorize the account, it will auto switch to a different config file.  This is just to fool the setup checks so that I didn't have to rewrite all of the phpmyid.php file.
	*/
	
	$GLOBALS['profile'] = array(
		'auth_username' => 'phpmyopenid',
		'auth_password' => 'phpmyopenid',
		'auth_realm' => 'phpmyid'
	);
}

require_once ('./phpmyid.php');
exit;
