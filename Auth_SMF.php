<?php
/*
SMF and MediaWiki Integration
=============================
Author: Ryan Wagoner (rswagoner at gmail dot com)
Version: 1.10

Place this file in your wiki/extenstions folder. If you
encouter an issue be sure to read the known issues below.

Add to LocalSettings.php
========================
# This requires a user be logged into the wiki to make changes.
$wgGroupPermissions['*']['edit'] = false; // MediaWiki Setting

# If you experience the issue where you appear to be logged in
# eventhough you are logged out then disable the page cache.
#$wgEnableParserCache = false;
#$wgCachePages = false;

# SMF Authentication
# To get started you only need to configure wgSMFPath and wgSMFVersion. 
# The rest of the settings are optional for advanced features.

# Relative path to the forum directory from the wiki
# Do not put a trailing /
# Example: /public_html/forum and /public_html/wiki -> ../forum
$wgSMFPath = "../forum"; 

# Set to the version of SMF you are using.
#$wgSMFVersion = "1.1";
$wgSMFVersion = "2.0";

# Use SMF's login system to automatically log you in/out of the wiki
# This will only work if you are using SMF database sessions (default).
# Make sure "Use database driven sessions" is checked in the
# SMF Admin -> Server Settings -> Feature Configuration section
# NOTE: Make sure to configure the wgCookeDomain below
#$wgSMFLogin = true;

# Make "Enable local storage of cookies" is unchecked in the
# SMF Admin -> Server Settings -> Feature Configuration section
# www.domain.org/wiki and www.domain.org/forums -> www.domain.org 
# wiki.domain.org and forums.doman.org -> .domain.org
#$wgCookieDomain = 'www.domain.org';
#$wgCookiePath = '/'; // Optional, defaults to '/'
#$wgCookieSecure = false;  // Optional, only change on scheme mismatch

# Require members to be a part of this SMF group(s) to login
# NOTE: Members of the SMF Administrator group are always able to login
#$wgSMFGroupName = 'Wiki Editor';
#$wgSMFGroupName = array('Wiki Editor', 'Global Moderator');

# Grant members of this SMF group(s) wiki sysop privileges
# NOTE: These members must be able to login to the wiki
#$wgSMFAdminGroupName = 'Wiki Admin';
#$wgSMFAdminGroupName = array('Wiki Admin', 'Global Moderator');

# Load up the extension
require_once './extensions/Auth_SMF.php';
$wgAuth = new Auth_SMF();

Known Issues
============
- The wiki converts underscores in usernames to spaces. For example john_doe becomes 
  John doe. To work around this we check for both cases and use the first registered
  SMF user. You will need to change the usernames of the later registered user.

- When wgSMFLogin is disabled if you register a new account from the wiki you will not
  be redirected back to the wiki. SMF does not have support for this in their code.

Change Log
==========
1.10 - Enable the register redirection hook when wgSMFLogin is enabled.
     - Enable support for post based groups. Reported by Slack on SMF.

1.9  - When logging in/out send them back to the page they were on. Reported by ecpcorran on SMF.
     - Redirect create account to the SMF register page when wgSMFLogin is disabled.
     - Fix issue with underscore in username when sgSMFLogin is enabled.

1.8  - Check for SMF administrator by ID instead of name. Reported by ecpcorran on SMF.

1.7  - Provide error message when SMF group name is invalid.
     - Fix login/logout redirection with new browser session when wgSMFLogin is enabled.

1.6  - Use existing wgAuth instead of creating a new class.
     - Clarify and clean up source code commenting.
     - Use set and get for user class instead of directly assigning variables.
     - Fix bug introduced by change password for new members when wgSMFLogin is disabled.
     - Fix admin check error for usernames with space or underscore when wgSMFLogin is disabled.
     - Load user from database only if no previous session when sgSMFLogin is enabled.
     - Alert for unexisiting username with space or underscore when wgSMFLogin is disabled.

1.5  - Correctly setup session when wgSMFLogin is enabled. Reported by Slack on SMF.

1.4  - Update email and display name changes when wgSMFLogin is enabled.

1.3  - Authenticate emails for new wiki users when wgSMFLogin is enabled.
     - Enable passwords to be changed via the wiki when wgSMFLogin is disabled.
     - Don't allow banned or unactivated users to log on when wgSMFLogin is disabled.

1.2  - Added support for SMF 2.0 with wgSMFVersion

1.1  - Attempt to work around underscores in usernames when wgSMFLogin is disabled.
     - Allow an array of multiple groups to be used for wgSMFGroupName.
     - Add wgSMFAdminGroupName to define groups that should be granted wiki sysop rights.

1.0  - Initial release
 */

	error_reporting(E_ALL); // Debug

	if(file_exists($wgSMFPath . '/Settings.php'))
		require_once($wgSMFPath . '/Settings.php');
	else
		die('Check to make sure $wgSMFPath is correctly set in LocalSettings.php!');

	$smf_settings['boardurl'] = $boardurl;
	$smf_settings['cookiename'] = $cookiename;

	$smf_settings['db_server'] = $db_server;
	$smf_settings['db_name'] = $db_name;
	$smf_settings['db_user'] = $db_user;
	$smf_settings['db_passwd'] = $db_passwd;
	$smf_settings['db_prefix'] = $db_prefix;

	// Setup the database fields depending on SMF version.
	if(isset($wgSMFVersion) && $wgSMFVersion == '1.1')
	{
		$smf_map['id_member'] = 'ID_MEMBER';
		$smf_map['member_name'] = 'memberName';
		$smf_map['date_registered'] = 'dateRegistered';
		$smf_map['real_name'] = 'realName';
		$smf_map['passwd'] = 'passwd';
		$smf_map['email_address'] = 'emailAddress';
		$smf_map['is_activated'] = 'is_activated';
		$smf_map['additional_groups'] = 'additionalGroups';
		$smf_map['id_post_group'] = 'ID_POST_GROUP';
		$smf_map['password_salt'] = 'passwordSalt';
		$smf_map['id_group'] = 'ID_GROUP';
		$smf_map['group_name'] = 'groupName';	
	}
	elseif(isset($wgSMFVersion) && $wgSMFVersion == '2.0')
	{
		$smf_map['id_member'] = 'id_member';
		$smf_map['member_name'] = 'member_name';
		$smf_map['date_registered'] = 'date_registered';
		$smf_map['real_name'] = 'real_name';
		$smf_map['passwd'] = 'passwd';
		$smf_map['email_address'] = 'email_address';
		$smf_map['is_activated'] = 'is_activated';
		$smf_map['additional_groups'] = 'additional_groups';
		$smf_map['id_post_group'] = 'id_post_group';
		$smf_map['password_salt'] = 'password_salt';
		$smf_map['id_group'] = 'id_group';
		$smf_map['group_name'] = 'group_name';
	}
	else
		die('Check to make sure $wgSMFVersion is correctly set in LocalSettings.php!');

	// Integrate with SMF login / logout?
	if(isset($wgSMFLogin) && $wgSMFLogin)
	{
		$wgHooks['AutoAuthenticate'][] = 'AutoAuthenticateSMF';
		$wgHooks['UserLoginForm'][] = 'UserLoginFormSMF';
		$wgHooks['UserLogout'][] = 'UserLogoutSMF';
	}

	// Always redirect registration to SMF.
	$wgHooks['UserCreateForm'][] = 'UserRegisterSMF';

	/**
	 * Check the SMF cookie and automatically log the user into the wiki.
	 *
	 * @param User $user
	 * @return bool
	 * @public
	 */
	function AutoAuthenticateSMF(&$user) {
		global $wgAuth, $smf_settings, $smf_map;

		$ID_MEMBER = 0;

		if (isset($_COOKIE[$smf_settings['cookiename']]))
		{
			$_COOKIE[$smf_settings['cookiename']] = stripslashes($_COOKIE[$smf_settings['cookiename']]);

			// Fix a security hole in PHP 4.3.9 and below...
			if (preg_match('~^a:[34]:\{i:0;(i:\d{1,6}|s:[1-8]:"\d{1,8}");i:1;s:(0|40):"([a-fA-F0-9]{40})?";i:2;[id]:\d{1,14};(i:3;i:\d;)?\}$~', $_COOKIE[$smf_settings['cookiename']]) == 1)
			{
				list ($ID_MEMBER, $password) = @unserialize($_COOKIE[$smf_settings['cookiename']]);
				$ID_MEMBER = !empty($ID_MEMBER) && strlen($password) > 0 ? (int) $ID_MEMBER : 0;
			}
		}

		// Only load this stuff if the user isn't a guest.
		if ($ID_MEMBER != 0)
		{
			$conn = $wgAuth->connect();
			$request = $wgAuth->query("		
				SELECT $smf_map[id_member], $smf_map[member_name], $smf_map[email_address], $smf_map[real_name],
					$smf_map[is_activated], $smf_map[passwd], $smf_map[password_salt]
				FROM $smf_settings[db_prefix]members
				WHERE $smf_map[id_member] = '{$ID_MEMBER}'
				LIMIT 1", $conn);

			$user_settings = mysql_fetch_assoc($request);

			// Did we find 'im?  If not, junk it.
			if (mysql_num_rows($request) != 0)
			{
				// SHA-1 passwords should be 40 characters long.
				if (strlen($password) == 40)
					$check = sha1($user_settings[$smf_map['passwd']] . $user_settings[$smf_map['password_salt']]) == $password;
				else
					$check = false;

				// Wrong password or not activated - either way, you're going nowhere.
				$ID_MEMBER = $check && ($user_settings[$smf_map['is_activated']] == 1 || $user_settings[$smf_map['is_activated']] == 11) ? $user_settings[$smf_map['id_member']] : 0;
			}
			else
				$ID_MEMBER = 0;

			mysql_free_result($request);
		}

		// Log out guests or members with invalid cookie passwords.
		if($ID_MEMBER == 0)
		{
			$user->logout();
			return true;
		}

		// If the username has an underscore or space accept the first registered user.
		if(strpos($user_settings[$smf_map['member_name']], ' ') !== false || strpos($user_settings[$smf_map['member_name']], '_') !== false)
		{
			// Format to wiki standards (underscores are converted to spaces).
			$case1 = str_replace('_', ' ', $user_settings[$smf_map['member_name']]);
			// Format the alternative case (spaces converted to underscores).
			$case2 = str_replace(' ', '_', $case1);

			$request = $wgAuth->query("
				SELECT $smf_map[id_member] 
				FROM $smf_settings[db_prefix]members
				WHERE $smf_map[member_name] = '{$case1}' 
					OR $smf_map[member_name] = '{$case2}'
				ORDER BY $smf_map[date_registered] ASC
				LIMIT 1", $conn);

			list($id) = mysql_fetch_row($request);
			mysql_free_result($request);

			// Sorry your name was taken already!
			if($id != $ID_MEMBER)
			{
				$user->logout();
				return true;
			}
		}

		// Lastly check to see if they are allowed to login.
		if (!$wgAuth->isGroupAllowed($user_settings[$smf_map['member_name']]))
		{
			$user->logout();
			return true;
		} 

		// Convert to wiki standards
		$username = ucfirst(str_replace('_', ' ', $user_settings[$smf_map['member_name']]));

		// Only poll the database if no session or username mismatch.
		if(!($user->isLoggedIn() && $user->getName() == $username))
		{
	       	$user->setName($username);
	       	$user->setId($user->idForName());

			// No ID we need to add this member to the wiki database.
			if ($user->getID() == 0)
			{
				// getID clears out the name set above.
				$user->setName($username);

				// Let wiki know that their email has been verified.
				$user->mEmailAuthenticated = wfTimestampNow(); 
				$user->addToDatabase();
			} 
			// Otherwise load their details.
			else
				$user->loadFromDatabase();
		}

		// Keep their email and real name up to date with SMF
		$user->setEmail($user_settings[$smf_map['email_address']]);
		$user->setRealName($user_settings[$smf_map['real_name']]);

		$wgAuth->setAdminGroup($user, $user_settings[$smf_map['member_name']]);

		$user->saveSettings();

		// Go ahead and log 'em in
		$user->setupSession();
		$user->setCookies();

		return true;
	}

	/**
	 * Redirect them to the SMF login page.
	 *
	 * @param User $user
	 * @public
	 */
	function UserLoginFormSMF(&$user) {
		smf_sessionSetup();	
		smf_redirectWrapper('old_url', 'login');
	}

	/**
	 * Redirect and utilize the SMF logout function.
	 *
	 * @param User $user
	 * @public
	 */
	function UserLogoutSMF(&$user) {
		$user->logout();

		smf_sessionSetup();	
		smf_redirectWrapper('logout_url', 'logout;sesc=' . $_SESSION['rand_code']);
	}

	/**
	 * Redirect and utilize the SMF register function.
	 *
	 * @public
	 */
	function UserRegisterSMF(&$template) {
		smf_sessionSetup();
		smf_redirectWrapper('old_url', 'register');
	}

	/**
	 * Wrapper to configure the SMF session and perform the redirect.
	 *
	 * @public
	 */
	function smf_redirectWrapper($session, $action)	{
		global $wgScriptPath, $smf_settings;

		$page = !empty($_GET['returnto']) ? '?title=' . $_GET['returnto'] . '&' : '?';
		$_SESSION[$session] = 'http://' . $_SERVER['SERVER_NAME'] . $wgScriptPath . '/index.php' . $page . 'board=redirect';	
		smf_sessionWrite($_COOKIE['PHPSESSID'], session_encode());

		// Do the actual redirect.
		header ('Location: ' . $smf_settings['boardurl'] . '/index.php?action=' . $action);
		exit();
	}

	/**
	 * If the user has visited the forum during the browser session
	 * then load up the exisiting session. Otherwise start a new
	 * session that SMF can use.
	 *
	 * @public
	 */
	function smf_sessionSetup() {
		global $wgCookiePath;

		// Clean out the existing session. This should have no affect
		// since we are going to redirct the user to the SMF page.
		session_destroy();
		session_start();

		// Load up the SMF session and set the redirect URL.
		if(isset($_COOKIE['PHPSESSID']))
			session_decode(smf_sessionRead($_COOKIE['PHPSESSID']));
		// No exisiting session, create one
		else
		{
			// Grab us a unique ID for SMF.
			session_regenerate_id();

			// Needed for SMF checks.
			$_SESSION['rand_code'] = md5(session_id() . rand());
			$_SESSION['USER_AGENT'] = $_SERVER['HTTP_USER_AGENT'];

			// Set the cookie.
			$_COOKIE['PHPSESSID'] = session_id();
			setcookie('PHPSESSID', session_id(), time() + 3600, $wgCookiePath, '', 0);
		}
	}

	/**
	 * Import the session data from SMF
	 * Modified from SMF Sources\Load.php
	 *
	 * @public
	 */
	function smf_sessionRead($session_id) {
		global $wgAuth, $smf_settings;

		if (preg_match('~^[A-Za-z0-9]{16,32}$~', $session_id) == 0)
			return false;

		// Look for it in the database.
		$conn = $wgAuth->connect();
		$result = $wgAuth->query("	
			SELECT data
			FROM $smf_settings[db_prefix]sessions
			WHERE session_id = '" . addslashes($session_id) . "'
			LIMIT 1", $conn);
		list ($sess_data) = mysql_fetch_row($result);
		mysql_free_result($result);

		return $sess_data;
	}

	/**
	 * Save the session data to SMF
	 * Modified from SMF Sources\Load.php
	 *
	 * @public
	 */
	function smf_sessionWrite($session_id, $data) {
		global $wgAuth, $smf_settings;

		if (preg_match('~^[A-Za-z0-9]{16,32}$~', $session_id) == 0)
			return false;

		// First try to update an existing row...
		$conn = $wgAuth->connect();
		$result = $wgAuth->query("
			UPDATE $smf_settings[db_prefix]sessions
			SET data = '" . addslashes($data) . "', last_update = " . time() . "
			WHERE session_id = '" . addslashes($session_id) . "'
			LIMIT 1", $conn);

		// If that didn't work, try inserting a new one.
		if (mysql_affected_rows($conn) == 0)
			$result = $wgAuth->query("
				INSERT IGNORE INTO $smf_settings[db_prefix]sessions
					(session_id, data, last_update)
				VALUES ('" . addslashes($session_id) . "', '" . addslashes($data) . "', " . time() . ")", $conn);

		return $result;
	}

	// First check if class has already been defined.
	if (!class_exists('AuthPlugin'))
		require_once './includes/AuthPlugin.php';

class Auth_SMF extends AuthPlugin {
	/**
	 * Check whether there exists a user account with the given name.
	 * The name will be normalized to MediaWiki's requirements, so
	 * you might need to munge it (for instance, for lowercase initial
	 * letters).
	 *
	 * @param $username String: username.
	 * @return bool
	 * @public
	 */
	function userExists( $username ) {
		global $smf_settings, $smf_map;

		$username = $this->fixUsername($username);

		$conn = $this->connect();
		$request = $this->query("
			SELECT $smf_map[member_name]
			FROM $smf_settings[db_prefix]members
			WHERE $smf_map[member_name] = '{$username}'
			LIMIT 1", $conn);

		list ($user) = mysql_fetch_row($request);
		mysql_free_result($request);

		// Play it safe and double check the match.
		if(strtolower($user) == strtolower($username))
			return true;

		return false;
	}

	/**
	 * Check if a username+password pair is a valid login.
	 * The name will be normalized to MediaWiki's requirements, so
	 * you might need to munge it (for instance, for lowercase initial
	 * letters).
	 *
	 * @param $username String: username.
	 * @param $password String: user password.
	 * @return bool
	 * @public
	 */
	function authenticate( $username, $password ) {
		global $smf_settings, $smf_map;
	
		$username = $this->fixUsername($username);

		$conn = $this->connect();
		$request = $this->query("
			SELECT $smf_map[passwd] 
			FROM $smf_settings[db_prefix]members
			WHERE $smf_map[member_name] = '{$username}'
				AND $smf_map[is_activated] = 1
			LIMIT 1", $conn);

		list($passwd) = mysql_fetch_row($request);
		mysql_free_result($request);

		$pw = sha1(strtolower($username) . $password);

		// Check for password match and that the user is allowed.
		if($pw == $passwd && $this->isGroupAllowed($username))
			return true;

		return false;
	}

	/**
	 * Modify options in the login template.
	 *
	 * @param $template UserLoginTemplate object.
	 * @public
	 */
	function modifyUITemplate( &$template ) {
		$template->set('usedomain',   false); // We do not want a domain name.
		$template->set('create',      false); // Remove option to create new accounts from the wiki.
		$template->set('useemail',    false); // Disable the mail new password box.
	}

	/**
	 * Set the domain this plugin is supposed to use when authenticating.
	 *
	 * @param $domain String: authentication domain.
	 * @public
	 */
	function setDomain( $domain ) {
		$this->domain = $domain;
	}

	/**
	 * Check to see if the specific domain is a valid domain.
	 *
	 * @param $domain String: authentication domain.
	 * @return bool
	 * @public
	 */
	function validDomain( $domain ) {
		return true;
	}

	/**
	 * When a user logs in, optionally fill in preferences and such.
	 * For instance, you might pull the email address or real name from the
	 * external user database.
	 *
	 * The User object is passed by reference so it can be modified; don't
	 * forget the & on your function declaration.
	 *
	 * @param User $user
	 * @public
	 */
	function updateUser( &$user ) {
		global $smf_settings, $smf_map;
		
		$username = $this->fixUsername($user->getName());

		$conn = $this->connect();
		$request = $this->query("
			SELECT $smf_map[email_address], $smf_map[real_name]
			FROM $smf_settings[db_prefix]members
			WHERE $smf_map[member_name] = '{$username}'
			LIMIT 1", $conn);

		while($row = mysql_fetch_assoc($request))
		{
			$user->setRealName($row[$smf_map['real_name']]);
			$user->setEmail($row[$smf_map['email_address']]);

			$this->setAdminGroup($user, $username);
			
			$user->saveSettings();
		}

		mysql_free_result($request);
	
		return true;
	}


	/**
	 * Return true if the wiki should create a new local account automatically
	 * when asked to login a user who doesn't exist locally but does in the
	 * external auth database.
	 *
	 * If you don't automatically create accounts, you must still create
	 * accounts in some way. It's not possible to authenticate without
	 * a local account.
	 *
	 * This is just a question, and shouldn't perform any actions.
	 *
	 * @return bool
	 * @public
	 */
	function autoCreate() {
		return true;
	}

	/**
	 * Can users change their passwords?
	 *
	 * @return bool
	 */
	function allowPasswordChange() {
		global $wgSMFLogin;

		// Only allow password change if not using auto login.
		// Otherwise we would need a bunch of code to rewrite
		// the SMF login cookie with the new password.
		if(isset($wgSMFLogin) && $wgSMFLogin)
			return false;

		return true;
	}

	/**
	 * Set the given password in the authentication database.
	 * As a special case, the password may be set to null to request
	 * locking the password to an unusable value, with the expectation
	 * that it will be set later through a mail reset or other method.
	 *
	 * Return true if successful.
	 *
	 * @param $user User object.
	 * @param $password String: password.
	 * @return bool
	 * @public
	 */
	function setPassword( $user, $password ) {
		global $smf_settings, $smf_map;

		$username = $this->fixUsername($user->getName());
		
		$pw = sha1(strtolower($username) . $password);

		// Verify that the password is up to par.
		if($this->validatePassword($password, $username, array($user->getRealName(), $user->getEmail())) != null)
			return false;

		// Commit it to the database.
		$conn = $this->connect();
		$this->query("
			UPDATE $smf_settings[db_prefix]members
			SET passwd = '{$pw}'
			WHERE $smf_map[member_name] = '{$username}'
			LIMIT 1", $conn);

		return true;
	}

	/**
	 * Update user information in the external authentication database.
	 * Return true if successful.
	 *
	 * @param $user User object.
	 * @return bool
	 * @public
	 */
	function updateExternalDB( $user ) {
		return true;
	}

	/**
	 * Check to see if external accounts can be created.
	 * Return true if external accounts can be created.
	 * @return bool
	 * @public
	 */
	function canCreateAccounts() {
		return false;
	}

	/**
	 * Add a user to the external authentication database.
	 * Return true if successful.
	 *
	 * @param User $user - only the name should be assumed valid at this point
	 * @param string $password
	 * @param string $email
	 * @param string $realname
	 * @return bool
	 * @public
	 */
	function addUser( $user, $password, $email='', $realname='' ) {
		return true;
	}


	/**
	 * Return true to prevent logins that don't authenticate here from being
	 * checked against the local database's password fields.
	 *
	 * This is just a question, and shouldn't perform any actions.
	 *
	 * @return bool
	 * @public
	 */
	function strict() {
		return true;
	}

	/**
	 * When creating a user account, optionally fill in preferences and such.
	 * For instance, you might pull the email address or real name from the
	 * external user database.
	 *
	 * The User object is passed by reference so it can be modified; don't
	 * forget the & on your function declaration.
	 *
	 * @param $user User object.
	 * @param $autocreate bool True if user is being autocreated on login
	 * @public
	 */
	function initUser( $user, $autocreate=false ) {
		global $smf_settings, $smf_map;

		$username = $this->fixUsername($user->getName());

		$conn = $this->connect();
		$request = $this->query("
			SELECT $smf_map[id_member], $smf_map[email_address], $smf_map[real_name]
			FROM $smf_settings[db_prefix]members
			WHERE $smf_map[member_name] = '{$username}'
			LIMIT 1", $conn);

		while($row = mysql_fetch_assoc($request))
		{
			$user->setRealName($row[$smf_map['real_name']]);
			$user->setEmail($row[$smf_map['email_address']]);

			// Let wiki know that their email has been verified.
			$user->mEmailAuthenticated = wfTimestampNow(); 

			$this->setAdminGroup($user, $username);

			$user->saveSettings();
		}
			
		mysql_free_result($request);

		return true;
	}

	/**
	 * If you want to munge the case of an account name before the final
	 * check, now is your chance.
	 *
	 * @public
	 */
	function getCanonicalName( $username ) {
		/**
		 * wiki converts username (john_doe -> John doe)
		 * then getCanonicalName is called
		 * user not in wiki database call userExists
		 * lastly call authenticate
		 */
		return $username;
	}

	/**
	 * The wiki converts underscores to spaces. Attempt to work around this
	 * by checking for both cases. Hopefully we'll only get one match.
	 * Otherwise the first registered SMF account takes priority.
	 *
	 * @public
	 */
	function fixUsername ( $username ) {
		global $smf_settings, $smf_map;

		// No space no problem.
		if(strpos($username, ' ') === false)
			return $username;

		// Look for either case sorted by date.
		$conn = $this->connect();
		$request = $this->query("
			SELECT $smf_map[member_name] 
			FROM $smf_settings[db_prefix]members
			WHERE $smf_map[member_name] = '{$username}' 
				OR $smf_map[member_name] = '" . str_replace(' ', '_', $username) . "'
			ORDER BY $smf_map[date_registered] ASC
			LIMIT 1", $conn);

		list($user) = mysql_fetch_row($request);
		mysql_free_result($request);

		// No result play it safe and return the original.
		return !isset($user) ? $username : $user;
	}

	/**
	 * Check to see if the user should have sysop rights.
	 * Either they are an administrator or are in one
	 * of the define groups.
	 *
	 * To save database queries the fixed username is used.
	 *
	 * @public
	 */
	function setAdminGroup ( &$user, $username ) {
		global $wgSMFAdminGroupName;

		// Administrator always get admin rights.
		if($this->isGroupMember($username, null, 1))
		{
			$user->addGroup("sysop");
			return;
		}

		// Search through all groups, if match give them admin rights.
		if(isset($wgSMFAdminGroupName) && !empty($wgSMFAdminGroupName))
		{
			if(!is_array($wgSMFAdminGroupName))
				$wgSMFAdminGroupName = array($wgSMFAdminGroupName);

			foreach($wgSMFAdminGroupName as $group)
				if($this->isGroupMember($username, $group))
				{
					$user->addGroup("sysop");
					return;
				}
		}

		// No go! Make sure they are not a sysop.
		$user->removeGroup("sysop");
		return;
	}

	/**
	 * Check to see if the user is allowed to log in.
	 * Either they are an administrator or are in one
	 * of the define groups.
	 *
	 * @public
	 */
	function isGroupAllowed ( $username ) {
		global $wgSMFGroupName;

		if(isset($wgSMFGroupName) && !empty($wgSMFGroupName))
		{
			if(!is_array($wgSMFGroupName))
				$wgSMFGroupName = array($wgSMFGroupName);

			// Administrators always allowed.
			if($this->isGroupMember($username, null, 1))
				return true;

			// Search through all groups, if match they're allowed.
			foreach($wgSMFGroupName as $group)
				if($this->isGroupMember($username, $group))
					return true;

			// No go!
			return false;
		}

		// Groups not defined or empty allow them.
		return true;
	}

	/**
	 * Lookup the user and the groups they are assigned to.
	 * Lookup the id for the group name. If there is a match
	 * return true. Otherwise return false.
	 *
	 * @public
	 */
	function isGroupMember ( $username, $groupName, $groupID = null ) {
		global $smf_settings, $smf_map;

		$conn = $this->connect();
		$request = $this->query("
			SELECT $smf_map[id_group], $smf_map[additional_groups], $smf_map[id_post_group]
			FROM $smf_settings[db_prefix]members
			WHERE $smf_map[member_name] = '{$username}'
			LIMIT 1", $conn);

		$groups = array();
		while($row = mysql_fetch_assoc($request))
		{
			$groups[] = $row[$smf_map['id_group']];
			if(!empty($row[$smf_map['additional_groups']]))
				$groups =  array_merge($groups, explode(',', $row[$smf_map['additional_groups']]));
			if(!empty($row[$smf_map['id_post_group']]))
				$groups =  array_merge($groups, explode(',', $row[$smf_map['id_post_group']]));
		}

		mysql_free_result($request);

		if(isset($groupName))
		{
			$request = $this->query("
				SELECT $smf_map[id_group]
				FROM $smf_settings[db_prefix]membergroups
				WHERE $smf_map[group_name] = '{$groupName}'
				LIMIT 1", $conn);

			list($groupID) = mysql_fetch_row($request);
			mysql_free_result($request);

			// Invalid group, error out!
			if(!isset($groupID))
				die ('Unable to find SMF group called "' . $groupName . '" set in LocalSettings.php!');
		}

		// Is there a match?
		if(in_array($groupID, $groups))
			return true;

		return false;
	}

	/**
	 * Check the password to make sure it is to SMF standards.
	 * Modified from SMF Sources\Subs-Auth.php
	 *
	 * @return null if the password is accepted.
	 * @return string with failure reason.
	 * @public
	 */
	function validatePassword($password, $username, $restrict_in = array())
	{
		global $smf_settings;

		$conn = $this->connect();
		$request = $this->query("
			SELECT variable, value
			FROM $smf_settings[db_prefix]settings
			WHERE variable = 'password_strength'
			", $conn);

		while($row = mysql_fetch_assoc($request))
			$modSettings[$row['variable']] = $row['value'];

		mysql_free_result($request);

		// Perform basic requirements first.
		if (strlen($password) < (empty($modSettings['password_strength']) ? 4 : 8))
			return 'short';

		// Is this enough?
		if (empty($modSettings['password_strength']))
			return null;

		// Otherwise, perform the medium strength test - checking if password appears in the restricted string.
		if (preg_match('~\b' . preg_quote($password, '~') . '\b~', implode(' ', $restrict_in)) != 0)
			return 'restricted_words';
		elseif (strpos($password, $username) !== false)
			return 'restricted_words';

		// !!! If pspell is available, use it on the word, and return restricted_words if it doesn't give "bad spelling"?

		// If just medium, we're done.
		if ($modSettings['password_strength'] == 1)
			return null;

		// Otherwise, hard test next, check for numbers and letters, uppercase too.
		$good = preg_match('~(\D\d|\d\D)~', $password) != 0;
		$good &= strtolower($password) != $password;

		return $good ? null : 'chars';
	}

	/**
	 * Connect to the database. Use the settings from smf.
	 *
	 * {@source}
	 * @return resource
	 */
	function connect()
	{
		global $smf_settings;

		// connect to database.
		$conn = mysql_connect($smf_settings['db_server'], $smf_settings['db_user'],
	 		$smf_settings['db_passwd'], true);

		// check if we are connected to the database.
		if (!$conn)
		{
			$this->mysqlerror("There was a problem when connecting to the SMF database.<br />\n" .
				'Check your host, username, and password settings.');
		}

		// select database: this assumes the wiki and smf are in the same database.
		$db_selected = mysql_select_db($smf_settings['db_name']);

		// check if we were able to select the database.
		if (!$db_selected)
		{
			$this->mysqlerror("There was a problem when connecting to the SMF database.<br />\n" .
				'The database ' . $smf_settings['db_server'] . ' was not found.');
		}

		return $conn;
	}

	/**
	 * Run the query and if applicable display the mysql error.
	 *
	 * @param string $query
	 * @return resource
	 */
	function query( $query, $conn )
	{
		$request = mysql_query($query, $conn);
		
		if(!$request)
			$this->mysqlerror('Unable to view external table.');

		return $request;
	}

	/**
	 * Display an error when a mysql error is found.
	 *
	 * @param string $message
	 * @access public
	 */
	function mysqlerror( $message )
	{
	   echo $message . "<br /><br />\n\n";
	   echo 'mySQL error number: ' . mysql_errno() . "<br />\n";
	   echo 'mySQL error message: ' . mysql_error() . "<br /><br />\n\n";
	   exit;
	}
}

