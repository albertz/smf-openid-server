<?php
//
// SMFSession.class.php
// Handles interoperability with SMF
//

class SMFInterop extends Object  {

	/**
	 * Reads SMF session from the database
	 * @throws DibiException	 
	 * @return Session data or false on invalid session
	 */	 	 	
	private function readSession($sessionId)
	{
		// Validate
		if (preg_match('~^[A-Za-z0-9]{16,32}$~', $sessionId) == 0)
			return false;

		// Look for it in the database.
		$result = dibi::query('SELECT
													[data]
													FROM 
													[:prefix:sessions]
													WHERE
													[session_id]=%s', $sessionId, '
													LIMIT 1');
		if (!$result)
			return false;
			
		// Fetch the row and check it
		$rows = $result->fetchAll();
		if (count($rows) !== 1)
			return false;
			
		return $rows[0];		
	}
	
	/**
	 * Writes the SMF session to database
	 * @param Session ID
	 * @param Encoded session data	 
	 */	 	 	
	private function writeSession($sessionId, $data)
	{
		if (preg_match('~^[A-Za-z0-9]{16,32}$~', $sessionId) == 0)
			return false;

		// First try to update an existing row...
		$result = dibi::query("
			UPDATE [:prefix:sessions]
			SET [data]=%s", $data, ",[last_update]=%u", time(), "
			WHERE [session_id]=%s", $sessionId, "
			LIMIT 1");

		// If that didn't work, try inserting a new one.
		if (dibi::affectedRows() == 0)
			$result = dibi::query("
				INSERT IGNORE INTO [:prefix:sessions]
					([session_id], [data], [last_update])
				VALUES (%s", $sessionId, ",%s", $data, ",%u", time(), ")");

		return $result;	
	
	}
	
	private function redirectWrapper($sessionId, $data)
	{
		$page = '?';
		if (!empty())
		$page = !empty($_GET['returnto']) ? '?title=' . $_GET['returnto'] . '&' : '?';
		$_SESSION[$session] = 'http://' . $_SERVER['SERVER_NAME'] . $wgScriptPath . '/index.php' . $page . 'board=redirect';	
		smf_sessionWrite($_COOKIE['PHPSESSID'], session_encode());
		
		// Do the actual redirect.
		header ('Location: ' . $smf_settings['boardurl'] . '/index.php?action=' . $action);
		exit();		
	}
	
	/**
	 * Sets up the session for use with SMF
	 * 
	 */	 	 	
	public function sessionSetup()
	{
		// Session cleanup
		$session = Environment::getSession();
		$session->clean();
		
		$cookie = Environment::getHttpRequest()->getCookie("PHPSESSID");
		if ($cookie)  {
			session_decode($this->readSession($cookie));
		} else {
			// Changing application state, regenerate the ID
			$session->regenerateId();
			
			// Needed for SMF checks.
			$_SESSION['rand_code'] = md5(session_id() . rand());
			$_SESSION['USER_AGENT'] = $_SERVER['HTTP_USER_AGENT'];

			// Set the cookie.
			Environment::getHttpResponse()->setCookie("PHPSESSID", $session->getId(), time() + 3600);		
		}
	}

}
