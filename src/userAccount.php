<?php

#!# Needs e-mail address change facility
#!# Needs account deletion facility

# Version 1.1.0


# Class to provide user login
class userAccount
{
	# Specify available arguments as defaults or as NULL (to represent a required argument)
	private $defaults = array (
		'namespace'							=> 'UserAccount',
		'baseUrl'							=> '',
		'loginUrl'							=> '/login/',				// after baseUrl. E.g. if the baseUrl is /app then the loginUrl should be set as e.g. /login/ , which will result in links to /app/login/
		'logoutUrl'							=> '/login/logout.html',	// after baseUrl
		'salt'								=> NULL,
		'brandname'							=> false,
		'autoLogoutTime'					=> 86400,
		'database'							=> NULL,
		'table'								=> 'users',
		'pageRegister'						=> 'register.html',
		'pageResetpassword'					=> 'resetpassword.html',
		'applicationName'					=> NULL,
		'administratorEmail'				=> NULL,
		'passwordResetTokenLength'			=> 12,
		'loginText'							=> 'log in',
		'loggedInText'						=> 'logged in',
		'logoutText'						=> 'log out',
		'loggedOutText'						=> 'logged out',
		'passwordMinimumLength'				=> 6,
		'passwordRequiresLettersAndNumbers'	=> true,
	);
	
	# Class properties
	private $html  = '';
	
	# Database structure definition
	public function databaseStructure ()
	{
		return "
		CREATE TABLE IF NOT EXISTS `{$this->settings['table']}` (
		  `id` int(11) NOT NULL AUTO_INCREMENT COMMENT 'Automatic key',
		  `email` varchar(255) COLLATE utf8_unicode_ci NOT NULL COMMENT 'Your e-mail address',
		  `password` varchar(255) COLLATE utf8_unicode_ci NOT NULL COMMENT 'Password',
		  `validationToken` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL COMMENT 'Token for validation (empty if validated)',
		  `passwordreset` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL COMMENT 'Password reset token',
		  `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Timestamp',
		  PRIMARY KEY (`id`),
		  UNIQUE KEY `email` (`email`)
		) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci COMMENT='Users';
		";
	}
	
	
	# Constructor
	function __construct ($settings = array (), $databaseConnection = NULL)
	{
		# Load required libraries
		require_once ('application.php');
		require_once ('database.php');
		
		# Merge in the arguments; note that $errors returns the errors by reference and not as a result from the method
		if (!$this->settings = application::assignArguments ($errors, $settings, $this->defaults, __CLASS__, NULL, $handleErrors = true)) {return false;}
		
		# Assign the baseUrl
		$this->baseUrl = $this->settings['baseUrl'];
		
		# Obtain the database connection
		if (!$databaseConnection || !$databaseConnection->connection) {
			$this->setupError = "\n<p class=\"warning\">No valid database connection was supplied. The website administrator needs to fix this problem.</p>";
			return false;
		}
		$this->databaseConnection = $databaseConnection;
		
		# Ensure the table exists
		$this->setupError = false;
		$tables = $this->databaseConnection->getTables ($this->settings['database']);
		if (!in_array ($this->settings['table'], $tables)) {
			$this->setupError = "\n<p class=\"warning\">The login system is not set up properly. The website administrator needs to fix this problem.</p>";
			return false;
		}
		
		# Lock down PHP session management
		ini_set ('session.name', 'session');
		ini_set ('session.use_only_cookies', 1);
		
		# Start the session handling
		if (!session_id ()) {session_start ();}
		
		# Regenerate the session ID
		session_regenerate_id ($deleteOldSession = true);
		
		// Take no action
		
	}
	
	
	
	# Public accessor to get the ID
	public function getUserId ()
	{
		# Check the session, and destroy it if there is a problem (e.g. mismatch in the user-agent, or the timestamp expires)
		$this->doSessionChecks ();
		
		# Return the e-mail address
		return (isSet ($_SESSION[$this->settings['namespace']]) ? $_SESSION[$this->settings['namespace']]['userId'] : false);
	}
	
	
	# Public accessor to get the username
	public function getUserEmail ()
	{
		# Check the session, and destroy it if there is a problem (e.g. mismatch in the user-agent, or the timestamp expires)
		$this->doSessionChecks ();
		
		# Return the e-mail address
		return (isSet ($_SESSION[$this->settings['namespace']]) ? $_SESSION[$this->settings['namespace']]['email'] : false);
	}
	
	
	# Public accessor to get the HTML
	public function getHtml ()
	{
		return $this->html;
	}
	
	
	
	# Session handler, with regenerative IDs and user agent checking
	public function login ($showStatus = false)
	{
		# End if there is a setup error
		if ($this->setupError) {
			echo $this->setupError;
			return false;
		}
		
		# Check the session, and destroy it if there is a problem (e.g. mismatch in the user-agent, or the timestamp expires)
		$this->doSessionChecks ();
		
		# Require login if the user has not presented a session
		if (!isSet ($_SESSION[$this->settings['namespace']])) {
			
			# If not on the login page, redirect to it
			if ($_SERVER['SCRIPT_URL'] != $this->baseUrl . $this->settings['loginUrl']) {
				$redirectto = $this->baseUrl . $this->settings['loginUrl'] . '?returnto=' . $_SERVER['REQUEST_URI'];
				header ('Location: http://' . $_SERVER['SERVER_NAME'] . $redirectto);
				return true;
			}
			
			# Show the login form
			if ($accountDetails = $this->loginForm ()) {
				
				# Accept the login, i.e. write into the session
				$this->doLogin ($accountDetails['id'], $accountDetails['email']);
				
				# Take the user to the same page in order to clear the form's POSTed variables and thereby prevent confusion in cases of refreshed pages
				$location = $_SERVER['REQUEST_URI'];
				header ('Location: http://' . $_SERVER['SERVER_NAME'] . $location);
				$this->html .= "\n<p>You are now logged in. <a href=\"" . htmlspecialchars ($location) . '">Please click here to continue.</a></p>';
			}
		}
		
		# If logged in, say so
		if (isSet ($_SESSION[$this->settings['namespace']])) {
			
			# Determine the return-to location, ensuring any URL return value starts with a /
			if (isSet ($_GET['returnto']) && strlen ($_GET['returnto'])) {
				$returnto = $this->baseUrl . $this->settings['loginUrl'];
				if (substr ($_GET['returnto'], 0, 1) == '/') {	// Authorise it if correct
					$returnto = $_GET['returnto'];
				}
				
				# Redirect to the user's original location if required
				if ($_SERVER['REQUEST_URI'] != $returnto) {
					header ('Location: http://' . $_SERVER['SERVER_NAME'] . $returnto);
					return true;
				}
			}
			
			# Confirm login if required and still on the page
			if ($showStatus) {
				$this->html .= "\n" . '<div class="graybox">';
				$this->html .= "\n\t" . '<p><img src="/images/icons/tick.png" /> You are currently ' . $this->settings['loggedInText'] . ' as <strong>' . htmlspecialchars ($_SESSION[$this->settings['namespace']]['email']) . '</strong>.</p>';
				$this->html .= "\n" . '</div>';
				$this->html .= "\n" . '<p>Please <a href="' . $this->baseUrl . $this->settings['logoutUrl'] . '">' . $this->settings['logoutText'] . '</a> when you have finished.</p>';
			}
		}
		
		# Return the session token
		return (isSet ($_SESSION[$this->settings['namespace']]) ? $_SESSION[$this->settings['namespace']]['email'] : false);
	}
	
	
	# Function to accept the login, i.e. write into the session
	private function doLogin ($userId, $email)
	{
		# Write the values into the session
		$_SESSION[$this->settings['namespace']]['userId'] = $userId;
		$_SESSION[$this->settings['namespace']]['email'] = $email;
		$_SESSION[$this->settings['namespace']]['fingerprint'] = $this->hashedString ($_SERVER['HTTP_USER_AGENT']);
		$timestamp = time ();
		$_SESSION[$this->settings['namespace']]['timestamp'] = $timestamp;
	}
	
	
	# Function to check the user's browser fingerprint
	private function doSessionChecks ()
	{
		# If the user has presented a session, check the user-agent
		if (isSet ($_SESSION[$this->settings['namespace']])) {
			if ($_SESSION[$this->settings['namespace']]['fingerprint'] != $this->hashedString ($_SERVER['HTTP_USER_AGENT'])) {
				$this->killSession ();
				$this->html .= "\n<p>You have been {$this->settings['loggedOutText']}.</p>";
			}
		}
		
		# Keep the user's session alive unless inactive for the time period defined in the settings
		$timestamp = time ();
		if (isSet ($_SESSION[$this->settings['namespace']]) && isSet ($_SESSION[$this->settings['namespace']]['timestamp'])) {
			if (($timestamp - $_SESSION[$this->settings['namespace']]['timestamp']) > $this->settings['autoLogoutTime']) {
				
				# Explicitly kill the session
				$this->killSession ();
				
				# Define the login form message
				$minutesInactivity = round ($this->settings['autoLogoutTime'] / 60);
				$this->html .= "\n<p>Your session expired due to " . ($minutesInactivity <= 1 ? 'around a minute of inactivity' : "{$minutesInactivity} minutes of inactivity") . ', so you have been ' . $this->settings['loggedOutText'] . '.</p>';
			}
		}
	}
	
	
	# Status label function
	public function getStatus ()
	{
		# If logged in, show the e-mail
		if (isSet ($_SESSION[$this->settings['namespace']])) {
			$html = '<a href="' . $this->baseUrl . $this->settings['loginUrl'] . '">' . htmlspecialchars ($_SESSION[$this->settings['namespace']]['email']) . '</a>';
		} else {
			$html = '<a href="' . $this->baseUrl . $this->settings['loginUrl'] . '">' . $this->settings['loginText'] . '</a>';
		}
		
		# Return the text
		return $html;
	}
	
	
	# Logout function
	public function logout ()
	{
		# Cache whether the user presented session data
		$userHadSessionData = (isSet ($_SESSION[$this->settings['namespace']]));
		
		# Explicitly destroy the session
		$this->killSession ();
		
		# Confirm logout if there was a session, and redirect the user to the login page if necessary
		$loginLocation = $this->baseUrl . $this->settings['loginUrl'];
		if ($userHadSessionData) {
			$this->html .= "\n<p>You have been successfully {$this->settings['loggedOutText']}.</p>\n<p>You can <a href=\"" . htmlspecialchars ($loginLocation) . '">' . $this->settings['loginText'] . ' again</a> if you wish.</p>';
		} else {
			header ('Location: http://' . $_SERVER['SERVER_NAME'] . $this->baseUrl . $loginLocation);
			$this->html .= "\n<p>You are not {$this->settings['loggedInText']}.</p>\n<p><a href=\"" . htmlspecialchars ($loginLocation) . '">Please click here to continue.</a></p>';
		}
	}
	
	
	# Helper function to destroy a session properly
	private function killSession ()
	{
		session_unset ();
		session_destroy ();
		unset ($_SESSION[$this->settings['namespace']]);
		
		if (ini_get ('session.use_cookies')) {
			$params = session_get_cookie_params ();
			setcookie (session_name (), '', time () - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
		}
	}
	
	
	# Helper function for passwords / user-agent comparison; see http://phpsec.org/articles/2005/password-hashing.html ; note that supplying the e-mail as well makes the salt more complex and therefore means that two users with the same password will have different hashes
	private function hashedString ($string, $emailAsAdditionalSalt = false)
	{
		return hash ('sha512', $this->settings['salt'] . ($emailAsAdditionalSalt ? $emailAsAdditionalSalt : '') . $string);
	}
	
	
	# Login form
	private function loginForm ()
	{
		# Start the HTML
		$html  = '';
		
		# Create the form
		require_once ('ultimateForm.php');
		$form = new form (array (
			'formCompleteText' => false,
			'div' => 'graybox useraccount',
			'displayRestrictions' => false,
			'requiredFieldIndicator' => false,
			'name' => false,
			'autofocus' => true,
		));
		$form->heading ('p', '<strong>Please enter your ' . ($this->settings['brandname'] ? $this->settings['brandname'] . ' ' : '') . 'e-mail and password to continue.</strong> Or:</p><p><a href="' . $this->baseUrl . '/' . $this->settings['pageRegister'] . '">Create a new account</a> if you don\'t have one yet.</p><p><a href="' . $this->baseUrl . '/' . $this->settings['pageResetpassword'] . (isSet ($_GET['email']) ? '?email=' . urldecode ($_GET['email']) : false) . '">Reset your password</a> if you have forgotten it.');
		$form->email (array (
			'name'			=> 'email',
			'title'			=> 'E-mail address',
			'required'		=> true,
			'default'		=> (isSet ($_GET['email']) ? urldecode ($_GET['email']) : false),
		));
		$form->password (array (
			'name'			=> 'password',
			'title'			=> 'Password',
			'required'		=> true,
		));
		if ($unfinalisedData = $form->getUnfinalisedData ()) {
			if (isSet ($unfinalisedData['email']) && isSet ($unfinalisedData['password'])) {
				if (strlen ($unfinalisedData['email']) && strlen ($unfinalisedData['password'])) {
					if (application::validEmail ($unfinalisedData['email'])) {	// #!# This restatement of logic is a bit hacky
						
						# Check the data and, if there is a failure inject a failure into the form processing
						if (!$accountDetails = $this->getUser ($unfinalisedData['email'], $unfinalisedData['password'], $message)) {
							$form->registerProblem ('failure', $message);
						}
					}
				}
			}
		}
		if (!$result = $form->process ($html)) {
			$this->html .= $html;
			return false;
		}
		
		# Confirm login
		$html  = "\n" . '<p><img src="/images/icons/tick.png" /> <strong>You have successfully ' . $this->settings['loggedInText'] . '.</strong></p>';
		
		# Register the HTML
		$this->html .= $html;
		
		# Return the e-mail address
		return $accountDetails;
	}
	
	
	# User account creation page
	public function register ()
	{
		# End if there is a setup error
		if ($this->setupError) {
			echo $this->setupError;
			return false;
		}
		
		# Start the HTML
		$html  = '';
		
		# If there is a signed-in user, prevent registration
		if ($this->getUserId ()) {
			$html  = "\n<p>You cannot reset the password while {$this->settings['loggedInText']}. Please <a href=\"{$this->baseUrl}{$this->settings['logoutUrl']}\">{$this->settings['logoutText']}</a> first.</p>";
			$this->html .= $html;
			return false;
		}
		
		# If a token is supplied, go to the validation page
		if (isSet ($_GET['token']) || isSet ($_GET['email'])) {return $this->registerValidationPage ();}
		
		# Show the form (which will write to $this->html)
		if (!$result = $this->formUsernamePassword ()) {return false;}
		
		# Hash the password
		$passwordHashed = $this->hashedString ($result['password'], $result['email']);
		
		# Create a token
		$token = application::generatePassword ($this->settings['passwordResetTokenLength']);
		
		# Insert the new user
		$insertData = array ('email' => $result['email'], 'password' => $passwordHashed, 'validationToken' => $token);
		$this->databaseConnection->insert ($this->settings['database'], $this->settings['table'], $insertData);
		
		# Confirm and invite the user to login
		$html .= "\n<p><strong>Please now check your e-mail account (" . htmlspecialchars ($result['email']) . ') to validate the account.</strong></p>';
		$html .= "\n<p>(If it has not appeared after a few minutes, please check your spam folder in case your e-mail provider has mis-filtered it.)</p>";
		
		# Assemble the message
		$message  = "\nA request to create a new account on {$_SERVER['SERVER_NAME']} has been made.";
		$message .= "\n\nTo validate the account, use this link:";
		$message .= "\n\n{$_SERVER['_SITE_URL']}{$this->baseUrl}/{$this->settings['pageRegister']}?token=" . $token . '&email=' . htmlspecialchars (rawurlencode ($result['email']));
		$message .= "\n\n\nIf you did not request to create this account, do not worry - it will not yet have been fully created. You can just ignore this e-mail.";
		
		# Send the e-mail
		$mailheaders = 'From: ' . ((PHP_OS == 'WINNT') ? $this->settings['administratorEmail'] : $this->settings['applicationName'] . ' <' . $this->settings['administratorEmail'] . '>');
		$additionalParameters = "-f {$this->settings['administratorEmail']} -r {$this->settings['administratorEmail']}";
		application::utf8Mail ($result['email'], "Registration on {$_SERVER['SERVER_NAME']} - confirmation required", wordwrap ($message), $mailheaders, $additionalParameters);
		
		# Register the HTML
		$this->html .= $html;
	}
	
	
	# Validation page
	private function registerValidationPage ()
	{
		# Start the HTML
		$html  = '';
		
		# Ensure a token and e-mail have been supplied
		if (!isSet ($_GET['token']) || !strlen ($_GET['token'])) {
			$html .= "<p>No token was supplied in the link you are using. Please check the link given in the e-mail and try again.</p>";
			$this->html = $html;
			return false;
		}
		if (!isSet ($_GET['email']) || !strlen ($_GET['email'])) {
			$html .= "<p>No e-mail adddress was supplied in the link you are using. Please check the link given in the e-mail and try again.</p>";
			$this->html = $html;
			return false;
		}
		
		# Validate the token and e-mail combination
		$match = array ('validationToken' => $_GET['token'], 'email' => $_GET['email']);
		if (!$user = $this->databaseConnection->selectOne ($this->settings['database'], $this->settings['table'], $match)) {
			$html .= "<p>The details you supplied were not correct. Please check the link given in the e-mail and try again.</p>";
			$this->html .= $html;
			return;	// End here; take no action
		}
		
		# Wipe out the validation token
		$updateData = array ('validationToken' => NULL);
		$this->databaseConnection->update ($this->settings['database'], $this->settings['table'], $updateData, array ('email' => $_GET['email']));
		
		# Confirm success
		$html .= "\n<p><strong>Your account has now been validated - many thanks for registering.</strong></p>";
		$html .= "\n<p><strong>Please now <a href=\"{$this->baseUrl}{$this->settings['loginUrl']}?email=" . htmlspecialchars (rawurlencode ($_GET['email'])) . "\">{$this->settings['loginText']}</a> to start.</strong></p>";
		
		# Register the HTML
		$this->html .= $html;
	}
	
	
	# Reset password page
	public function resetpassword ()
	{
		# If a token is supplied, divert to the reset form
		if (isSet ($_GET['token'])) {return $this->newPasswordChangePage ();}
		
		# Start the HTML
		$html  = '';
		
		# Determine if the user is already logged-in
		$loggedInUsername = $this->getUserId ();
		
		# Create the form
		require_once ('ultimateForm.php');
		$form = new form (array (
			'formCompleteText' => false,
			'div' => 'graybox useraccount',
			'displayRestrictions' => false,
			'requiredFieldIndicator' => false,
			'name' => false,
			'autofocus' => true,
		));
		$form->heading ('p', 'You can use this form to reset your password.</p><p>Enter your e-mail address below. If the e-mail address has been registered, instructions on resetting your password will be sent to it.');
		$form->email (array (
			'name'			=> 'email',
			'title'			=> 'E-mail address',
			'required'		=> true,
			'editable'		=> (!$loggedInUsername),
			'default'		=> ($loggedInUsername ? $loggedInUsername : (isSet ($_GET['email']) ? urldecode ($_GET['email']) : false)),
		));
		$form->heading ('p', 'If no e-mail comes through after a few tries, it is likely that the original e-mail you gave was invalid. Please check your address and create a new account.');
		if (!$result = $form->process ($html)) {
			$this->html .= $html;
			return;
		}
		
		# State that an e-mail may have been sent
		$html .= "<p>If that e-mail address has been registered, instructions on resetting your password have been sent to it.</p>";
		
		# Lookup the account details
		if (!$user = $this->databaseConnection->selectOne ($this->settings['database'], $this->settings['table'], array ('email' => $result['email']))) {
			$this->html .= $html;
			return;	// End here; take no action
		}
		
		# Create a token
		$token = application::generatePassword ($this->settings['passwordResetTokenLength']);
		
		# Write the token into the database for this user
		$updateData = array ('passwordreset' => $token);
		$this->databaseConnection->update ($this->settings['database'], $this->settings['table'], $updateData, array ('email' => $user['email']));
		
		# Assemble the message
		$message  = "\nA request to change your password on {$_SERVER['SERVER_NAME']} has been made.";
		$message .= "\n\nTo create a new password, use this link:";
		$message .= "\n\n{$_SERVER['_SITE_URL']}{$this->baseUrl}/{$this->settings['pageResetpassword']}?token={$token}";
		$message .= "\n\n\nIf you did not request a new password, do not worry - your password has not been changed. You can just ignore this e-mail.";
		
		# Send the e-mail
		$mailheaders = 'From: ' . ((PHP_OS == 'WINNT') ? $this->settings['administratorEmail'] : $this->settings['applicationName'] . ' <' . $this->settings['administratorEmail'] . '>');
		application::utf8Mail ($result['email'], "Password reset request for {$_SERVER['SERVER_NAME']}", wordwrap ($message), $mailheaders);
		
		# Register the HTML
		$this->html .= $html;
	}
	
	
	# Password change page
	private function newPasswordChangePage ()
	{
		# Start the HTML
		$html  = '';
		
		# If there is a signed-in user, prevent registration
		if ($this->getUserId ()) {
			$html  = "\n<p>You cannot reset a password while {$this->settings['loggedInText']}. Please <a href=\"{$this->baseUrl}{$this->settings['logoutUrl']}\">{$this->settings['logoutText']}</a> first.</p>";
			$this->html .= $html;
			return false;
		}
		
		# Ensure a token has been supplied
		if (!isSet ($_GET['token']) || !strlen ($_GET['token'])) {
			$html .= "<p>No token was supplied in the link you are using. Please check the link given in the e-mail and try again.</p>";
			$this->html = $html;
			return false;
		}
		// Note that the token is only checked below, when the user has also entered an e-mail address, which makes this much harder to crack
		
		# Show the form (which will write to $this->html)
		if (!$result = $this->formUsernamePassword ($_GET['token'])) {return false;}
		
		# Hash the password
		$passwordHashed = $this->hashedString ($result['password'], $result['email']);
		
		# Update the password in the database; if the user never validated the account, validate it, because this process has proven that the user has an e-mail address
		$insertData = array ('password' => $passwordHashed, 'passwordreset' => NULL, 'validationToken' => NULL);
		$this->databaseConnection->update ($this->settings['database'], $this->settings['table'], $insertData, array ('email' => $result['email']));
		
		# Log the user in
		$accountDetails = $this->getUser ($result['email'], $result['password']);
		$this->doLogin ($accountDetails['id'], $accountDetails['email']);
		
		# Confirm and invite the user to login
		$html .= "\n" . '<p><strong><img src="/images/icons/tick.png" /> Your password has been successfully changed.</strong></p>';
		$html .= "\n<p>You are now logged in with the new password</a>.</p>";
		
		# Register the HTML
		$this->html .= $html;
	}
	
	
	# Function to create a form with a username and password
	private function formUsernamePassword ($tokenConfirmation = false)
	{
		# Start the HTML
		$html  = '';
		
		# In password reset mode, i.e. where a token has been supplied, prefill the e-mail address field; note that an unvalidated account is fine, because this the reset token has come from an e-mail anyway
		$prefillEmail = false;
		if ($tokenConfirmation) {
			if ($prefill = $this->databaseConnection->selectOne ($this->settings['database'], $this->settings['table'], array ('passwordreset' => $tokenConfirmation))) {
				$prefillEmail = $prefill['email'];
			}
		}
		
		# Create the form
		require_once ('ultimateForm.php');
		$form = new form (array (
			'formCompleteText' => false,
			'div' => 'graybox useraccount',
			'displayRestrictions' => false,
			'requiredFieldIndicator' => false,
			'name' => false,
			'display' => 'paragraphs',
			'autofocus' => true,
		));
		if (!$tokenConfirmation) {
			$form->heading ('p', 'Enter your e-mail address. We will send a confirmation message to this address.');
		}
		$form->email (array (
			'name'			=> 'email',
			'title'			=> 'E-mail address',
			'required'		=> true,
			'size'			=> 50,
			'default'		=> $prefillEmail,
			'editable'		=> (!$prefillEmail),
		));
		$form->heading ('p', 'Now ' . ($tokenConfirmation ? 'enter a new password' : 'choose a password') . ", and repeat it to confirm.");
		$form->password (array (
			'name'			=> 'password',
			'title'			=> ($tokenConfirmation ? '<strong>New</strong> password' : 'Password'),
			'required'		=> true,
			'confirmation'	=> true,
			'description'	=> "Must be <strong>at least {$this->settings['passwordMinimumLength']} characters long</strong>" . ($this->settings['passwordRequiresLettersAndNumbers'] ? ', and including at least one letter and number' : '') . '.',
		));
		if ($unfinalisedData = $form->getUnfinalisedData ()) {
			if (isSet ($unfinalisedData['email']) && isSet ($unfinalisedData['password'])) {
				if (strlen ($unfinalisedData['email']) && strlen ($unfinalisedData['password'])) {
					if (application::validEmail ($unfinalisedData['email'])) {	// #!# This restatement of logic is a bit hacky
						
						# When in account creation mode, check the e-mail address has not already been registered
						if (!$tokenConfirmation) {
							$match = array ('email' => $unfinalisedData['email']);
							if ($this->databaseConnection->selectOne ($this->settings['database'], $this->settings['table'], $match)) {
								$form->registerProblem ('failure', "There is already an account registered with this address. If you have forgotten the password, you can apply to <a href=\"{$this->baseUrl}/resetpassword.html?email=" . htmlspecialchars (rawurlencode ($unfinalisedData['email'])) . "\">reset the password</a>.");
							}
						}
						
						# In password reset mode, i.e. where a token has been supplied, check that both the e-mail and token are correct; note that an unvalidated account is fine, because this the reset token has come from an e-mail anyway
						if ($tokenConfirmation) {
							$match = array ('email' => $unfinalisedData['email'], 'passwordreset' => $tokenConfirmation, );
							if (!$this->databaseConnection->selectOne ($this->settings['database'], $this->settings['table'], $match)) {
								$form->registerProblem ('failure', "The token in the URL and e-mail address did not match. Please check the link in the e-mail has been followed correctly, and that you have entered your e-mail address correctly.");
							}
						}
						
						# Check that the password is sufficiently complex enough
						if (!$this->passwordComplexityOk ($unfinalisedData['password'], $message)) {
							$form->registerProblem ('complexity', $message);
						}
					}
				}
			}
		}
		
		# Process the form
		$result = $form->process ($html);
		
		# Register the HTML
		$this->html .= $html;
		
		# Return the result
		return $result;
	}
	
	
	# Function to check that a password is sufficiently complex
	private function passwordComplexityOk ($password, &$message)
	{
		# Ensure it is long enough
		if (strlen ($password) < $this->settings['passwordMinimumLength']) {
			$message = "The password must be at least {$this->settings['passwordMinimumLength']} characters long.";
			return false;
		}
		
		# Must have both letters and numbers
		if ($this->settings['passwordRequiresLettersAndNumbers']) {
			if (!preg_match ('/[a-zA-Z]/', $password) && !preg_match ('/[0-9]/', $password)) {
				$message = 'The password must include at least one letter and number.';
				return false;
			}
		}
		
		# All tests passed
		return true;
	}
	
	
	# Check credentials
	private function getUser ($email, $password, &$message = '')
	{
		# Get the data row for this username
		$user = $this->databaseConnection->selectOne ($this->settings['database'], $this->settings['table'], array ('email' => $email));
		
		# Hash the supplied password, so it can be compared against the database string which is also hashed
		$passwordHashed = $this->hashedString ($password, $email);
		
		# Compare
		if (($passwordHashed == $user['password']) && (!strlen ($user['validationToken']))) {return $user;}
		
		# Credentials not valid
		$message = 'The e-mail/password pair you provided did not match any registered and validated account. <a href="' . $this->baseUrl . '/' . $this->settings['pageResetpassword'] . '?email=' . htmlspecialchars (rawurlencode ($email)) . '">Reset your password</a> if you have forgotten it.';
		return false;
	}
}

?>