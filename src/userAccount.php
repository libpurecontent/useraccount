<?php

#!# Needs e-mail address change facility
#!# Needs account deletion facility

# Version 1.4.0


# Class to provide user login
class userAccount
{
	# Specify available arguments as defaults or as NULL (to represent a required argument)
	private $defaults = array (
		'namespace'							=> 'UserAccount',
		'baseUrl'							=> '',
		'loginUrl'							=> '/login/',					// after baseUrl. E.g. if the baseUrl is /app then the loginUrl should be set as e.g. /login/ , which will result in links to /app/login/
		'logoutUrl'							=> '/login/logout/',			// after baseUrl
		'salt'								=> false,						// Only needed if there are legacy password hashes in the database which have not been updated
		'brandname'							=> false,
		'autoLogoutTime'					=> 86400,
		'database'							=> NULL,
		'table'								=> 'users',
		'pageRegister'						=> '/login/register/',			// after baseUrl
		'pageResetpassword'					=> '/login/resetpassword/',		// after baseUrl
		'pageAccountdetails'				=> '/login/accountdetails/',    // after baseUrl
		'applicationName'					=> NULL,
		'administratorEmail'				=> NULL,
		'validationTokenLength'				=> 24,
		'loginText'							=> 'log in',
		'loggedInText'						=> 'logged in',
		'logoutText'						=> 'log out',
		'loggedOutText'						=> 'logged out',
		'passwordMinimumLength'				=> 6,
		'passwordRequiresLettersAndNumbers'	=> true,
		'usernames'							=> false,	// Whether to use usernames (necessary only for social applications, where friendly profile URLs are needed)
		'usernameRegexp'					=> '^([a-z0-9]{5,})$',
		'usernameRegexpDescription'			=> 'Usernames must be all lower-case letters/numbers, at least 5 characters long. NO capital letters allowed.',
		'privileges'						=> false,	// Whether there is a privileges field
	);
	
	# Class properties
	private $html  = '';
	
	# Database structure definition
	public function databaseStructure ()
	{
		# Determine optional parts
		$username = ($this->settings['usernames'] ? "`username` varchar(30) COLLATE utf8_unicode_ci NOT NULL COMMENT 'Username'," : '');
		$usernameIndex = ($this->settings['usernames'] ? "UNIQUE KEY `username` (`username`)," : '');
		$privileges = ($this->settings['privileges'] ? "`privileges` set('administrator','other') COLLATE utf8_unicode_ci DEFAULT NULL COMMENT 'Privileges'," : '');
		
		# Assemble the SQL
		$sql = "
		CREATE TABLE IF NOT EXISTS `{$this->settings['table']}` (
		  `id` int(11) NOT NULL AUTO_INCREMENT COMMENT 'Automatic key',
		  {$username}
		  `email` varchar(255) COLLATE utf8_unicode_ci NOT NULL COMMENT 'Your e-mail address',
		  `password` varchar(255) COLLATE utf8_unicode_ci NOT NULL COMMENT 'Password',
		  {$privileges}
		  `validationToken` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL COMMENT 'Token for validation or password reset',
		  `lastLoggedInAt` datetime DEFAULT NULL COMMENT 'Last logged in time',
		  `validatedAt` datetime DEFAULT NULL COMMENT 'Time when validated',
		  `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Timestamp',
		  PRIMARY KEY (`id`),
		  {$usernameIndex}
		  UNIQUE KEY `email` (`email`)
		) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci COMMENT='Users';
		";
		
		# Return the SQL
		return $sql;
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
		
		# Load the password_compat library if password_* functions do not exist; see: https://github.com/ircmaxell/password_compat/
		if (!defined ('PASSWORD_DEFAULT')) {
			require_once ('password.php');
		}
		
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
	
	
	# Public accessor to get the e-mail address
	public function getUserEmail ()
	{
		# Check the session, and destroy it if there is a problem (e.g. mismatch in the user-agent, or the timestamp expires)
		$this->doSessionChecks ();
		
		# Return the e-mail address
		return (isSet ($_SESSION[$this->settings['namespace']]) ? $_SESSION[$this->settings['namespace']]['email'] : false);
	}
	
	
	# Public accessor to get the username
	public function getUserUsername ()
	{
		# Return NULL if not enabled
		if (!$this->settings['usernames']) {return NULL;}
		
		# Check the session, and destroy it if there is a problem (e.g. mismatch in the user-agent, or the timestamp expires)
		$this->doSessionChecks ();
		
		# Return the username
		return (isSet ($_SESSION[$this->settings['namespace']]) ? $_SESSION[$this->settings['namespace']]['username'] : false);
	}
	
	
	# Public accessor to get the list of available privileges
	public function getAvailablePrivileges ()
	{
		# Return NULL if not enabled
		if (!$this->settings['privileges']) {return NULL;}
		
		# Get the field spec
		$fields = $this->databaseConnection->getFields ($this->settings['database'], $this->settings['table']);
		
		# Return the list
		return $fields['privileges']['_values'];
	}
	
	
	# Public accessor to determine if the user has a privilege
	public function hasPrivilege ($privilege)
	{
		# Return NULL if not enabled
		if (!$this->settings['privileges']) {return NULL;}
		
		# Check the session, and destroy it if there is a problem (e.g. mismatch in the user-agent, or the timestamp expires)
		$this->doSessionChecks ();
		
		# Return the status
		return (isSet ($_SESSION[$this->settings['namespace']]) ? in_array ($privilege, $_SESSION[$this->settings['namespace']]['privileges'], true) : false);
	}
	
	
	# Public accessor to add a privilege
	public function addPrivilege ($userId, $privilege)
	{
		# Return NULL if not enabled
		if (!$this->settings['privileges']) {return NULL;}
		
		# Return the result
		return $this->databaseConnection->addToSet ($this->settings['database'], $this->settings['table'], 'privileges', $privilege, 'id', $userId);
	}
	
	
	# Public accessor to remove a privilege
	public function removePrivilege ($userId, $privilege)
	{
		# Return NULL if not enabled
		if (!$this->settings['privileges']) {return NULL;}
		
		# Return the result
		return $this->databaseConnection->removeFromSet ($this->settings['database'], $this->settings['table'], 'privileges', $privilege, 'id', $userId);
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
			
			# Make sure the user is using the official URL for this login page, if embedded
			if ($_SERVER['SCRIPT_URL'] != $this->baseUrl . $this->settings['loginUrl']) {
				$redirectto = $this->baseUrl . $this->settings['loginUrl'] . '?' . $_SERVER['SCRIPT_URL'];
				header ('Location: http://' . $_SERVER['SERVER_NAME'] . $redirectto);
				return true;
			}
			
			# Show the login form, and obtain the account details if successfully authenticated
			if ($accountDetails = $this->loginForm ()) {
				
				# Accept the login, i.e. write into the session
				$this->doLogin ($accountDetails);
				
				# Take the user to the same page in order to clear the form's POSTed variables and thereby prevent confusion in cases of refreshed pages
				$location = $_SERVER['REQUEST_URI'];
				header ('Location: http://' . $_SERVER['SERVER_NAME'] . $location);
				$this->html .= "\n<p>You are now logged in. <a href=\"" . htmlspecialchars ($location) . '">Please click here to continue.</a></p>';
				return true;
			}
		}
		
		# If logged in, say so
		if (isSet ($_SESSION[$this->settings['namespace']])) {
			
			# If a returnto is specified, find this in the subsequent query string; note we cannot use a GET key because /path/foo.html would become /path/foo_html as PHP converts . to _
			$returnto = false;
			if (substr_count ($_SERVER['QUERY_STRING'], "action={$_GET['action']}&/")) {
				$returnto = '/' . str_replace ("action={$_GET['action']}&/", '', $_SERVER['QUERY_STRING']);
			}
			
			# If returnto is set to one of the internal pages (e.g. the user has clicked on a top-right login link while on the reset password page), avoid redirecting back to that internal page, to avoid confusion
			if ($returnto) {
				$avoidReturnto = array (
					$this->baseUrl . $this->settings['pageResetpassword'],
					$this->baseUrl . $this->settings['pageRegister'],
				);
				if (in_array ($returnto, $avoidReturnto)) {
					$returnto = $this->baseUrl . '/';
				}
			}
			
			# If a validated returnto is specified, redirect to the user's original location if required
			if ($returnto) {
				if ($_SERVER['REQUEST_URI'] != $returnto) {
					header ('Location: http://' . $_SERVER['SERVER_NAME'] . $returnto);
					$this->html .= "\n<p>You are now logged in. <a href=\"" . htmlspecialchars ($returnto) . '">Please click here to continue.</a></p>';
					return true;
				}
			}
			
			# Otherwise, still on the page, confirm login
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
	
	
	# Function to write the login into the session
	private function doLogin ($accountDetails)
	{
		# Log that the user has logged in
		$updateData = array ('lastLoggedInAt' => 'NOW()');
		$this->databaseConnection->update ($this->settings['database'], $this->settings['table'], $updateData, array ('email' => $accountDetails['email']));
		
		# Write the values into the session
		$_SESSION[$this->settings['namespace']]['userId'] = $accountDetails['id'];
		$_SESSION[$this->settings['namespace']]['email'] = $accountDetails['email'];
		if ($this->settings['usernames']) {
			$_SESSION[$this->settings['namespace']]['username'] = $accountDetails['username'];
		}
		if ($this->settings['privileges']) {
			$_SESSION[$this->settings['namespace']]['privileges'] = ($accountDetails['privileges'] ? explode (',', $accountDetails['privileges']) : array ());
		}
		$_SESSION[$this->settings['namespace']]['fingerprint'] = md5 ($_SERVER['HTTP_USER_AGENT']);		// md5 merely to condense the string; see: http://stackoverflow.com/a/1221933
		$_SESSION[$this->settings['namespace']]['timestamp'] = time ();
	}
	
	
	# Function to check the user's browser fingerprint
	private function doSessionChecks ()
	{
		# If the user has presented a session, check the user-agent
		if (isSet ($_SESSION[$this->settings['namespace']])) {
			if ($_SESSION[$this->settings['namespace']]['fingerprint'] != md5 ($_SERVER['HTTP_USER_AGENT'])) {
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
		$form->heading ('p', '<strong>Please enter your ' . ($this->settings['brandname'] ? $this->settings['brandname'] . ' ' : '') . 'e-mail and password to continue.</strong> Or:</p><p><a href="' . $this->baseUrl . $this->settings['pageRegister'] . '">Create a new account</a> if you don\'t have one yet.<br /><a href="' . $this->baseUrl . $this->settings['pageResetpassword'] . (isSet ($_GET['email']) ? '?email=' . htmlspecialchars (rawurldecode ($_GET['email'])) : false) . '">Forgotten your password?</a> - link to reset it.<br /><br />');
		$widgetType = ($this->settings['usernames'] ? 'input' : 'email');	// Prefer HTML5 e-mail type if usernames are not in use
		$form->{$widgetType} (array (
			'name'			=> 'email',		// Retained this name so that browsers auto-fill
			'title'			=> 'E-mail address' . ($this->settings['usernames'] ? ' or username' : ''),
			'required'		=> true,
			'default'		=> (isSet ($_GET['email']) ? rawurldecode ($_GET['email']) : false),
		));
		$form->password (array (
			'name'			=> 'password',
			'title'			=> 'Password',
			'required'		=> true,
		));
		if ($unfinalisedData = $form->getUnfinalisedData ()) {
			if (isSet ($unfinalisedData['email']) && isSet ($unfinalisedData['password'])) {
				if (strlen ($unfinalisedData['email']) && strlen ($unfinalisedData['password'])) {
					if (strlen ($unfinalisedData['email'])) {
						
						# Check the data and, if there is a failure inject a failure into the form processing
						if (!$accountDetails = $this->getValidatedUser ($unfinalisedData['email'], $unfinalisedData['password'], $message)) {
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
		
		# Return the account details
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
		if (isSet ($_GET['token'])) {return $this->registerValidationPage ();}
		
		# Show the form (which will write to $this->html)
		if (!$result = $this->formUsernamePassword ()) {return false;}
		
		# Hash the password
		$result['password'] = password_hash ($result['password'], PASSWORD_DEFAULT);
		
		# Add in a validation token
		$result['validationToken'] = application::generatePassword ($this->settings['validationTokenLength']);
		
		# Insert the new user
		if (!$this->databaseConnection->insert ($this->settings['database'], $this->settings['table'], $result)) {
			$html .= "\n<p>There was a problem creating the account. Please try again later.</p>";
			$this->html .= $html;
			return;
		}
		
		# Confirm and invite the user to login
		$html .= "\n<p><strong>Please now check your e-mail account (" . htmlspecialchars ($result['email']) . ') to validate the account.</strong></p>';
		$html .= "\n<p>(If it has not appeared after a few minutes, please check your spam folder in case your e-mail provider has mis-filtered it.)</p>";
		
		# Assemble the message
		$message  = "\nA request to create a new account on {$_SERVER['SERVER_NAME']} has been made.";
		$message .= "\n\nTo validate the account, use this link:";
		$message .= "\n\n{$_SERVER['_SITE_URL']}{$this->baseUrl}{$this->settings['pageRegister']}{$result['validationToken']}/";
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
		
		# Ensure a token has been supplied
		if (!isSet ($_GET['token']) || !strlen ($_GET['token'])) {
			$html .= "<p>The link you used appears to be invalid. Please check the link given in the e-mail and try again.</p>";
			$this->html = $html;
			return false;
		}
		
		# Validate the token and get the user's account details
		$match = array ('validationToken' => $_GET['token']);
		$fields = array ('id', 'email');
		if ($this->settings['usernames']) {$fields[] = 'username';}	// Add username if enabled
		if ($this->settings['privileges']) {$fields[] = 'privileges';}	// Add privileges if enabled
		if (!$accountDetails = $this->databaseConnection->selectOne ($this->settings['database'], $this->settings['table'], $match, $fields)) {
			$html .= "<p>The details you supplied were not correct. Please check the link given in the e-mail and try again.</p>";
			$this->html .= $html;
			return;	// End here; take no action
		}
		
		# Set the account as validated
		$html .= $this->setAccountValidated ($accountDetails['id']);
		
		# Log the user in
		$this->doLogin ($accountDetails);
		$html .= "\n" . '<p><img src="/images/icons/user.png" /> You are now logged in with the new password.</p>';
		
		# Register the HTML
		$this->html .= $html;
	}
	
	
	# Function to set an account as validated
	private function setAccountValidated ($userId)
	{
		# Set the user as validated, by wiping out the validation token and logging the validation time
		$updateData = array ('validationToken' => NULL, 'validatedAt' => 'NOW()');
		$this->databaseConnection->update ($this->settings['database'], $this->settings['table'], $updateData, array ('id' => $userId));
		
		# Assemble the HTML
		$html = "\n" . '<p><strong><img src="/images/icons/tick.png" /> Your account has now been validated - many thanks for registering.</strong></p>';
		
		# Return the HTML
		return $html;
	}
	
	
	# Reset password request page
	public function resetpassword ()
	{
		# Determine if the user is already logged-in
		$loggedInUsername = $this->getUserId ();
		
		# If there is a signed-in user, prevent reset
		if ($this->getUserId ()) {
			$html  = "\n<p>You cannot reset a password while {$this->settings['loggedInText']}. Please <a href=\"{$this->baseUrl}{$this->settings['logoutUrl']}\">{$this->settings['logoutText']}</a> first.</p>";
			$this->html .= $html;
			return false;
		}
		
		# If a token is supplied, or the user is currently logged in, divert to the reset form
		if (isSet ($_GET['token'])) {return $this->newPasswordChangePage ();}
		
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
		$form->heading ('p', "You can use this form to reset your password.</p>\n<p>Enter your e-mail address" . ($this->settings['usernames'] ? ' or username' : '') . ' below. If it has been registered, instructions on resetting your password will be sent by e-mail.');
		$widgetType = ($this->settings['usernames'] ? 'input' : 'email');	// Prefer HTML5 e-mail type if usernames are not in use
		$form->$widgetType (array (
			'name'			=> 'email',		// Retained this name so that browsers auto-fill
			'title'			=> 'E-mail address' . ($this->settings['usernames'] ? ' or username' : ''),
			'required'		=> true,
			'editable'		=> (!$loggedInUsername),
			'default'		=> ($loggedInUsername ? $loggedInUsername : (isSet ($_GET['email']) ? rawurldecode ($_GET['email']) : false)),
		));
		if (!$result = $form->process ($html)) {
			$this->html .= $html;
			return;
		}
		
		# Determine if the identifier is an e-mail or username, and create a description of it
		$identifierIsEmail = (substr_count ($result['email'], '@'));
		$identifierDescription = ($identifierIsEmail ? 'e-mail' : 'username');
		
		# State that an e-mail may have been sent
		$html .= "\n<p>If that {$identifierDescription} has been registered, instructions on resetting your password have been sent by e-mail.</p>";
		$html .= "\n<p>If no e-mail comes through after a few tries, it is likely that the {$identifierDescription} you gave was invalid. Please check it, or create a new account.</p>";
		
		# Lookup the account details
		$identifierField = ($identifierIsEmail ? 'email' : 'username');
		if (!$user = $this->databaseConnection->selectOne ($this->settings['database'], $this->settings['table'], array ($identifierField => $result['email']))) {
			$this->html .= $html;
			return;	// End here; take no action
		}
		
		# Create a token
		$validationToken = application::generatePassword ($this->settings['validationTokenLength']);
		
		# Write the token into the database for this user
		$updateData = array ('validationToken' => $validationToken);
		$this->databaseConnection->update ($this->settings['database'], $this->settings['table'], $updateData, array ('email' => $user['email']));
		
		# Assemble the message
		$message  = "\nA request to change your password on {$_SERVER['SERVER_NAME']} has been made.";
		$message .= "\n\nTo create a new password, use this link:";
		$message .= "\n\n{$_SERVER['_SITE_URL']}{$this->baseUrl}{$this->settings['pageResetpassword']}{$validationToken}/";
		$message .= "\n\n\nIf you did not request a new password, do not worry - your password has not been changed. You can just ignore this e-mail.";
		
		# Send the e-mail
		$mailheaders = 'From: ' . ((PHP_OS == 'WINNT') ? $this->settings['administratorEmail'] : $this->settings['applicationName'] . ' <' . $this->settings['administratorEmail'] . '>');
		application::utf8Mail ($user['email'], "Password reset request for {$_SERVER['SERVER_NAME']}", wordwrap ($message), $mailheaders);
		
		# Register the HTML
		$this->html .= $html;
	}
	
	
	# Password change page
	private function newPasswordChangePage ()
	{
		# Start the HTML
		$html  = '';
		
		# Ensure a token has been supplied
		if (!isSet ($_GET['token']) || !strlen ($_GET['token'])) {
			$html .= "<p>The link you used appears to be invalid. Please check the link given in the e-mail and try again.</p>";
			$this->html = $html;
			return false;
		}
		
		# Show the form (which will write to $this->html)
		if (!$result = $this->formUsernamePassword ($_GET['token'])) {return false;}
		
		# Get the user's account details
		$match = array ('email' => $result['email']);
		$fields = array ('id', 'email', 'validatedAt');
		if ($this->settings['usernames']) {$fields[] = 'username';}	// Add username if enabled
		if ($this->settings['privileges']) {$fields[] = 'privileges';}	// Add privileges if enabled
		if (!$accountDetails = $this->databaseConnection->selectOne ($this->settings['database'], $this->settings['table'], $match, $fields)) {
		$html .= "<p>There was a problem fetching your account details. Please try again later.</p>";
			$this->html .= $html;
			return;	// End here; take no action
		}
		
		# Set the account as validated if not already; this would happen if the user has not validated it, then gone to the password reset page, followed the link in the e-mail correctly, and reached this point - which is equivalent to validation
		if (!$accountDetails['validatedAt']) {
			$html .= $this->setAccountValidated ($accountDetails['id']);
		}
		
		# Hash the password
		$passwordHashed = password_hash ($result['password'], PASSWORD_DEFAULT);
		
		# Update the password in the database
		$updateData = array ('password' => $passwordHashed, 'validationToken' => NULL);
		$this->databaseConnection->update ($this->settings['database'], $this->settings['table'], $updateData, array ('email' => $result['email']));
		$html .= "\n" . '<p><strong><img src="/images/icons/tick.png" /> Your password has been successfully set.</strong></p>';
		
		# Log the user in
		$this->doLogin ($accountDetails);
		$html .= "\n" . '<p><img src="/images/icons/user.png" /> You are now logged in with the new password.</p>';
		
		# Register the HTML
		$this->html .= $html;
	}
	
	
	# Function to create a form with an e-mail, password, and possibly a username
	private function formUsernamePassword ($tokenConfirmation = false)
	{
		# Start the HTML
		$html  = '';
		
		# In password reset mode, i.e. where a token has been supplied, prefill the e-mail address field; note that an unvalidated account is fine, because this the reset token has come from an e-mail anyway
		$prefillEmail = false;
		if ($tokenConfirmation) {
			if ($prefill = $this->databaseConnection->selectOne ($this->settings['database'], $this->settings['table'], array ('validationToken' => $tokenConfirmation))) {
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
			$form->heading ('p', '<strong>Fill in these details to create an account.</strong> ' . ($this->settings['usernames'] ? 'Choose a username, specify' : 'Specify') . ' your e-mail address, and create a password.');
		}
		if ($this->settings['usernames']) {
			if (!$tokenConfirmation) {
				$form->input (array (
					'name'			=> 'username',
					'title'			=> 'Username',
					'required'		=> true,
					'maxlength'		=> 30,
					'size'			=> 20,
					'regexp'		=> $this->settings['usernameRegexp'],
					'description'	=> $this->settings['usernameRegexpDescription'],
				));
			}
		}
		$form->email (array (
			'name'			=> 'email',
			'title'			=> 'E-mail address',
			'required'		=> true,
			'size'			=> 50,
			'default'		=> $prefillEmail,
			'editable'		=> (!$prefillEmail),
			'description'	=> ($tokenConfirmation ? '' : 'We will send a confirmation message to this address.'),
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
						
						# When in account creation mode, check the e-mail address (and if required the username) has not already been registered
						if (!$tokenConfirmation) {
							$match = array ('email' => $unfinalisedData['email']);
							if ($this->databaseConnection->selectOne ($this->settings['database'], $this->settings['table'], $match)) {
								$form->registerProblem ('emailfailure', "There is already an account registered with this address. If you have forgotten the password, you can apply to <a href=\"{$this->baseUrl}{$this->settings['pageResetpassword']}?email=" . htmlspecialchars (rawurlencode ($unfinalisedData['email'])) . "\">reset the password</a>.");
							}
							if ($this->settings['usernames']) {
								$match = array ('username' => $unfinalisedData['username']);
								if ($this->databaseConnection->selectOne ($this->settings['database'], $this->settings['table'], $match)) {
									$form->registerProblem ('emailfailure', "That username has been taken already - please choose another. (If you think you might have already registered but have forgotten the password, you can apply to <a href=\"{$this->baseUrl}{$this->settings['pageResetpassword']}?email=" . htmlspecialchars (rawurlencode ($unfinalisedData['email'])) . "\">reset the password</a>.)");
								}
							}
						}
						
						# In password reset mode, i.e. where a token has been supplied, check that both the e-mail and token are correct; note that an unvalidated account is fine, because this the reset token has come from an e-mail anyway
						if ($tokenConfirmation) {
							$match = array ('email' => $unfinalisedData['email'], 'validationToken' => $tokenConfirmation);
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
	
	
	# Check credentials, by supplying the e-mail/username so that the row containing the password can be found, and then matching the password
	private function getValidatedUser ($identifier, $password, &$message = '')
	{
		# Determine if the identifier is an e-mail or username
		$identifierIsEmail = true;
		if ($this->settings['usernames']) {
			$identifierIsEmail = (substr_count ($identifier, '@'));
		}
		
		# Define a description of the identifier
		$identifierDescription = ($identifierIsEmail ? 'e-mail' : 'username');
		
		# Define a message which will be used if validation fails
		$resetPasswordLink  = $this->baseUrl . $this->settings['pageResetpassword'];
		if ($identifierIsEmail) {	// If a username has been entered, do not expose the associated e-mail address for the account
			$resetPasswordLink .= '?email=' . htmlspecialchars (rawurlencode ($identifier));
		}
		$failureMessage = "The {$identifierDescription}/password pair you provided did not match any registered account. <a href=\"" . $resetPasswordLink . '">Reset your password</a> if you have forgotten it.';
		
		# Get the data row for this identifier
		$identifierField = ($identifierIsEmail ? 'email' : 'username');
		if (!$user = $this->databaseConnection->selectOne ($this->settings['database'], $this->settings['table'], array ($identifierField => $identifier))) {
			$message = $failureMessage;
			return false;
		}
		
		# Verify the password
		if (!$this->passwordVerify ($password, $user)) {
			$message = $failureMessage;
			return false;
		}
		
		# If the credentials are correct, but the account not validated, disallow login, as the user has not yet confirmed they have access to the e-mail they originally specified
		if (!$user['validatedAt']) {
			$message = "The account for the {$identifierDescription} you specified has not yet been validated. Please check your e-mail account for the validation link you were sent, or <a href=\"" . $resetPasswordLink . '">request it again</a> if you cannot find it.';
			return false;
		}
		
		# Filter to id and e-mail fields - all others should be considered internal
		$fields = array ('id', 'email');
		if ($this->settings['usernames']) {$fields[] = 'username';}	// Add username if enabled
		if ($this->settings['privileges']) {$fields[] = 'privileges';}	// Add privileges if enabled
		$userFiltered = array ();
		foreach ($fields as $field) {
			$userFiltered[$field] = $user[$field];
		}
		
		# Return the user
		return $userFiltered;
	}
	
	
	# Verify the password - basically a wrapper to password_verify with support for hashes stored as legacy hash(sha512) or manually-salted crypt()
	private function passwordVerify ($suppliedPassword, $user)
	{
		# Verify according to the type of hash in the database
		switch (true) {
			
			# Legacy manually-salted crypt(); currently only 13-character CRYPT_STD_DES hashes supported
			case ((strlen ($user['password']) == 13) && (substr ($user['password'], 0, 2) == substr ($this->settings['salt'], 0, 2)) && (!preg_match ('/^\$\w{2}\$/', $user['password']))):
				$suppliedPasswordHashed = crypt ($suppliedPassword, $this->settings['salt']);
				$correct = ($suppliedPasswordHashed == $user['password']);
				break;
				
			# Legacy hash(sha512) hash; see http://stackoverflow.com/questions/20841766/
			case (!preg_match ('/^\$\w{2}\$/', $user['password'])):
				$suppliedPasswordHashed = hash ('sha512', $this->settings['salt'] . $user['email'] . $suppliedPassword);	// http://phpsec.org/articles/2005/password-hashing.html ; note that supplying the e-mail as well makes the salt more complex and therefore means that two users with the same password will have different hashes
				$correct = ($suppliedPasswordHashed == $user['password']);
				break;
				
			# Modern password_verify (wrapper to crypt)
			default:
				$correct = password_verify ($suppliedPassword, $user['password']);
		}
		
		# Return false if authentication failed
		if (!$correct) {return false;}
		
		# Rehash if required
		if (password_needs_rehash ($user['password'], PASSWORD_DEFAULT)) {
			$newHash = password_hash ($suppliedPassword, PASSWORD_DEFAULT);
			$update = array ('password' => $newHash);
			$this->databaseConnection->update ($this->settings['database'], $this->settings['table'], $update, array ('id' => $user['id']));
		}
		
		# Confirm a successful match
		return true;
	}
	
	
	# Page to change account details
	public function accountdetails ()
	{
		# Start the HTML
		$html  = '';
		
		# Ensure the user is logged in
		if (!$userId = $this->getUserId ()) {
			$html  = "\n" . '<p>You must <a href="' . $this->baseUrl . $this->settings['loginUrl'] . '?' . $this->baseUrl . $this->settings['pageAccountdetails'] . '">' . $this->settings['loginText'] . '</a> first, if you wish to change account details.</p>';
			$this->html .= $html;
			return false;
		}
		
		# Get the initial details of the current user
		$userEmail = $this->getUserEmail ();
		$userUsername = $this->getUserUsername ();
		
		# Define an introduction to the form
		$introductionHtml = "\n<p>If you wish to change any of your account details, enter the changes below.</p>";
		
		# Show the form
		require_once ('ultimateForm.php');
		$form = new form (array (
			'displayRestrictions' 	=> false,
			'formCompleteText' 	=> false,
			'div' => 'accountdetails ultimateform horizontalonly',
			'unsavedDataProtection' => true,
			'reappear' => true,
		));
		$form->email (array (
			'name'			=> 'email',
			'title'			=> 'E-mail address',
			'size'			=> 50,
			'default'		=> $userEmail,
			'required'		=> true,
			'editable'		=> false,
		));
		if ($this->settings['usernames']) {
			$form->input (array (
				'name'			=> 'username',
				'title'			=> 'Username',
				'required'		=> true,
				'default'		=> $userUsername,
				'maxlength'		=> 30,
				'size'			=> 20,
				'regexp'		=> $this->settings['usernameRegexp'],
				'description'	=> $this->settings['usernameRegexpDescription'],
			));
		}
		$form->password (array (
			'name'			=> 'newpassword',		/* Non-standard name avoids browser auto-filling */
			'title'			=> 'Change password',
			'confirmation'	=> true,
		));
		$form->password (array ( 
			'name'			=> 'currentpassword',
			'title'			=> 'Your current password, to make changes',
			'description'	=> '<strong>Please enter your current password, for security, to make changes above.</strong>',
			'required'		=> true,
			'size'			=> 20,
			'maxlength'		=> 128,
			'discard'		=> true,
		));
		
		# Do checks on the submitted data
		if ($unfinalisedData = $form->getUnfinalisedData ()) {
			
			# Authenticate the account
			if (strlen ($unfinalisedData['currentpassword'])) {
				if (!$accountDetails = $this->getValidatedUser ($userEmail, $unfinalisedData['currentpassword'])) {
					$form->registerProblem ('failure', 'The current password you provided was not correct. Please correct it and try again.', 'password');
				}
			}
			
			# If a new username is proposed, check its availability
			if ($this->settings['usernames']) {
				if (strlen ($unfinalisedData['username'])) {
					if ($unfinalisedData['username'] != $userUsername) {
						$match = array ('username' => $unfinalisedData['username']);
						if ($this->databaseConnection->selectOne ($this->settings['database'], $this->settings['table'], $match)) {
							$form->registerProblem ('emailfailure', 'The username <em>' . htmlspecialchars ($unfinalisedData['username']) . '</em> has been taken already - please choose another.');
						}
					}
				}
			}
		}
		
		# Process the form
		if (!$result = $form->process ($html)) {
			$html = $introductionHtml . $html;
			$this->html .= $html;
			return false;
		}
		
		# Determine what is to be updated
		$updates = array ();
		if ($this->settings['usernames']) {
			if (strlen ($result['username'])) {
				$updates['username'] = $result['username'];
			}
		}
		if (strlen ($result['newpassword'])) {
			$updates['password'] = password_hash ($result['newpassword'], PASSWORD_DEFAULT);;
		}
		
		# End if no updates
		if (!$updates) {
			$this->html .= $html;
			return;
		}
		
		# Perform the update
		if (!$this->databaseConnection->update ($this->settings['database'], $this->settings['table'], $updates, $conditions = array ('id' => $userId))) {
			$html = "\n<p>The details were not changed, as a problem occured. Please contact the Webmaster.</p>";
			$this->html = $html;
			return;
		}
		
		# Make the new name usable straight away
		if ($this->settings['usernames']) {
			if (isSet ($updates['username'])) {
				$_SESSION[$this->settings['namespace']]['username'] = $result['username'];
			}
		}
		
		# Confirm success, prepending this to the HTML
		$confirmationHtml .= "\n" . '<div class="graybox">';
		$confirmationHtml .= "\n\t" . '<p><img src="/images/icons/tick.png" /> <strong>Your profile details have been updated.</strong></p>';
		$confirmationHtml .= "\n" . '</div>';
		$html = $confirmationHtml . $html;
		
		# Register the HTML
		$this->html .= $html;
	}
}

?>