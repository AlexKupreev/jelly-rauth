<?php defined('SYSPATH') OR die('No direct access allowed.');
/**
 * User authorization library. Handles user login and logout, as well as secure password hashing.
 * Based on Kohana Auth library and its Jelly-Auth driver without role handling and 'is_active' property instead.
 * Allows to set up a number of independent auth profiles with different settings (like salt, hashing etc)
 * Uses Jelly modelling system
 *
 * @package rAuth
 * @uses    Jelly
 * @author  Kohana Team
 * @author  Israel Canasa
 * @author  Alexander Kupreyeu (Kupreev) alexander.kupreev@gmail.com      
 */
class Kohana_Rauth {

    // Auth instances
    protected static $instances = array();

    /**
     * rAuth singleton
     *
     * @return rAuth
     */
    public static function instance($config_entry = NULL)
    {
        if ( ! $config_entry)
        {
            $config_entry = 'default';
        }
        
        if ( ! isset(Rauth::$instances[$config_entry]))
        {
            // Load the configuration for this type
            $config = Kohana::config('rauth.'.$config_entry);
            
            $config['entry'] = $config_entry;

            // Create a new rauth instance
            Rauth::$instances[$config_entry] = new Rauth($config);

        }

        return Rauth::$instances[$config_entry];
    }

    /**
     * Create an instance of Rauth.
     *
     * @return  rAuth
     */
    public static function factory($config = array())
    {
        return new Rauth($config);
    }

    protected $session;

    protected $config;
    
    /**
     * Loads Session and configuration options.
     *
     * @return  void
     */
    public function __construct($config = array())
    {
        // Clean up the salt pattern and split it into an array
        $config['salt_pattern'] = preg_split('/,\s*/', $config['salt_pattern']); 
        
        // Check model name: it should be string and should not contain the model prefix
        if (isset($config['model_name']) AND is_string($config['model_name']))
        {
            $config['model_name'] = str_ireplace('model_', '', strtolower($config['model_name']));
        }
        else
        {
            $config['model_name'] = 'user';
        }

        // Save the config in the object
        $this->config = $config;
        
        // Set token model name and check model existence
        $this->config['token_model_name'] = $this->config['model_name'].'_token';
        $model_class = Jelly::model_prefix().$this->config['token_model_name'];
        
        if ($this->config['autologin_cookie'] AND ! class_exists($model_class))
        {
            throw new Kohana_Exception ('Could not find token model class :name', 
                array(':name' => $model_class));
        }
        
        $this->session = Session::instance();
    }

    /**
     * Logs a user in.
     *
     * @param   string   username
     * @param   string   password
     * @param   boolean  enable auto-login
     * @return  boolean
     */
    public function _login($user, $password, $remember)
    {
        // Make sure we have a user object
        $user = $this->_get_object($user);
        
        // If the passwords match, perform a login
        if ($user->is_active AND $user->password === $password)
        {
            
            if ($remember === TRUE AND $this->config['autologin_cookie'])
            {
                // Create a new autologin token
                $token = Model::factory($this->config['token_model_name']);

                // Set token data
                $token->user = $user->id;
                $token->expires = time() + $this->config['lifetime'];

                $token->create();

                // Set the autologin Cookie
                Cookie::set($this->config['autologin_cookie'], $token->token, $this->config['lifetime']);
            }

            // Finish the login
            $this->complete_login($user);

            return TRUE;
        }

        // Login failed
        return FALSE;
    }

    /**
     * Get the stored password for a username.
     *
     * @param   mixed   $user   username
     * @return  string
     */
    public function password($user)
    {
        // Make sure we have a user object
        $user = $this->_get_object($user);
        
        return $user->password;
    }

    /**
     * Gets the currently logged in user from the session.
     * Returns FALSE if no user is currently logged in.
     *
     * @return  mixed
     */
    public function get_user()
    {
        if ($this->logged_in())
        {
            return $this->session->get($this->config['session_key']);
        }

        return FALSE;
    }
    
    /**
     * Convert a unique identifier string to a user object
     * 
     * @param mixed $user
     * @param   bool    $strong_check   TRUE to force checking existence in DB 
     * @return Model_User
     */
    protected function _get_object($user, $strong_check = FALSE)
    {
        $name = $this->config['entry'];
        static $current;

        //make sure the user is loaded only once.
        if ( ! is_object($current[$name]) AND is_string($user))
        {
            // Load the user
            $current[$name] = Jelly::select($this->config['model_name'])
                ->where('username', '=', $user)
                ->limit(1)
                ->execute();
        }
        
        if (is_object($user) AND is_subclass_of($user, 'Model_Rauth_User') AND $user->loaded()) 
        {
            if ($strong_check)
            {
                $current[$name] = Jelly::select($this->config['model_name'])
                    ->where('id', '=', $user->id)
                    ->where('username', '=', $user->username)
                    ->limit(1)
                    ->execute();
            }
            else
            {
                $current[$name] = $user;
            }            
        }

        return $current[$name];
    }


    /**
     * Attempt to log in a user by using an ORM object and plain-text password.
     *
     * @param   string   username to log in
     * @param   string   password to check against
     * @param   boolean  enable auto-login
     * @return  boolean
     */
    public function login($username, $password, $remember = FALSE)
    {
	if (empty($password))
            return FALSE;

	if (is_string($password))
	{
            // Get the salt from the stored password
            $salt = $this->find_salt($this->password($username));

            // Create a hashed password using the salt from the stored password
            $password = $this->hash_password($password, $salt);
	}

	return $this->_login($username, $password, $remember);
    }
    
    /**
     * Logs a user in, based on the rauth autologin Cookie.
     *
     * @return  boolean
     */
    public function auto_login()
    {
        if ($token = Cookie::get($this->config['autologin_cookie']))
        {
            // Load the token and user
            $token = Jelly::select($this->config['token_model_name'])
                    ->where('token', '=', $token)
                    ->limit(1)
                    ->execute();
            
            if ($token->loaded() AND $token->user->loaded())
            {
                if ($token->expires >= time() AND $token->user_agent === sha1(Request::$user_agent))
                {
                    // Save the token to create a new unique token
                    $token->update();

                    // Set the new token
                    Cookie::set($this->config['autologin_cookie'], $token->token, $token->expires - time());

                    // Complete the login with the found data
                    $this->complete_login($token->user);

                    // Automatic login was successful
                    return TRUE;
                }

                // Token is invalid
                $token->delete();
            }
        }

        return FALSE;
    }


    /**
     * Log out a user by removing the related session variables.
     *
     * @param   boolean  completely destroy the session
     * @param	boolean  remove all tokens for user
     * @return  boolean
     */
    public function logout($destroy = FALSE, $logout_all = FALSE)
    {
	if ($token = Cookie::get($this->config['autologin_cookie']))
        {
            // Delete the autologin Cookie to prevent re-login
            Cookie::delete($this->config['autologin_cookie']);
            
            // Clear the autologin token from the database
            $token = Jelly::select($this->config['token_model_name'])
                    ->where('token', '=', $token)
                    ->limit(1)
                    ->execute();

            if ($token->loaded() AND $logout_all)
            {
                Jelly::delete($this->config['token_model_name'])
                        ->where('user_id', '=' ,$token->user->id)
                        ->execute();
            }
            elseif ($token->loaded())
            {
                $token->delete();
            }
        }
        
        if ($destroy === TRUE)
    	{
            // Destroy the session completely
            $this->session->destroy();
	}
	else
	{
            // Remove the user from the session
            $this->session->delete($this->config['session_key']);

            // Regenerate session_id
            $this->session->regenerate();
	}

	// Double check
	return ! $this->logged_in();
    }

    /**
     * Checks if a session is active.
     *
     * @return  boolean
     */
    public function logged_in()
    {
        $status = FALSE;
                  
        // Get the user from the session
        $user = $this->session->get($this->config['session_key']);
        
        if ( ! is_object($user))
        {
            // Attempt auto login
            if ($this->auto_login())
            {
                // Success, get the user back out of the session
                $user = $this->session->get($this->config['session_key']);
            }
        }
        
        // check from DB if set in config
        if ($this->config['strong_check'])
        {
            $user = $this->_get_object($user, TRUE);
        }
    
        if (is_object($user) 
            AND is_subclass_of($user, 'Model_Rauth_User') 
            AND $user->loaded()
            AND $user->is_active
            )
        {
            // Everything is okay so far
            $status = TRUE;

        }

        return $status;
    }         

    /**
     * Creates a hashed password from a plaintext password, inserting salt
     * based on the configured salt pattern.
     *
     * @param   string  plaintext password
     * @return  string  hashed password string
     */
    public function hash_password($password, $salt = FALSE)
    {
	if ($salt === FALSE)
	{
            // Create a salt seed, same length as the number of offsets in the pattern
            $salt = substr($this->hash(uniqid(NULL, TRUE)), 0, count($this->config['salt_pattern']));
	}

	// Password hash that the salt will be inserted into
	$hash = $this->hash($salt.$password);

	// Change salt to an array
	$salt = str_split($salt, 1);

	// Returned password
	$password = '';

	// Used to calculate the length of splits
	$last_offset = 0;

	foreach ($this->config['salt_pattern'] as $offset)
	{
            // Split a new part of the hash off
            $part = substr($hash, 0, $offset - $last_offset);

            // Cut the current part out of the hash
            $hash = substr($hash, $offset - $last_offset);

            // Add the part to the password, appending the salt character
            $password .= $part.array_shift($salt);

            // Set the last offset to the current offset
            $last_offset = $offset;
	}

	// Return the password, with the remaining hash appended
	return $password.$hash;
    }

    /**
     * Perform a hash, using the configured method.
     *
     * @param   string  string to hash
     * @return  string
     */
    public function hash($str)
    {
	return hash($this->config['hash_method'], $str);
    }

    /**
     * Finds the salt from a password, based on the configured salt pattern.
     *
     * @param   string  hashed password
     * @return  string
     */
    public function find_salt($password)
    {
	$salt = '';

	foreach ($this->config['salt_pattern'] as $i => $offset)
    	{
            // Find salt characters, take a good long look...
            $salt .= substr($password, $offset + $i, 1);
	}

	return $salt;
    }

    /**
     * Complete the login for a user by incrementing the logins and setting
     * session data: user_id, username, roles
     *
     * @param   object   user model object
     * @return  void
     */
    protected function complete_login($user)
    {
    	// Update the number of logins
        $user->logins += 1;

        // Set the last login date
        $user->last_login = time();

        // Save the user
        $user->save();

        // Regenerate session_id
	$this->session->regenerate();

	// Store username in session
	$this->session->set($this->config['session_key'], $user);

	return TRUE;
    }

} // End rAuth