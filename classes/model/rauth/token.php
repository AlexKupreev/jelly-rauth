<?php defined('SYSPATH') or die ('No direct script access.');
/**
 * Jelly rAuth User Token Model
 * @package Jelly rAuth
 * @author  Israel Canasa
 * @author  Alexander Kupreyeu (Kupreev) alexander.kupreev@gmail.com
 */
class Model_Rauth_Token extends Jelly_Model
{
    public static function initialize(Jelly_Meta $meta)
    {
	$meta->fields(array(
            'id' => new Field_Primary,
            'token' => new Field_String(array(
		'unique' => TRUE,
		'rules' => array(
                    'max_length' => array(32)
                    )
		)),
            'user' => new Field_BelongsTo,
            'user_agent' => new Field_String,
            'created' => new Field_Timestamp(array(
                'auto_now_create' => TRUE,
                )),
            'expires' => new Field_Timestamp,
            ));
	        
    }
    
    public function __construct() 
    {
        parent::__construct();
        
        if (mt_rand(1, 100) === 1)
        {
            // Do garbage collection
            Jelly::delete($this)->where('expires', '<', time())->execute();
        }
    }
	
    public function create()
    {		
	// Set hash of the user agent
	$this->user_agent = sha1(Request::$user_agent);

	// Create a new token each time the token is saved
	$this->token = $this->create_token();
		
	return parent::save();
    }
	
    public function update()
    {
	// Create a new token each time the token is saved
    	$this->token = $this->create_token();
		
	return parent::save();
    }

    /**
     * Finds a new unique token, using a loop to make sure that the token does
     * not already exist in the database. This could potentially become an
     * infinite loop, but the chances of that happening are very unlikely.
     *
     * @return  string
     */
    public function create_token()
    {
	while (TRUE)
	{
            // Create a random token
            $token = text::random('alnum', 32);

            // Make sure the token does not already exist
            if( ! Jelly::select($this)->where('token', '=', $token)->count())
            {
		// A unique token has been found
		return $token;
            }
	}
    }
} // End Model_rAuth_User_Token