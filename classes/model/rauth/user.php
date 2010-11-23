<?php defined('SYSPATH') or die ('No direct script access.');
/**
 * Jelly rAuth User Model
 * @package Jelly rAuth
 * @author  Israel Canasa
 * @author  Alexander Kupreyeu (Kupreev) alexander.kupreev@gmail.com   
 */
class Model_Rauth_User extends Jelly_Model
{
    public static function initialize(Jelly_Meta $meta)
    {
	$meta->name_key('username')
            ->sorting(array('username' => 'ASC'))
            ->fields(array(
		'id' => new Field_Primary,
		'username' => new Field_String(array(
                    'unique' => TRUE,
                    'rules' => array(
			'not_empty' => array(TRUE),
			'max_length' => array(32),
			'min_length' => array(3),
			'regex' => array('/^[\pL_.-]+$/ui')
			)
                    )),
		'password' => new Field_Password(array(
                    'hash_with' => array(Rauth::instance(), 'hash_password'),
                    'rules' => array(
			'not_empty' => array(TRUE),
			'max_length' => array(50),
			'min_length' => array(6)
			)
                    )),
		'password_confirm' => new Field_Password(array(
                    'in_db' => FALSE,
                    'callbacks' => array(
			'matches' => array('Model_Rauth_User', '_check_password_matches')
			),
                    'rules' => array(
			'not_empty' => array(TRUE),
			'max_length' => array(50),
			'min_length' => array(6)
			)
                    )),
		'email' => new Field_Email(array(
                    'unique' => TRUE,
                    'rules' => array(
                        'not_empty' => array(TRUE),
                        )
                    )),
                'is_active' => new Field_Boolean(array(
                    'default' => FALSE,
                    )),                  
		'logins' => new Field_Integer(array(
                    'default' => 0
                    )),
                'last_login' => new Field_Timestamp,
		'tokens' => new Field_HasMany(array(
                    'foreign' => 'ruser_token'
                    )),
		));
    }

    /**
     * Validate callback wrapper for checking password match
     * @param Validate $array
     * @param string   $field
     * @return void
     */
    public static function _check_password_matches(Validate $array, $field)
    {
        $auth = Rauth::instance();

        if ($array['password'] !== $array[$field])
        {
                // Re-use the error messge from the 'matches' rule in Validate
                $array->error($field, 'matches', array('param1' => 'password'));
        }
    }
	
} // End Model_rAuth_User