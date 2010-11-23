<?php defined('SYSPATH') OR die('No direct access allowed.');

return array
(
    'default' => array(
        // user model name without model prefix, 'user' by default (if NULL set or not set at all)
        // if need autologin, create $config['model_name'].'_token' model class that extends Model_Rauth_Token
        'model_name'    =>  NULL,
        // function name to hash password
        'hash_method'   =>  'sha1',
        // salt pattern
        'salt_pattern'  =>  '1, 3, 5, 9, 14, 15, 20, 21, 28, 30',
        // session lifetime
        'lifetime'      =>  1209600,
        // session key name
        'session_key'   =>  'rauth_user',
        // autologin cookie name
        'autologin_cookie' =>  'rauthautologin',
        // should user be checked from DB, set TRUE for better security, but that adds DB load
        'strong_check'  =>  FALSE,
        ),    
);
