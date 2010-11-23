# Jelly-rAuth

## What is it?
The Kohana 3 authentication library for [Jelly](http://github.com/jonathangeiger/kohana-jelly) modelling system. It is based on the strongly rebuilt [Jelly-Auth](https://github.com/raeldc/jelly-auth) driver by [raeldc](https://github.com/raeldc). 

**Main differences**

 * (Unfortunately) it is not a driver, but library. So it can't be easily ported for other ORMs (hope to do that in the future). 
 * Supports a number of independent 'access areas' (auth profiles) with different settings like salt, hashing etc.
 * Roles were eliminated (IMO they should be integrated in ACL)
 * Added property 'is\_active', that in some manner equivalent to 'login' role in Ko3 Auth
 * User validity can be checked in DB at every logged_in() call if needed.

## How can it be used?

**Basic way**
It is about using only one auth profile. Your user model will be Model\_User, feel free to enrich its functionality (copy it from *MODPATH/jelly-rauth/classes/model/user.php* to *APPPATH/jelly-rauth/classes/model/user.php* and extend).

 1. Be sure to plug-in Jelly modelling system in bootstrap.php
 2. Plug-in jelly-rauth module in bootstrap.php
 3. Tune *config/rauth.php* default profile for your needs
 4. Create the database structure, you cat take *jelly-rauth-schema.sql* as example (tokens table can be omitted if you do not use autologin)
 5. *Rauth::instance()* returns authentication object with default profile. Certainly you can use an arbitrary profile name 'some-profile-name', that case use *Rauth::instance('some-profile-name')*

**Advanced way**

Sometimes you feel some hesitancy when, for example, need admin password to be hashed strongly, and user password need not, or want to check admin in the database repeatedly, but for users it is not critical and can overload database. With Jelly-rAuth you can create different auth profiles, like independent 'restricted access areas' -- one for users and another for administrators, for example. 

 1. Be sure to plug-in Jelly modelling system in bootstrap.php
 2. Plug-in jelly-rauth module in bootstrap.php
 3. Go to *config/rauth.php* and set up profiles, like below. Please **be sure** to set different session keys and (if use) autologin cookies. 'model\_name' should be set without Jelly model prefix ('Model\_') 

        return array
        (
            'user' => array(
                // user model name without model prefix, 'user' by default
                'model_name'    =>  'user',
                'hash_method'   => 'md5',
                'salt_pattern'  => '1, 3, 6, 9, 12, 15', 
                'lifetime'      => 1209600,
                'session_key'   => 'rauth_user',
                // autologin cookie name
                'autologin_cookie'  =>  'user_autologin',
                // should user status be checked from DB at every instance, set TRUE for better security, but that adds load for DB too
                'strong_check'  =>  FALSE,
                ),
            'admin' => array(
                // user model name without model prefix, 'user' by default
                'model_name'    =>  'admin',
                'hash_method'   =>  'sha1',
                'salt_pattern'  =>  '2, 5, 8, 11, 14, 17, 20, 29', 
                'lifetime'      =>  1209600,
                'session_key'   =>  'rauth_admin',
                // autologin cookie name
                'autologin_cookie' =>  'admin_autologin',
                // should user status be checked from DB at every instance, set TRUE for better security, but that adds load for DB too
                'strong_check'  =>  TRUE,
                ),    
         );

 4. Create the database structure, you can take jelly-rauth-schema.sql as example. If want to use autologins, create a corresponding number of token tables, for our config they **should** be 'user\_tokens' and 'admin\_tokens', by model names. If change field names, be sure to modify corresponding Jelly models. 
 5. There should be a model extending *Model\_Rauth\_User* for every config entry. In our case, *Model\_User* is presented by default, you should manually create *Model\_Admin* (and adjust it to your needs) like

        class Model_Admin extends Model_Rauth_User
        {
            public static function initialize(Jelly_Meta $meta)
            {
                $meta->fields(array(
                   'email' => new Field_Email(array(
                       'label' => __('E-mail'),
                        )),
                    ));
        
                parent::initialize($meta);
            }
        }

 6. Tokens should also have their own models (named like *Model\_$config['model_name']\_Token*) extending *Model\_Rauth\_Token*. In our case, *Model\_User\_Token* is presented by default, we only need *Model\_Admin\_Token* like that (notice that field properties are modified to correspond our database schema)

        class Model_Admin_Token extends Model_Rauth_Token 
        {    
            public static function initialize(Jelly_Meta $meta)
            {
	        $meta->fields(array(
                    'user' => new Field_BelongsTo(array(
                        'foreign'   =>  'admin',
                        'column'    =>  'user_id', 
                        )),
                    ));
        
                parent::initialize($meta);
            }
        }

 7. *Rauth::instance('some-profile-name')* returns corresponding auth instance. For our example, we can use *Rauth::instance('user')* and *Rauth::instance('admin')* to work with corresponding authentication profiles. 

**Please provide feedback to make Jelly-rAuth better. Thank you!** 