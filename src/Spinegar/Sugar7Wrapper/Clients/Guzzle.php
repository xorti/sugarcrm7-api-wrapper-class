<?php namespace Spinegar\Sugar7Wrapper\Clients;

use Guzzle\Common\Event;
use Guzzle\Http\Client;
use Guzzle\Http\Query;
use Guzzle\Http\Exception\ClientErrorResponseException;

/**
 * SugarCRM 7 Rest Client
 *
 * @package   SugarCRM 7 Rest Wrapper
 * @category  Libraries
 * @author  Sean Pinegar
 * @license MIT License
 * @link   https://github.com/spinegar/sugarcrm7-api-wrapper-class
 */

class Guzzle implements ClientInterface {

  /**
  * Variable: $url
  * Description:  A Sugar Instance. 
  */
  private $url;

  /**
  * Variable: $platform
  * Description:  SugarCRM client platform.
  */
  private $platform = 'api';

  /**
  * Variable: $username
  * Description:  A SugarCRM User. 
  */
  private $username;

  /**
  * Variable: $password
  * Description:  The password for the $username SugarCRM account
  */
  private $password;

  /**
  * Variable: $token
  * Description:  OAuth 2.0 token
  */
  protected $token;

  /**
   * Variable: $refresh_token
   * Description:  OAuth 2.0 refresh token
   */
  protected $refresh_token;

  /**
  * Variable: $client
  * Description:  Guzzle Client
  */
  protected $client;

  /**
  * Function: __construct()
  * Parameters:   none    
  * Description:  Construct Class
  * Returns:  VOID
  */
  function __construct()
  {
    $this->client = new Client();
  }

  /**
  * Function: __destruct()
  * Parameters:   none    
  */
  function __destruct(){}

  
  /**
  * Function: connect()
  * Parameters:   $refreshToken TRUE it will refresh the access token.
  *                             FALSE will use standard username/password authentication.
  * Description:  Authenticate and set the oAuth 2.0 token
  * Returns:  TRUE on login success, otherwise FALSE
  */
  public function connect($refreshToken = false)
  {
    if (!$refreshToken) {
      $parameters = array(
        'grant_type'    => 'password',
        'client_id'     => 'sugar',
        'client_secret' => '',
        'username'      => $this->username,
        'password'      => $this->password,
        'platform'      => $this->platform,
      );
    } else {
      $parameters = array(
        'grant_type'    => 'refresh_token',
        'client_id'     => 'sugar',
        'client_secret' => '',
        'refresh_token' => $this->refresh_token,
      );
    }

    $request = $this->client->post('oauth2/token', null, $parameters);

    $result = $request->send()->json();
   
    if(!$result['access_token'])
      return false;

    $token = $result['access_token'];
    self::setToken($token);

    $refreshToken = $result['refresh_token'];
    self::setRefreshToken($refreshToken);

    return true;
  }

  /**
   * Function: reconnect()
   * Parameters:   none
   * Description:  Re-establish a valid connection if token no longer valid.
   * Returns:  TRUE on connection success, otherwise FALSE
   */
  protected function reconnect() {

      if (!$this->check()) {
          return self::connect();
      }

      try{
          $request = $this->get('ping');
          $response = $request->send()->json();
      } catch (ClientErrorResponseException $e) {
          if ($e->getResponse()->getStatusCode() == 401) {
              return self::connect(true);
          }
      }
  }

  /**
  * Function: check()
  * Parameters:   none    
  * Description:  check if token is set
  * Returns:  TRUE on login success, otherwise FALSE
  */
  public function check()
  {
    if(!$this->token)
      return false;

    return true;
  }

  /**
  * Function: setClientOptions()
  * Parameters:   $key = Guzzle option, $value = Value  
  * Description:  Set Default options for the Guzzle client.
  * Returns:  returns FALSE is falsy, otherwise TRUE
  */
  public function setClientOption($key, $value)
  {
    if(!$key || $value)
      return false;

    $this->client->setDefaultOption($key, $value);

    return true;
  }

  /**
  * Function: setUrl()
  * Parameters:   $value = URL for the REST API    
  * Description:  Set $url
  * Returns:  returns FALSE is falsy, otherwise TRUE
  */
  public function setUrl($value)
  {
    if(!$value)
      return false;

    $this->url = $value;
    $this->client->setBaseUrl($this->url) ;

    return true;
  }

  /**
  * Function: getUrl()
  * Description:  Set $url
  * Returns:  returns a value if successful, otherwise FALSE
  */
  public function getUrl()
  {
    return $this->url;
  }

  /**
   * Function: setPlatform()
   * Parameters:   $value SugarCRM platform identifier
   * Description:  Set $platform
   * Returns:  returns FALSE is falsy, otherwise TRUE
   */
  public function setPlatform($value)
  {
    if(!$value)
      return false;

    $this->platform = $value;

    return true;
  }

  /**
   * Function: getPlatform()
   * Parameters:   none
   * Description:  Get $platform
   * Returns:  returns $platform value
   */
  public function getPlatform()
  {
    return $this->platform;
  }

  /**
  * Function: setUsername()
  * Parameters:   $value = Username for the REST API User    
  * Description:  Set $username
  * Returns:  returns FALSE is falsy, otherwise TRUE
  */
  public function setUsername($value)
  {
    if(!$value)
      return false;

    $this->username = $value;

    return true;
  }

  /**
  * Function: setPassword()
  * Parameters:   none    
  * Description:  Set $password
  * Returns:  returns FALSE is falsy, otherwise TRUE
  */
  public function setPassword($value)
  {
    if(!$value)
      return false;

    $this->password = $value;

    return true;
  }

  /**
   * Function: getToken()
   * Parameters:   none
   * Description:  Get $token
   * Returns:  returns token string
   */
  public function getToken()
  {
    return $this->token;
  }

  /**
  * Function: setToken()
  * Parameters:   none    
  * Description:  Set $token
  * Returns:  returns FALSE is falsy, otherwise TRUE
  */
  public function setToken($value)
  {
    if(!$value)
      return false;

    $this->token = $value;

    $this->client->getEventDispatcher()->addListener(
      'request.before_send',
      function (Event $event) use ($value) {
        $event['request']->setHeader('OAuth-Token', $value);
      }
    );

    return true;
  }

  /**
   * Function: getToken()
   * Parameters:   none
   * Description:  Get $token
   * Returns:  returns token string
   */
  public function getRefreshToken()
  {
    return $this->refresh_token;
  }

  /**
   * Function: setToken()
   * Parameters:   none
   * Description:  Set $token
   * Returns:  returns FALSE is falsy, otherwise TRUE
   */
  public function setRefreshToken($value)
  {
    if(!$value)
      return false;

    $this->refresh_token = $value;

    return true;
  }

  /**
  * Function: get()
  * Parameters: 
  *   $endpoint = endpoint per API specs
  *   $parameters = Parameters per API specs
  * Description:  Calls the API via HTTP GET
  * Returns:  Returns an Array if successful, otherwise FALSE
  */
  public function get($endpoint, $parameters = array())
  {
    self::reconnect();

    $request = $this->client->get($endpoint);

    $query = $request->getQuery();

    foreach($parameters as $key=>$value)
    {
      $query->add($key, $value);
    }

    $response = $request->send()->json();

    if(!$response)
      return false;

    return $response;
  }

  /**
  * Function: get()
  * Parameters: 
  *   $endpoint = endpoint per API specs
  *   $destinationFile = destination file including folders and file extension (e.g. /var/www/html/somefile.zip)
  *   $parameters = Parameters per API specs
  * Description:  Calls the API via HTTP GET
  * Returns:  Returns an Array if successful, otherwise FALSE
  */
  public function getFile($endpoint, $destinationFile, $parameters = array())
  {
    self::reconnect();

    $request = $this->client->get($endpoint);

    $query = $request->getQuery();

    foreach($parameters as $key=>$value)
    {
      $query->add($key, $value);
    }

    $request->setResponseBody($destinationFile);

    $response = $request->send();

    if(!$response)
      return false;

    return $response;
  }

  /**
  * Function: post()
  * Parameters: 
  *   $endpoint = endpoint per API specs
  *   $parameters = Parameters per API specs
  * Description:  Calls the API via HTTP POST
  * Returns:  Returns an Array if successful, otherwise FALSE
  */
  public function post($endpoint, $parameters = array())
  {
    self::reconnect();

    $request = $this->client->post($endpoint, null, json_encode($parameters));
    $response = $request->send()->json();

    if(!$response)
      return false;

    return $response;
  }
  
  /**
  * Function: put()
  * Parameters: 
  *   $endpoint = endpoint per API specs
  *   $parameters = Parameters per API specs
  * Description:  Calls the API via HTTP PUT
  * Returns:  Returns an Array if successful, otherwise FALSE
  */
  public function put($endpoint, $parameters = array())
  {
    self::reconnect();

    $request = $this->client->put($endpoint, null, json_encode($parameters));
    $response = $request->send()->json();

    if(!$response)
      return false;

    return $response;
  }

    /**
  * Function: delete()
  * Parameters: 
  *   $endpoint = endpoint per API specs
  * Description:  Calls the API via HTTP DELETE
  * Returns:  Returns an Array if successful, otherwise FALSE
  */
  public function delete($endpoint, $parameters = array())
  {
    self::reconnect();

    $request = $this->client->delete($endpoint);
    $response = $request->send()->json();


    if(!$response)
      return false;

    return $response;
  }
}
