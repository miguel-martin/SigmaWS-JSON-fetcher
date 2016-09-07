<?php


/*
 * FIXME dirty-way to store vars without DB.
 */
global $configuracion;

/*
 * Override Drupal variable_set
 */
function variable_set($name, $value) {
  $configuracion[$name] = $value;
}


/*
 **  FIXME
 */
function variable_get($name){
  if (isset($configuracion[$name])){
    return $configuracion[$name];
  }
  else{
    return null;
  }
}




function _drupal_parse_response_status($response) {
  $response_array = explode(' ', trim($response), 3);
  // Set up empty values.
  $result = array(
    'reason_phrase' => '',
  );
  $result['http_version'] = $response_array[0];
  $result['response_code'] = $response_array[1];
  if (isset($response_array[2])) {
    $result['reason_phrase'] = $response_array[2];
  }
  return $result;
}



function timer_start($name) {
  global $timers;

  $timers[$name]['start'] = microtime(TRUE);
  $timers[$name]['count'] = isset($timers[$name]['count']) ? ++$timers[$name]['count'] : 1;
}

function timer_read($name) {
  global $timers;

  if (isset($timers[$name]['start'])) {
    $stop = microtime(TRUE);
    $diff = round(($stop - $timers[$name]['start']) * 1000, 2);

    if (isset($timers[$name]['time'])) {
      $diff += $timers[$name]['time'];
    }
    return $diff;
  }
  return $timers[$name]['time'];
}




function drupal_http_request($url, array $options = array()) {
  // Allow an alternate HTTP client library to replace Drupal's default
  // implementation.
  $override_function = variable_get('drupal_http_request_function', FALSE);
  if (!empty($override_function) && function_exists($override_function)) {
    return $override_function($url, $options);
  }

  $result = new stdClass();

  // Parse the URL and make sure we can handle the schema.
  $uri = @parse_url($url);

  if ($uri == FALSE) {
    $result->error = 'unable to parse URL';
    $result->code = -1001;
    return $result;
  }

  if (!isset($uri['scheme'])) {
    $result->error = 'missing schema';
    $result->code = -1002;
    return $result;
  }

  timer_start(__FUNCTION__);

  // Merge the default options.
  $options += array(
    'headers' => array(),
    'method' => 'GET',
    'data' => NULL,
    'max_redirects' => 3,
    'timeout' => 30.0,
    'context' => NULL,
  );

  // Merge the default headers.
  $options['headers'] += array(
    'User-Agent' => 'Drupal (+http://drupal.org/)',
  );

  // stream_socket_client() requires timeout to be a float.
  $options['timeout'] = (float) $options['timeout'];

  // Use a proxy if one is defined and the host is not on the excluded list.
  $proxy_server = variable_get('proxy_server', '');
  if ($proxy_server && _drupal_http_use_proxy($uri['host'])) {
    // Set the scheme so we open a socket to the proxy server.
    $uri['scheme'] = 'proxy';
    // Set the path to be the full URL.
    $uri['path'] = $url;
    // Since the URL is passed as the path, we won't use the parsed query.
    unset($uri['query']);

    // Add in username and password to Proxy-Authorization header if needed.
    if ($proxy_username = variable_get('proxy_username', '')) {
      $proxy_password = variable_get('proxy_password', '');
      $options['headers']['Proxy-Authorization'] = 'Basic ' . base64_encode($proxy_username . (!empty($proxy_password) ? ":" . $proxy_password : ''));
    }
    // Some proxies reject requests with any User-Agent headers, while others
    // require a specific one.
    $proxy_user_agent = variable_get('proxy_user_agent', '');
    // The default value matches neither condition.
    if ($proxy_user_agent === NULL) {
      unset($options['headers']['User-Agent']);
    }
    elseif ($proxy_user_agent) {
      $options['headers']['User-Agent'] = $proxy_user_agent;
    }
  }

  switch ($uri['scheme']) {
    case 'proxy':
      // Make the socket connection to a proxy server.
      $socket = 'tcp://' . $proxy_server . ':' . variable_get('proxy_port', 8080);
      // The Host header still needs to match the real request.
      $options['headers']['Host'] = $uri['host'];
      $options['headers']['Host'] .= isset($uri['port']) && $uri['port'] != 80 ? ':' . $uri['port'] : '';
      break;

    case 'http':
    case 'feed':
      $port = isset($uri['port']) ? $uri['port'] : 80;
      $socket = 'tcp://' . $uri['host'] . ':' . $port;
      // RFC 2616: "non-standard ports MUST, default ports MAY be included".
      // We don't add the standard port to prevent from breaking rewrite rules
      // checking the host that do not take into account the port number.
      $options['headers']['Host'] = $uri['host'] . ($port != 80 ? ':' . $port : '');
      break;

    case 'https':
      // Note: Only works when PHP is compiled with OpenSSL support.
      $port = isset($uri['port']) ? $uri['port'] : 443;
      $socket = 'ssl://' . $uri['host'] . ':' . $port;
      $options['headers']['Host'] = $uri['host'] . ($port != 443 ? ':' . $port : '');
      break;

    default:
      $result->error = 'invalid schema ' . $uri['scheme'];
      $result->code = -1003;
      return $result;
  }

  if (empty($options['context'])) {
    $fp = @stream_socket_client($socket, $errno, $errstr, $options['timeout']);
  }
  else {
    // Create a stream with context. Allows verification of a SSL certificate.
    $fp = @stream_socket_client($socket, $errno, $errstr, $options['timeout'], STREAM_CLIENT_CONNECT, $options['context']);
  }

  // Make sure the socket opened properly.
  if (!$fp) {
    // When a network error occurs, we use a negative number so it does not
    // clash with the HTTP status codes.
    $result->code = -$errno;
    $result->error = trim($errstr) ? trim($errstr) : t('Error opening socket @socket', array('@socket' => $socket));

    // Mark that this request failed. This will trigger a check of the web
    // server's ability to make outgoing HTTP requests the next time that
    // requirements checking is performed.
    // See system_requirements().
    variable_set('drupal_http_request_fails', TRUE);

    return $result;
  }

  // Construct the path to act on.
  $path = isset($uri['path']) ? $uri['path'] : '/';
  if (isset($uri['query'])) {
    $path .= '?' . $uri['query'];
  }

  // Only add Content-Length if we actually have any content or if it is a POST
  // or PUT request. Some non-standard servers get confused by Content-Length in
  // at least HEAD/GET requests, and Squid always requires Content-Length in
  // POST/PUT requests.
  $content_length = strlen($options['data']);
  if ($content_length > 0 || $options['method'] == 'POST' || $options['method'] == 'PUT') {
    $options['headers']['Content-Length'] = $content_length;
  }

  // If the server URL has a user then attempt to use basic authentication.
  if (isset($uri['user'])) {
    $options['headers']['Authorization'] = 'Basic ' . base64_encode($uri['user'] . (isset($uri['pass']) ? ':' . $uri['pass'] : ':'));
  }

  // If the database prefix is being used by SimpleTest to run the tests in a copied
  // database then set the user-agent header to the database prefix so that any
  // calls to other Drupal pages will run the SimpleTest prefixed database. The
  // user-agent is used to ensure that multiple testing sessions running at the
  // same time won't interfere with each other as they would if the database
  // prefix were stored statically in a file or database variable.
  $test_info = &$GLOBALS['drupal_test_info'];
  if (!empty($test_info['test_run_id'])) {
    $options['headers']['User-Agent'] = drupal_generate_test_ua($test_info['test_run_id']);
  }

  $request = $options['method'] . ' ' . $path . " HTTP/1.0\r\n";
  foreach ($options['headers'] as $name => $value) {
    $request .= $name . ': ' . trim($value) . "\r\n";
  }
  $request .= "\r\n" . $options['data'];
  $result->request = $request;
  // Calculate how much time is left of the original timeout value.
  // FIXME MIGUEL
  $timeout = $options['timeout'] - timer_read(__FUNCTION__) / 1000;
  //$timeout = 0;

  if ($timeout > 0) {
    stream_set_timeout($fp, floor($timeout), floor(1000000 * fmod($timeout, 1)));
    fwrite($fp, $request);
  }

  // Fetch response. Due to PHP bugs like http://bugs.php.net/bug.php?id=43782
  // and http://bugs.php.net/bug.php?id=46049 we can't rely on feof(), but
  // instead must invoke stream_get_meta_data() each iteration.
  $info = stream_get_meta_data($fp);
  $alive = !$info['eof'] && !$info['timed_out'];
  $response = '';

  while ($alive) {
    // Calculate how much time is left of the original timeout value.
    // FIXME
    $timeout = $options['timeout'] - timer_read(__FUNCTION__) / 1000;
    //$timeout = 0;
    if ($timeout <= 0) {
      $info['timed_out'] = TRUE;
      break;
    }
    stream_set_timeout($fp, floor($timeout), floor(1000000 * fmod($timeout, 1)));
    $chunk = fread($fp, 1024);
    $response .= $chunk;
    $info = stream_get_meta_data($fp);
    $alive = !$info['eof'] && !$info['timed_out'] && $chunk;
  }
  fclose($fp);

  if ($info['timed_out']) {
    $result->code = HTTP_REQUEST_TIMEOUT;
    $result->error = 'request timed out';
    return $result;
  }
  // Parse response headers from the response body.
  // Be tolerant of malformed HTTP responses that separate header and body with
  // \n\n or \r\r instead of \r\n\r\n.
  list($response, $result->data) = preg_split("/\r\n\r\n|\n\n|\r\r/", $response, 2);
  $response = preg_split("/\r\n|\n|\r/", $response);

  // Parse the response status line.
  $response_status_array = _drupal_parse_response_status(trim(array_shift($response)));
  $result->protocol = $response_status_array['http_version'];
  $result->status_message = $response_status_array['reason_phrase'];
  $code = $response_status_array['response_code'];

  $result->headers = array();

  // Parse the response headers.
  while ($line = trim(array_shift($response))) {
    list($name, $value) = explode(':', $line, 2);
    $name = strtolower($name);
    if (isset($result->headers[$name]) && $name == 'set-cookie') {
      // RFC 2109: the Set-Cookie response header comprises the token Set-
      // Cookie:, followed by a comma-separated list of one or more cookies.
      $result->headers[$name] .= ',' . trim($value);
    }
    else {
      $result->headers[$name] = trim($value);
    }
  }

  $responses = array(
    100 => 'Continue',
    101 => 'Switching Protocols',
    200 => 'OK',
    201 => 'Created',
    202 => 'Accepted',
    203 => 'Non-Authoritative Information',
    204 => 'No Content',
    205 => 'Reset Content',
    206 => 'Partial Content',
    300 => 'Multiple Choices',
    301 => 'Moved Permanently',
    302 => 'Found',
    303 => 'See Other',
    304 => 'Not Modified',
    305 => 'Use Proxy',
    307 => 'Temporary Redirect',
    400 => 'Bad Request',
    401 => 'Unauthorized',
    402 => 'Payment Required',
    403 => 'Forbidden',
    404 => 'Not Found',
    405 => 'Method Not Allowed',
    406 => 'Not Acceptable',
    407 => 'Proxy Authentication Required',
    408 => 'Request Time-out',
    409 => 'Conflict',
    410 => 'Gone',
    411 => 'Length Required',
    412 => 'Precondition Failed',
    413 => 'Request Entity Too Large',
    414 => 'Request-URI Too Large',
    415 => 'Unsupported Media Type',
    416 => 'Requested range not satisfiable',
    417 => 'Expectation Failed',
    500 => 'Internal Server Error',
    501 => 'Not Implemented',
    502 => 'Bad Gateway',
    503 => 'Service Unavailable',
    504 => 'Gateway Time-out',
    505 => 'HTTP Version not supported',
  );
  // RFC 2616 states that all unknown HTTP codes must be treated the same as the
  // base code in their class.
  if (!isset($responses[$code])) {
    $code = floor($code / 100) * 100;
  }
  $result->code = $code;

  switch ($code) {
    case 200: // OK
    case 201: // Created
    case 202: // Accepted
    case 203: // Non-Authoritative Information
    case 204: // No Content
    case 205: // Reset Content
    case 206: // Partial Content
    case 304: // Not modified
      break;
    case 301: // Moved permanently
    case 302: // Moved temporarily
    case 307: // Moved temporarily
      $location = $result->headers['location'];
      $options['timeout'] -= timer_read(__FUNCTION__) / 1000;
      if ($options['timeout'] <= 0) {
        $result->code = HTTP_REQUEST_TIMEOUT;
        $result->error = 'request timed out';
      }
      elseif ($options['max_redirects']) {
        // Redirect to the new location.
        $options['max_redirects']--;
        $result = drupal_http_request($location, $options);
        $result->redirect_code = $code;
      }
      if (!isset($result->redirect_url)) {
        $result->redirect_url = $location;
      }
      break;
    default:
      $result->error = $result->status_message;
  }

  return $result;
}


class SigmaHttpWS {
  protected $url;
  protected $oauth_parameters;
  protected $migrateID;
  protected $sigmaws_shared_secret;

  public function __construct($url, $migrateID, $params = array()) {
    $this->url = $url;
    $this->migrateID = $migrateID;
    // This should go on a static class
    $this->sigmaws_shared_secret = 'abc123';
    if (empty($params)) {
      $this->oauth_parameters['oauth_consumer_key'] = 'nosevalida';
      $this->oauth_parameters['oauth_nonce'] = 'randomquenoserepitapormilisegundo';
      $this->oauth_parameters['oauth_signature_method'] = 'HMAC-SHA1';
      $this->oauth_parameters['oauth_timestamp'] = time();
    } else {
      $this->oauth_parameters = $params;
    }
    $this->oauth_parameters['oauth_signature'] = $this->generate_oauth_signature();
  }

  public function make_request() {
    $http_headers = $this->get_request_header();
    $response = drupal_http_request($this->url, array('headers' => $http_headers));
    return $response;
  }

  public function process_request($response) {
    if (isset($response->headers['etag'])) {
      print("SIGMA ETAG: ".$response->headers['etag']);
      variable_set('sigmaws_etag_' . $this->migrateID, $response->headers['etag']);
    }
    if ($response->code == '304') {
      // No changes!
      $json_data = json_encode(array());
    } elseif ($response->code != '304' && $response->code != '200') {
      // Posibly an error, lets log it.
      // MIGUEL FIXME
      echo ("HTTP code not expected: ".$response->code);
      /*Migration::displayMessage(
        t('HTTP code not expected: !code - !error',
          array(
            '!code' => $response->code,
            '!error' => $response->error,
          )
        )
      );*/
      // No changes!
      $json_data = json_encode(array());
    } elseif ($response->data) {
      $json_data = $response->data;
    }

    return $json_data;
  }

  public function get_request_header() {
    $http_headers['identificacion'] = 'Oauth';
    $http_headers['Authorization'] = $this->get_oauth_header();
    $http_etag = '';
    if ($http_etag) {
      // ToDo. Enable etag
      // $http_headers['If-None-Match'] = $http_etag;
    }
    return $http_headers;
  }

  public function get_oauth_header() {
    $oauth_header = 'OAuth';
    foreach ($this->oauth_parameters as $key => $value) {
      $oauth_header .= ' ' . OAuthUtil::urlencode_rfc3986($key) . '="' . OAuthUtil::urlencode_rfc3986($value) . '",';
    }
    return rtrim($oauth_header, ",");
  }

  public function generate_oauth_signature() {
    $key = OAuthUtil::urlencode_rfc3986($this->sigmaws_shared_secret) . '&';
    $base_string = $this->get_oauth_signature_base_string();

    return base64_encode(hash_hmac('sha1', $base_string, $key, true));
  }

  public function get_oauth_signature_base_string() {
    $parts = array(
      'GET',
      $this->url,
      $this->get_signable_parameters(),
    );

    $parts = OAuthUtil::urlencode_rfc3986($parts);
    return implode('&', $parts);
  }

  public function get_signable_parameters() {
    // Grab all parameters
    $params = $this->oauth_parameters;

    // Remove oauth_signature if present
    if (isset($params['oauth_signature'])) {
      unset($params['oauth_signature']);
    }

    return OAuthUtil::build_http_query($params);
  }
}

/**
 * Oauth utils class
 */
class OAuthUtil {
  public static function urlencode_rfc3986($input) {
    if (is_array($input)) {
      return array_map(array('OAuthUtil', 'urlencode_rfc3986'), $input);
    } elseif (is_scalar($input)) {
      return rawurlencode($input);
    } else {
      return '';
    }
  }
  public static function build_http_query($params) {
    if (!$params) {
      return '';
    }

    // Urlencode both keys and values
    $keys = OAuthUtil::urlencode_rfc3986(array_keys($params));
    $values = OAuthUtil::urlencode_rfc3986(array_values($params));
    $params = array_combine($keys, $values);

    // Parameters are sorted by name, using lexicographical byte value ordering.
    uksort($params, 'strcmp');

    $pairs = array();
    foreach ($params as $parameter => $value) {
      $pairs[] = $parameter . '=' . $value;
    }

    // Each name-value pair is separated by an '&' character (ASCII code 38)
    return implode('&', $pairs);
  }
}


/**
 * Retrieve Sigma WS JSON Responses
 * Author: Carlos Sańchez <info@carletex.com>
 */
class SigmaJSONFetcher {
  public $id;

  public function __construct($id) {
    $this->id = $id;
  }

  /**
   * Copy the returned JSON from Sigma WS to the local system.
   */
  public function getSingleJSON($url, $dest_filename) {
    // MIGUEL FIXME
    //$data_folder = drupal_get_path('module', 'titulaciones_migration') . '/data';
    $data_folder = "./data";
    $data_file_destination = $data_folder . '/' . $dest_filename . '.json';

    $sigmaWS = new SigmaHttpWS($url, $this->id);
    $response = $sigmaWS->make_request();
    $json_data = $sigmaWS->process_request($response);


    if ($response->code == 200) {
      // Copy to local file
      if (!file_put_contents($data_file_destination, $json_data)) {
        // MIGUEL FIXME
        echo "Could not write JSON data file at '".$data_file_destination.'/'.$json_data."'";
        /*Migration::displayMessage(t('Could not write JSON data file at !file',
                                    array('!file' => $data_file_destination)));*/
      }
    }
    elseif ($response->code == 304) {
      // No changes in the file. We should stop Migrate to avoid reading the files
      // which while import nothing. Second option, empty file.
      $data_file_destination = $data_folder . '/empty.json';
    }
    else {
      echo "Something went wrong";
      /*Migration::displayMessage(t('Something went wrong in the request to !url',
                                  array('!url' => $url)));*/
    } 

    return $data_file_destination;
  }

  public function getPagedJSON($url, $dest_filename, $container) {
    $data_folder = drupal_get_path('module', 'titulaciones_migration') . '/data';
    $data_file_destination = $data_folder . '/' . $dest_filename . '-tmp.json';

    $pages = 0;
    $currentPage = 1;
    file_put_contents('', $data);
    do {
      $sigmaWS = new SigmaHttpWS($url . '/' . $currentPage, $this->id);
      $response = $sigmaWS->make_request();
      $data = $sigmaWS->process_request($response);
      $json_data = json_decode($data);

      if ($response->code == 200) {
        if (!$pages) {
          $pages = $json_data->paginasTotales;
        }

        $data = json_encode($json_data->$container);
        $data = ltrim($data, '[');
        $data = rtrim($data, ']');
        $data .= ',';
        if (!file_put_contents($data_file_destination, $data, FILE_APPEND | LOCK_EX)) {
           Migration::displayMessage(t('Could not write JSON data file at !file',
                                       array('!file' => $data_file_destination)));
        }
        $currentPage++;
      } 
      else {
        Migration::displayMessage(t('Something went wrong in the request to !url',
                                  array('!url' => $url)));
      }

    } while ($currentPage <= 2); // ToDo. $page

    $data = "[";
    $data .= rtrim(file_get_contents($data_file_destination), ',');
    $data .= "]";

    $data_file_destination = $data_folder . '/' . $dest_filename . '-real.json';
    file_put_contents($data_file_destination, $data);

    return $data_file_destination;
  }

  public function getIdsJSON($url, $dest_filename, $ids) {
    $data_folder = drupal_get_path('module', 'titulaciones_migration') . '/data';
    $data_file_destination = $data_folder . '/' . $dest_filename . '-tmp.json';

    file_put_contents('', $data);
    foreach ($ids as $id) {
      $sigmaWS = new SigmaHttpWS($url . '/' . $id, $this->id);
      $response = $sigmaWS->make_request();
      $data = $sigmaWS->process_request($response) . ',';

      if ($response->code == 200) {
        if (!file_put_contents($data_file_destination, $data, FILE_APPEND | LOCK_EX)) {
           Migration::displayMessage(t('Could not write JSON data file at !file',
                                       array('!file' => $data_file_destination)));
        }
      }
      else {
        Migration::displayMessage(t('Something went wrong in the request to !url',
                                  array('!url' => $url)));
      }
    }

    $data = "[";
    $data .= rtrim(file_get_contents($data_file_destination), ',');
    $data .= "]";

    $data_file_destination = $data_folder . '/' . $dest_filename . '-real.json';
    file_put_contents($data_file_destination, $data);
    
    return $data_file_destination;
  }

  public function getTimecheckJSON($url, $dest_filename, $ids) {

  }
}




date_default_timezone_set('UTC');

/*echo "Generando centros.json...\n";
$ws_url = "http://demo.sigmaaie.org/wsods/resources/titulaciones/2016/centros";
$ws_url_update = "http://demo.sigmaaie.org/wsods/resources/administracion/2016/cargarcentros";
echo "WARNING: Recuerde que para actualizar el ODS deben haberse hecho las llamadas necesarias a ".$ws_url_update;

$migrateID = 'CentrosMigration';
$fetcher = new SigmaJSONFetcher($migrateID);
$data = $fetcher->getSingleJSON($ws_url, 'centros');*/



echo "Generando asignaturas.json...\n";
echo date('l jS \of F Y h:i:s A');
$ws_url = "http://demo.sigmaaie.org/wsods/resources/titulaciones/2016/asignaturas";
$ws_url_update = "http://demo.sigmaaie.org/wsods/resources/administracion/2016/cargarasignaturas";
$migrateID = 'AsignaturasMigration';
for ($i=1; $i<=151; $i++){ // hay 151 páginas (ahora!)
    echo "\n Pagina ".$i;
    $fetcher = new SigmaJSONFetcher($migrateID);
    $data = $fetcher->getSingleJSON($ws_url.'/'.$i, 'asignaturas_'.$i);
}
echo "Proceso completado";
echo date('l jS \of F Y h:i:s A');


/*echo "Generando arbol.json...\n";
$ws_url = "http://demo.sigmaaie.org/wsods/resources/titulaciones/2016/estudios";
$ws_url_update = "http://demo.sigmaaie.org/wsods/resources/administracion/2016/cargararbol";
$migrateID = 'EstudiosMigration';
$fetcher = new SigmaJSONFetcher($migrateID);
$data = $fetcher->getSingleJSON($ws_url, 'arbol');*/


