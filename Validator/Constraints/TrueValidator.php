<?php

namespace EWZ\Bundle\RecaptchaBundle\Validator\Constraints;

use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;
use Symfony\Component\Validator\Exception\ValidatorException;

class TrueValidator extends ConstraintValidator
{
    protected $container;

    /**
     * The reCAPTCHA server URL's
     */
    const RECAPTCHA_VERIFY_SERVER = 'www.google.com';

    /**
     * Construct.
     *
     * @param ContainerInterface $container An ContainerInterface instance
     */
    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
    }

    /**
     * {@inheritdoc}
     */
    public function validate($value, Constraint $constraint)
    {
        // if recaptcha is disabled, always valid
        if (!$this->container->getParameter('ewz_recaptcha.enabled')) {
            return true;
        }

        // define variable for recaptcha check answer
        $privateKey = $this->container->getParameter('ewz_recaptcha.private_key');

        $remoteip   = $this->container->get('request')->server->get('REMOTE_ADDR');
        $challenge  = $this->container->get('request')->get('recaptcha_challenge_field');
        $response   = $this->container->get('request')->get('recaptcha_response_field');

        if (!$this->checkAnswer($privateKey, $remoteip, $challenge, $response)) {
            $this->context->addViolation($constraint->message);
        }
    }

    /**
      * Calls an HTTP POST function to verify if the user's guess was correct
      *
      * @param string $privateKey
      * @param string $remoteip
      * @param string $challenge
      * @param string $response
      * @param array $extra_params an array of extra variables to post to the server
      *
      * @return ReCaptchaResponse
      */
    private function checkAnswer($privateKey, $remoteip, $challenge, $response, $extra_params = array())
    {
        if ($remoteip == null || $remoteip == '') {
            throw new ValidatorException('For security reasons, you must pass the remote ip to reCAPTCHA');
        }

        // discard spam submissions
        if ($challenge == null || strlen($challenge) == 0 || $response == null || strlen($response) == 0) {
            return false;
        }

        $response = $this->httpPost(self::RECAPTCHA_VERIFY_SERVER, '/recaptcha/api/verify', array(
            'privatekey' => $privateKey,
            'remoteip'   => $remoteip,
            'challenge'  => $challenge,
            'response'   => $response
        ) + $extra_params);

        $answers = explode ("\n", $response [1]);

        if (trim($answers[0]) == 'true') {
            return true;
        }

        return false;
    }

    /**
     * Submits an HTTP POST to a reCAPTCHA server
     *
     * @param string $host
     * @param string $path
     * @param array $data
     * @param int port
     *
     * @return array response
     */
    private function httpPost($host, $path, $data, $port = 80)
    {
        $req = http_build_query($data);
        $url = "http://$host$path";
        $httpProxy = $this->container->getParameter('ewz_recaptcha.http_proxy');
        if (ini_get('allow_url_fopen')) {
            $opts['http'] = array(
                'method' => "POST", 
                'user-agent' => 'reCAPTCHA/PHP', 
                'timeout' => 10,
                'header' => "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: " . strlen($req)."\r\n",
                'content' => $req
            );
            if (isset($httpProxy['host'], $httpProxy['port'])) {            
                $opts['http']['proxy'] = 'tcp://' . $httpProxy['host'] . ':' . $httpProxy['port'];
                $opts['http']['request_fulluri'] = true;
                if (isset($httpProxy['auth'])) {
                    $opts['http']['header'] .= "Proxy-Authorization: Basic ".base64_encode($httpProxy['auth'])."\r\n";
                }
            }
            $context = stream_context_create(($opts));
    
            if (!$response = file_get_contents($url, false, $context)) {
                throw new ValidatorException('Could not open socket');
            }
            return array(1=>$response);
        } elseif (function_exists('curl_init')) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            curl_setopt($ch, CURLOPT_HEADER, 0);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            if (ini_get('open_basedir')) {
                //@TODO some gambi                
            } else {
                curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            }
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $req);
            curl_setopt($ch, CURLOPT_URL, $url);
            if (isset($httpProxy['host'], $httpProxy['port'])) {
                curl_setopt($ch, CURLOPT_PROXYTYPE, $httpProxy['type']);
                curl_setopt($ch, CURLOPT_PROXY, $httpProxy['host']);
                curl_setopt($ch, CURLOPT_PROXYPORT, $httpProxy['port']);
                if (isset($httpProxy['auth'])) {
                    curl_setopt($ch, CURLOPT_PROXYUSERPWD, $httpProxy['auth']);
                }
            }
            $response = curl_exec($ch);
            curl_close($ch);
            return array(1=>$response);
        } else {
            throw new ValidatorException('Could not open socket');
        }
    }

    /**
     * Encodes the given data into a query string format
     *
     * @param $data - array of string elements to be encoded
     *
     * @return string - encoded request
     */
    private function getQSEncode($data)
    {
        $req = null;
        foreach ($data as $key => $value) {
            $req .= $key.'='.urlencode(stripslashes($value)).'&';
        }

        // cut the last '&'
        $req = substr($req,0,strlen($req)-1);
        return $req;
    }
}
