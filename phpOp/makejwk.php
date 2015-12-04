<?php
/**
 * Copyright 2013 Nomura Research Institute, Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

include_once('base64url.php');
include_once('libjsoncrypto.php');

/**
Parameters

    $n  modulus in big endian format
    $e  exponent in big endian format
    $kid kid string
    $use key usage: sig or enc

**/

function make_rsa_jwk($n, $e, $kid = NULL, $use = '') {
    
    if(!$n || !$e)
        return false;
        
    $key_info =  array(  'e'   => base64url_encode($e),
                         'kty' => 'RSA',
                         'n'   => base64url_encode($n),
                      );
    if($kid)
        $key_info['kid'] = $kid;
    else {
        $key_info['kid'] = base64url_encode(hash('sha256', json_encode($key_info), true));
    }
    if($use)
        $key_info['use'] = $use;                      
 
    $jwk = array('keys' => array($key_info));
    return pretty_json(json_encode($jwk));
    
}


function make_rsa_jwk_key($n, $e, $kid = NULL, $use = '') {
    
    if(!$n || !$e)
        return false;
        
    $key_info =  array(  'e'   => base64url_encode($e),
                         'kty' => 'RSA',
                         'n'   => base64url_encode($n),
                      );
    if($kid)
        $key_info['kid'] = $kid;
    else {
        printf("jwk = %s\n", json_encode($key_info));
        $key_info['kid'] = base64url_encode(hash('sha256', json_encode($key_info), true));

    }
    if($use)
        $key_info['use'] = $use;                      
    return $key_info; 
}

function make_rsa_pkix_key($cert_chain, $kid = NULL, $use = '') {
    
    if(!$cert_chain)
        return false;
        
    $key_info =  array( 'kty' => 'PKIX',
                         'x5c'   => $cert_chain
                      );
    if($kid)
        $key_info['kid'] = $kid;
    if($use)
        $key_info['use'] = $use;                      
    return $key_info; 
}


function make_jwk($keys) {
    if(!is_array($keys))
        $keys = array($keys);
    $jwk = array('keys' => $keys);
    return pretty_json(json_encode($jwk));
}

if($argc > 1) {
    if($argv[1] == 'mergejwks') {
        $json = array('keys'=>array());
        for($i = 2; $i < count($argv); $i++) {
            $file = file_get_contents($argv[$i]);
            if($file) {
                $temp = json_decode($file, true);
                if($temp) {
                    if(isset($temp['keys']))
                        $json = array_merge_recursive($json, $temp);
                }
            }
        }
        echo pretty_json(json_encode($json));

    } else if($argv[1] == 'thumbprint') {
        echo get_rsa_key_thumbprint(file_get_contents($argv[2]));
    } else {
        $cert = file_get_contents($argv[1]);
        if($cert) {
            $key_pattern = '/(?m)^-----BEGIN (CERTIFICATE|PUBLIC KEY|RSA PRIVATE KEY)-----$\n((?s).*)\n^-----END (CERTIFICATE|PUBLIC KEY|RSA PRIVATE KEY)-----$/';  // matches whole block,
            if(preg_match($key_pattern, $cert, $matches)) {
                $encoded_der = $matches[2];
                $jwk_keys = array();
                if($matches[1] == 'RSA PRIVATE KEY')
                    $pubinfo = get_mod_exp_from_key($cert, NULL, true);
                else
                    $pubinfo = get_mod_exp_from_key($cert);
                $kid = isset($argv[2]) ? $argv[2] : '';
                $use = isset($argv[3]) ? $argv[3] : '';

                if($pubinfo) {
                    list($n, $e) = $pubinfo;
                    $jwk_key = make_rsa_jwk_key($n, $e, $kid, $use);
//                $jwk_key['x5c'] = array($encoded_der);
                    if($jwk_key)
                        $jwk_keys[] = $jwk_key;
                }
                $jwk = make_jwk($jwk_keys);
                printf("%s\n", $jwk);
            } else
                printf("no match\n");
        }
    }

} else {
    printf("Usage : php makejwk.php pem_file_path kid use\n");
}






