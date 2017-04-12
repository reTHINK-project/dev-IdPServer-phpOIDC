/**
* Copyright (c) 2016 Orange
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*   http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* IdentityProxy -- NODE OPENID CONNECT Server
* Initial specification: D4.1
*
* The IdentityModule is a component managing user Identity. It downloads, instantiates
* and manage Identity Provider Proxy (IdP) for its own user identity or for external
* user identity verification.
*
* The IdP contains methods and parameters to actually access and make request
* to the IdP Server. Alternatively some functionnalities can be done locally.
*
*/

  var SOURCEURL = "SOURCE_PROTOCOLESOURCE_DOMAIN",
      AUTHPATH = "/phpOp/index.php/auth",
      VERIFYPATH = "/phpOp/index.php/validatetoken",
      CLIENT_ID='SET_CLIENT_ID',
      CLIENT_SECRET = 'SET_CLIENT_SECRET'
      DONEPATH='/phpOp/index.php/proxy/done',
      KEYPATH = '/phpOp/index.php/proxy/key',
      IDPATH = '/phpOp/index.php/proxy/id',
      PROXYTYPE = "rethink-oidc-ns",
      IDSCOPE = "openid",
      FULLSCOPE = "openid webrtc",
      TYPE       =   'id_token token',
      CLAIMS = '{"id_token":{"name": {"essential": true}, "login": {"essential": true}}}',
      RESPONSE_MODE = 'body';
var idp_addr = {'domain': "SOURCE_DOMAIN", 'protocol': PROXYTYPE}

if (typeof console == "undefined") {
    this.console = {
        log: function () {}
    };
}

/**
 str conversion
*/
 function str2ab(str) {
   var buf = new ArrayBuffer(str.length);
   var bufView = new Uint8Array(buf);
   for (var i=0, strLen=str.length; i < strLen; i++) {
     bufView[i] = str.charCodeAt(i);
   }
   return buf;
 }

 function ab2str(buf) {
   return String.fromCharCode.apply(null, new Uint8Array(buf));
 }


/**
 *
 * @return {public Key}              PublicKey
*/
  function getProxyKey(header){

    return new Promise(function(resolve, reject) {
      var xmlhttp = new XMLHttpRequest();
      xmlhttp.onreadystatechange = function() {
        if (xmlhttp.readyState == 4 && xmlhttp.status == 200) {
          console.info(xmlhttp.responseText);
		  var res = JSON.parse(xmlhttp.responseText);
          if (res.error != undefined) {
            reject(res.error)
          } else {
            resolve(res.keys)
          }
        }
      };
      xmlhttp.open("GET", SOURCEURL + "/phpOp/op.jwk", true); //header.jku, true);
      xmlhttp.send();
    })
  }



// IDP Proxy code
var idp = {
  /**
  * Generation of an IdAssertion through OIDC IdP
  */
 generateAssertion: function(contents, origin, hint)
{
     		var _url =   SOURCEURL+AUTHPATH+
                     '?scope=' + FULLSCOPE +
                     '&client_id=' + CLIENT_ID +
                     '&redirect_uri=' + SOURCEURL + DONEPATH +
                     '&response_type=' + TYPE +
                     '&claims=' + CLAIMS +
                     '&nonce=' + 'N-'+Math.random() +
                     '&rtcsdp='+contents+
                     '&response_mode='+RESPONSE_MODE;
//                     '&origin=' + origin +
		var myInit = {method: 'GET',
		              credentials: 'same-origin',
		             };

		return fetch(_url,myInit)
    .then(response => {
		    if(response.redirected){
		        //Change response_mode=body to default, will make proxy/done close the popup after login
		        var loginUrl = response.url.replace('%26response_mode%3D'+RESPONSE_MODE, '')
		        throw {'name': 'IdpLoginError', 'loginUrl': loginUrl, 'requestedUrl': _url}
		    }
		    else
		        return response.text()
		})
		.then(text => {
			return {'assertion': text, 'idp': idp_addr}
    })
},


  /**
  * Verification of a received IdAssertion validity (OTHER USER'S IDENTITY)
  * Can also be used to validate token received by IdP
  * @param  {DOMString} assertion assertion
  */
  validateAssertion: (assertion, origin) => {
    assertion = assertion.split(".")
    var header = assertion[0],
        payload = assertion[1],
        signature = assertion[2]
    //TODO there is probably a better way to do that?
    console.log("assertion + header + payload + signature");
    console.log(assertion);
  	console.log(header);
  	console.log(payload);
  	console.log(signature);
    signature = signature.replace(/_/g, "/").replace(/-/g, "+");
  	var mavariable = JSON.parse(atob(assertion[0]));
    return getProxyKey(mavariable)
    .then(Key => {
      return crypto.subtle.importKey('jwk',Key[0], { name: 'RSASSA-PKCS1-v1_5',hash: {name: "SHA-256"}},true, ['verify'])
    })
	  .then(JWK => {
      return crypto.subtle.verify('RSASSA-PKCS1-v1_5', JWK, str2ab(atob(signature)), str2ab(header+"."+payload))
    })
	  .then(result => {
  		if (!result)
        return Promise.reject({'name':'IdpError', 'message':'162: Invalid signature on identity assertion'})
  		else {
  			console.log("Token signature validated");
  			payload = JSON.parse(atob(payload));

  			var name = payload.sub.split('@')[0];
        //From peerConnectionIdP.jsm
        let provider = idp_addr.domain;
        let providerPortIdx = provider.indexOf(':');
  		  if (providerPortIdx > 0) {
  			   provider = provider.substring(0, providerPortIdx);
  		  }
        return Promise.resolve({'identity': name+'@'+provider, 'name':payload.name , 'login':payload.login , 'contents': payload.rtcsdp});//, 'acr': json.dummy_acr}) //resolve
			//return resolve({"identity": contents.sub+'@'+idp_addr.domain, "contents": contents})
		  }
    })
    .catch(error => reject({'name':'IdpError', 'message':'171: '+error}))
}
}


if (typeof rtcIdentityProvider != 'undefined') {
  rtcIdentityProvider.register(idp);
  console.log("Proxy loaded")
} else {
  console.warn('IdP not running in the right sandbox');
}
