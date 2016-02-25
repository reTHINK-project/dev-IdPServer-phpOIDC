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
  
  var SOURCEURL = "https://localhost",
      AUTHPATH = "/phpOp/index.php/auth",
      VERIFYPATH = "/phpOp/index.php/validatetoken",
	  CLIENT_ID='yfVsyslQqwkU_UUuJmEZUg',
	  CLIENT_SECRET = 'dToM94ZAmiQptw',
	  DONEPATH='/phpOp/index.php/proxy/done',
      KEYPATH = '/phpOp/index.php/proxy/key',
	  IDPATH = '/phpOp/index.php/proxy/id',
      PROXYTYPE = "rethink-oidc-ns",
      IDSCOPE = "openid profile",
      FULLSCOPE = "openid profile",
      TYPE       =   'id_token token';
 
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
	  var totor = header.jku;
      xmlhttp.open("GET", header.jku, true);
      xmlhttp.send();
    })
  }
  
  /**
  *
  *
  */
  function getProxyID(){
   return CLIENT_ID;
 
 }
 

// IDP Proxy code
var idp = {
  /**
  * Generation of an IdAssertion through OIDC IdP
  */
  generateAssertion: (contents /*, origin, hint */) => {
  // TODO : sign contents in the Id Token
    return new Promise((resolve, reject) => {
          var _url = SOURCEURL+AUTHPATH+'?scope=' + IDSCOPE + '&client_id=' + CLIENT_ID +
                     '&redirect_uri=' + SOURCEURL + DONEPATH + '&response_type=' + TYPE +
                     '&nonce=' + 'N-'+Math.random()
              // this will open a window with the URL which will open a page
              // sent by IdP for the user to insert the credentials
              // the IdP validates the credentials then send a access token
          window.open(_url, 'openIDrequest', 'width=800, height=600')
              // respond to events
          this.addEventListener('message', event => {
			 console.log(event.origin);
            if(event.origin !== SOURCEURL) {
				return;
			}
            resolve(JSON.parse(event.data).id_token)
            //idp.validateAssertion(res.id_token).then(
            //    response => resolve(response), error => reject(error))
          },false)
 }
)},

  /**
  * Verification of a received IdAssertion validity (OTHER USER'S IDENTITY)
  * Can also be used to validate token received by IdP
  * @param  {DOMString} assertion assertion
  */
  validateAssertion: (assertion) => {
    assertion = assertion.split(".")
    var header = assertion[0],
        payload = assertion[1],
        signature = assertion[2]
    //TODO there is probably a better way to do that?
    signature = signature.replace(/_/g, "/").replace(/-/g, "+")
	var mavariable = JSON.parse(atob(assertion[0]));
    return new Promise((resolve, reject) =>
      getProxyKey(mavariable)
        .then(Key => {
		    crypto.subtle.importKey('jwk',Key[0],{ name: 'RSASSA-PKCS1-v1_5',hash: {name: "SHA-256"}},true, ['verify'])
			.then(JWK => {
			  var test = JWK;
			  //crypto.verify(algo, key, signature, text2verify);
			  crypto.subtle.verify('RSASSA-PKCS1-v1_5',
								   JWK,
								   str2ab(atob(signature)),   //ArrayBuffer of the signature,
								   str2ab(header+"."+payload))//ArrayBuffer of the data
				.then(result => {
				  if (!result) reject(new Error('Invalid signature on identity assertion'))
				  else {
					console.log("Token signature validated")
					var contents = JSON.parse(atob(payload))
					resolve({"identity": contents.sub, "contents": contents})
				  }
				 })
				}
			 )
			}
		)
    )
},

  /**
 * In relation with a classical Relying Party: Login
 * @param  {Identifier}      identifier      identifier
 * @param  {Scope}           scope           scope
 * @return {Promise}         Promise         IDToken
 */
  loginWithRP: () => {
    return new Promise(function(resolve, reject) {
   //   getProxyKey().then(function(response){
        var IDPROXYID = CLIENT_ID;//response
        var _url = SOURCEURL+AUTHPATH+'?scope=' + IDSCOPE + '&client_id=' + IDPROXYID +
                '&redirect_uri=' + SOURCEURL + DONEPATH + '&response_type=' + TYPE +
                '&nonce=' + 'N-'+Math.random()
        // this will open a window with the URL which will open a page sent by google for the user to insert the credentials
        // when the google validates the credentials then send a access token
        var win = window.open(_url, 'openIDrequest', 'width=800, height=600');
          
        // respond to events
        window.addEventListener('message',function(event) {
          if(event.origin !== SOURCEURL) return;
          var res = JSON.parse(event.data)
          validateAssertion(res.id_token).then(function(response) {
            resolve(response)
          }, function(error) {
            reject(error);
          })
        },false);
      }//, function(error){
       // reject(error)  
      //})
    )
  }
}


if (rtcIdentityProvider) {
  rtcIdentityProvider.register(idp);
  console.log("Proxy loaded")
} else {
  console.warn('IdP not running in the right sandbox');
}