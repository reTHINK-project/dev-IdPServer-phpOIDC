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
//class NodeOIDCProxy {
  
  var SOURCEURL = "https://oidc-ns.kermit.orange-labs.fr/phpOp/index.php",
      AUTHPATH = "/auth",
      VERIFYPATH = "/proxy/verify",
      //DONEPATH = "/proxy/done",
	  CLIENT_ID='4wBRdEeXzKNS1h67JRCNtA',
	  DONEPATH='/proxy/done',
      KEYPATH = '/proxy/key',
      PROXYTYPE = "rethink-oidc-ns",
      IDSCOPE = "openid",
      FULLSCOPE = "openid profile",
      TYPE       =   'id_token token';
  //var TYPE       =   'code';
                  
//  /**
//  * USER'S OWN IDENTITY
//  */
//  constructor() {
//
//  }
//
//  /**
//  * Register a new Identity with an Identity Provider
//  */
//  registerIdentity() {
//    // Body...
//  }
//
//  /**
//  * In relation with a classical Relying Party: Registration
//  */
//  registerWithRP() {
//    // Body...
//  }
//
//  /**
//  * In relation with a classical Relying Party: Login
//  * @param  {Identifier}      identifier      identifier
//  * @param  {Scope}           scope           scope
//  * @return {Promise}         Promise         IDToken
//  */
  function loginWithRP() {
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
  


  /**
  * OTHER USER'S IDENTITY
  */

  /**
  * Verification of a received IdAssertion validity
  * Can also be used to validate token received by IdP
  * @param  {DOMString} assertion assertion
  */
  function validateAssertion(assertion) {
    return new Promise(function(resolve, reject) {
      getProxyKey().then(function(response){
        var IDPROXYID = response
        var xmlhttp = new XMLHttpRequest();
        xmlhttp.onreadystatechange = function() {
        if (xmlhttp.readyState == 4 && xmlhttp.status == 200) {
          var res = JSON.parse(xmlhttp.responseText);
          if (res.error != undefined) {
            reject(res.error)
          } else {
            resolve(res.id_token)
          }
        }
      };
      xmlhttp.open("GET", SOURCEURL+VERIFYPATH+"?key="+IDPROXYID+"&id_token="+assertion, true);
      xmlhttp.send();
      }, function(error){
        reject(error)  
      })  
    })
  }

  /**
  * Trust level evaluation of a received IdAssertion
  * @param  {DOMString} assertion assertion
  */
  function getAssertionTrustLevel(assertion) {
    // Body...
  }

//
//  /**
//  * In relation with a Hyperty Instance: Associate identity
//  */
//  setHypertyIdentity() {
//    // Body...
//  }
//
//  /**
//  * Generates an Identity Assertion for a call session
//  * @param  {DOMString} contents     contents
//  * @param  {DOMString} origin       origin
//  * @param  {DOMString} usernameHint usernameHint
//  * @return {IdAssertion}              IdAssertion
//  */
//  generateAssertion(contents, origin, usernameHint) {
//    // At the moment login if needed
//    // Save and send assertion
//  }

//}

  function getProxyKey(){
    return new Promise(function(resolve, reject) {
      var xmlhttp = new XMLHttpRequest();
      xmlhttp.onreadystatechange = function() {
        if (xmlhttp.readyState == 4 && xmlhttp.status == 200) {
          var res = JSON.parse(xmlhttp.responseText);
          if (res.error != undefined) {
            reject(res.error)
          } else {
            resolve(res.key)
          }
        }
      };
      xmlhttp.open("GET", SOURCEURL+KEYPATH, true);
      xmlhttp.send();
    })
  }

console.log("Proxy loaded")
