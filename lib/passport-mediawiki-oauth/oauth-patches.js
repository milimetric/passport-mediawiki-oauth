var querystring = require('querystring');
var URL = require('url');


exports.patch_getOAuthAccessToken = function(context){
    // HACK: getOAuthAccessToken needs to pass oauth_verifier in the URL
    // usage: from something that has _oauth
    //    this._oauth.getOAuthAccessToken = oauth_patches.patch_getOAuthAccessToken(this._oauth);
    return function(oauth_token, oauth_token_secret, oauth_verifier,  callback) {
        var extraParams= {};
        if( typeof oauth_verifier === 'function' ) {
            callback = oauth_verifier;
        } else {
            extraParams.oauth_verifier = oauth_verifier;
        }
        
        // This is the differeence in this patched method, along with accessUrlWithVerifier being used below
        var accessUrlWithVerifier = context._accessUrl + '&oauth_verifier=' + oauth_verifier;
        
        context._performSecureRequest( oauth_token, oauth_token_secret, context._clientOptions.accessTokenHttpMethod, accessUrlWithVerifier, extraParams, null, null, function(error, data, response) {
            if( error ){ callback(error); }
            else {
                var results = querystring.parse( data );
                var oauth_access_token = results.oauth_token;
                delete results.oauth_token;
                var oauth_access_token_secret= results.oauth_token_secret;
                delete results.oauth_token_secret;
                callback(null, oauth_access_token, oauth_access_token_secret, results );
            }
        });
    };
};


exports.patch_performSecureRequest = function(context){
    // HACK: (VERY UGLY but my pull request was not merged upstream)
    // usage: from something that has _oauth
    //    this._oauth._performSecureRequest = oauth_patches.patch_performSecureRequest(this._oauth);
    
    return function( oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type,  callback ) {
      var orderedParameters= context._prepareParameters(oauth_token, oauth_token_secret, method, url, extra_params);

      if( !post_content_type ) {
        post_content_type= "application/x-www-form-urlencoded";
      }
      var parsedUrl= URL.parse( url, false );
      if( parsedUrl.protocol == "http:" && !parsedUrl.port ) parsedUrl.port= 80;
      if( parsedUrl.protocol == "https:" && !parsedUrl.port ) parsedUrl.port= 443;

      var headers= {};
      var authorization = context._buildAuthorizationHeaders(orderedParameters);
      if ( context._isEcho ) {
        headers["X-Verify-Credentials-Authorization"]= authorization;
      }
      else {
        headers["Authorization"]= authorization;
      }

      headers["Host"] = parsedUrl.host

      for( var key in context._headers ) {
        if (context._headers.hasOwnProperty(key)) {
          headers[key]= context._headers[key];
        }
      }

      // Filter out any passed extra_params that are really to do with OAuth
      for(var key in extra_params) {
        if( context._isParameterNameAnOAuthParameter( key ) ) {
          delete extra_params[key];
        }
      }

      if( (method == "POST" || method == "PUT")  && ( post_body == null && extra_params != null) ) {
        // Fix the mismatch between the output of querystring.stringify() and context._encodeData()
        post_body= querystring.stringify(extra_params)
                           .replace(/\!/g, "%21")
                           .replace(/\'/g, "%27")
                           .replace(/\(/g, "%28")
                           .replace(/\)/g, "%29")
                           .replace(/\*/g, "%2A");
      }

      headers["Content-length"]= post_body ? Buffer.byteLength(post_body) : 0;
      headers["Content-Type"]= post_content_type;

      var path;
      if( !parsedUrl.pathname  || parsedUrl.pathname == "" ) parsedUrl.pathname ="/";
      if( parsedUrl.query ) path= parsedUrl.pathname + "?"+ parsedUrl.query ;
      else path= parsedUrl.pathname;

      var request;
      if( parsedUrl.protocol == "https:" ) {
        request= context._createClient(parsedUrl.port, parsedUrl.hostname, method, path, headers, true);
      }
      else {
        request= context._createClient(parsedUrl.port, parsedUrl.hostname, method, path, headers);
      }

      var clientOptions = context._clientOptions;
      if( callback ) {
        var data="";
        var self= context;

        // Some hosts *cough* google appear to close the connection early / send no content-length header
        // allow this behaviour.
        var allowEarlyClose= false; // note: hacked this to false because we don't deal with google and we don't have access to the internal utils
        var callbackCalled= false;
        function passBackControl( response ) {
          if(!callbackCalled) {
            callbackCalled= true;
            if ( response.statusCode >= 200 && response.statusCode <= 299 ) {
              // this is the only change to this function (just passing orderedParameters to the callback)
              callback(null, data, response, orderedParameters);
            } else {
              // Follow 301 or 302 redirects with Location HTTP header
              if((response.statusCode == 301 || response.statusCode == 302) && clientOptions.followRedirects && response.headers && response.headers.location) {
                self._performSecureRequest( oauth_token, oauth_token_secret, method, response.headers.location, extra_params, post_body, post_content_type,  callback);
              }
              else {
                // this is the only change to this function (just passing orderedParameters to the callback)
                callback({ statusCode: response.statusCode, data: data }, data, response, orderedParameters);
              }
            }
          }
        }

        request.on('response', function (response) {
          response.setEncoding('utf8');
          response.on('data', function (chunk) {
            data+=chunk;
          });
          response.on('end', function () {
            passBackControl( response );
          });
          response.on('close', function () {
            if( allowEarlyClose ) {
              passBackControl( response );
            }
          });
        });

        request.on("error", function(err) {
          callbackCalled= true;
          callback( err )
        });

        if( (method == "POST" || method =="PUT") && post_body != null && post_body != "" ) {
          request.write(post_body);
        }
        request.end();
      }
      else {
        if( (method == "POST" || method =="PUT") && post_body != null && post_body != "" ) {
          request.write(post_body);
        }
        return request;
      }

      return;
    };
};


exports.getNonceFromParameters = function(orderedParameters){
    // example ordered params:
    //
    // [ [ 'oauth_consumer_key', '...' ],
    //   [ 'oauth_nonce', '...' ],
    //   [ 'oauth_signature_method', 'HMAC-SHA1' ],
    //   [ 'oauth_timestamp', 1389307371 ],
    //   [ 'oauth_token', '...' ],
    //   [ 'oauth_version', '1.0' ],
    //   [ 'title', 'Special:OAuth/identify' ],
    //   [ 'oauth_signature', '...' ] ]
    for (var i=0; i < orderedParameters.length; i++) {
        var param = orderedParameters[i];
        if (param[0] === 'oauth_nonce') {
            return param[1];
        }
    }
    return '';
};
