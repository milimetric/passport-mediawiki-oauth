/**
 * Module dependencies.
 */
var util = require('util');
var jwt = require('jwt-simple');
var url = require('url');
var OAuthStrategy = require('passport-oauth').OAuthStrategy;
var InternalOAuthError = require('passport-oauth').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * The MediaWiki authentication strategy authenticates requests by delegating to
 * MediaWiki using the OAuth protocol.
 *
 * Applications must supply a `verify` callback which accepts a `token`,
 * `tokenSecret` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.    If an exception occured, `err` should be set.
 *
 * Options (required):
 *     - `consumerKey`      identifies client to MediaWiki
 *     - `consumerSecret`   secret used to establish ownership of the consumer key
 *     - `callbackURL`      MediaWiki will redirect the user here, after authorization
 *
 * Options (optional):
 *     - `baseURL`          the MediaWiki instance to work with
 *     - `sessionKey`       to store results
 *
 * Examples:
 *
 *         passport.use(new MediaWikiStrategy({
 *                 consumerKey: '123-456-789',
 *                 consumerSecret: 'shhh-its-a-secret',
 *                 callbackURL: 'https://www.yoursite.net/auth/mediawiki/callback',
 *                 baseURL: 'https://en.wikipedia.org/
 *             },
 *             function(token, tokenSecret, profile, done) {
 *                 User.findOrCreate(..., function (err, user) {
 *                     done(err, user);
 *                 });
 *             }
 *         ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
    options = options || {};
    options.baseURL              = options.baseURL || 'https://meta.wikimedia.org/';
    options.sessionKey           = options.sessionKey || 'oauth:mediawiki';
    
    options.requestTokenURL      = options.baseURL + 'w/index.php';
    options.accessTokenURL       = options.baseURL + 'w/index.php?title=Special:OAuth/token';
    options.userAuthorizationURL = options.baseURL + 'wiki/Special:OAuth/authorize';
    
    OAuthStrategy.call(this, options, verify);
    this.userIdentifyURL = options.baseURL + 'w/index.php?title=Special:OAuth/identify?format=json';
    this.name = 'mediawiki';
}

/**
 * Inherit from `OAuthStrategy`.
 */
util.inherits(Strategy, OAuthStrategy);

/**
 * Retrieve user profile from MediaWiki via the optional identify endpoint.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *     - `id`           The global id of this MediaWiki user
 *     - `displayName`
 *
 * @param {String} token
 * @param {String} tokenSecret
 * @param {Object} params
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(token, tokenSecret, params, done) {
    var self = this;
    this._oauth.get(this.userIdentifyURL, token, tokenSecret, function (err, body, res) {
        if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }
        
        try {
            var identification = jwt.decode(body, self.consumerSecret);
            
            // verify the identification was done securely
            // Verify the issuer is who we expect
            var iss_hostname = url.parse(identification.iss).hostname;
            var mw_hostname = url.parse(self.baseURL).hostname;
            if (iss_hostname !== mw_hostname) {
                throw new InternalOAuthError('JSON Web Token Validation Problem, iss');
            }
            
            // Verify we are the intended audience
            if (identification.aud !== self.consumerSecret){
                throw new InternalOAuthError('JSON Web Token Validation Problem, aud');
            }
            
            // Verify we are within the time limits of the token.
            // Issued at (iat) should be in the past
            var now = Math.round((new Date()).getTime() / 1000);
            if (parseInt(identification.iat, 10) > now){
                throw new InternalOAuthError('JSON Web Token Validation Problem, iat');
            }
            
            // Expiration (exp) should be in the future
            if (parseInt(identification.exp, 10) < now){
                throw new InternalOAuthError('JSON Web Token Validation Problem, exp');
            }
            
            // Verify we haven't seen this nonce before,
            // which would indicate a replay attack
            // TODO: implement nonce for extra security
            //if identification['nonce'] != <<original request nonce>>
                //throw new InternalOAuthError('JSON Web Token Validation Problem, nonce')
            
            var profile = { provider: 'mediawiki' };
            profile.id = identification.sub;
            profile.displayName = identification.username;
            profile.emails = [];
            
            profile._raw = body;
            profile._json = identification;
            
            done(null, profile);
        } catch(e) {
            done(e);
        }
    });
};

/**
 * Mediawiki requires extra parameters for the request token endpoint.
 * Options:
 *
 *    - `requestTokenTitle`         the title passed when requesting a token
 *    - `requestTokenOauthCallback` the oauth_callback passed when requesting a token
 *
 * @param {Object} options
 */
Strategy.prototype.requestTokenParams = function(options) {
    return {
        title: options.requestTokenTitle || 'Special:MWOauth/initiate',
        oauth_callback: options.requestTokenOauthCallback || 'oob'
    };
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
