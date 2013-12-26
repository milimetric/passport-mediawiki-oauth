# Passport-MediaWiki-OAuth

[Passport](http://passportjs.org/) strategies for authenticating with
[MediaWiki](https://www.mediawiki.org/) using OAuth 1.0a.
Documentation and code shamelessly adapted from Jared Hanson's
[Passport-Google-OAuth](https://github.com/jaredhanson/passport-google-oauth).

This module lets you authenticate using MediaWiki in your Node.js applications.
By plugging into Passport, MediaWiki authentication can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

## Install

    $ npm install passport-mediawiki-oauth

## Usage of OAuth 1.0

#### Configure Strategy

The MediaWiki OAuth 1.0 authentication strategy authenticates users using a MediaWiki
account and OAuth tokens.  The strategy requires a `verify` callback, which
accepts these credentials and calls `done` providing a user, as well as `options`
specifying a consumer key, consumer secret, and callback URL.

```Javascript
var MediaWikiStrategy = require('passport-mediawiki-oauth').OAuthStrategy;

passport.use(new MediaWikiStrategy({
    consumerKey: MEDIAWIKI_CONSUMER_KEY,
    consumerSecret: MEDIAWIKI_CONSUMER_SECRET,
    callbackURL: MEDIAWIKI_CALLBACK_URL
  },
  function(token, tokenSecret, profile, done) {
    User.findOrCreate({ mediawikiGlobalId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));
```

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'mediawiki'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

```Javascript
app.get('/auth/mediawiki',
  passport.authenticate('mediawiki', { scope: MEDIAWIKI_AUTH_SCOPE }));

app.get('/auth/mediawiki/callback', 
  passport.authenticate('mediawiki', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/');
  });
```

## Examples

For a complete, working example, refer to the [OAuth 1.0 example](https://git.wikimedia.org/blob/passport-mediawiki/HEAD/examples%2Foauth%2Fapp.js).  To get it up and running, you can do:

    $ cd examples/oauth
    $ npm install
    $ node app.js

## Tests

    $ npm install --dev
    $ make test

[![Build Status](https://secure.travis-ci.org/wikimedia/passport-mediawiki-oauth.png)](http://travis-ci.org/wikimedia/passport-mediawiki-oauth)

## Credits

  - [Jared Hanson](http://github.com/jaredhanson)
  - [Wikimedia Foundation](http://github.com/wikimedia)

## License

[The MIT License](http://opensource.org/licenses/MIT)
