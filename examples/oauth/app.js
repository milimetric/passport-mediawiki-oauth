var express = require('express');
var passport = require('passport');
var util = require('util');
// in a real applicaiton, just require('passport-mediawiki-oauth') and add
// passport-mediawiki-oauth to dependencies in package.json
var MediaWikiStrategy = require('passport-mediawiki-oauth').OAuthStrategy;

// API Access link for creating consumer key and secret:
// https://www.mediawiki.org/wiki/Special:OAuthConsumerRegistration/propose
// This example uses a develop-only consumer registered to work with localhost:5000
var MEDIAWIKI_CONSUMER_KEY = 'd28ee52e069d0ef4fd362a710b5142d9';
var MEDIAWIKI_CONSUMER_SECRET = '8ee2f3a9a8f6ba996db6a7750bc74a6b45c74f58';
var MEDIAWIKI_CALLBACK_URL = 'http://localhost:5000/auth/mediawiki/callback';


// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.  However, since this example does not
//   have a database of user records, the profile is serialized and deserialized.
passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(obj, done) {
  done(null, obj);
});


// Use the MediaWikiStrategy within Passport.
//   Strategies in passport require a `verify` function, which accept
//   credentials (in this case, a token, tokenSecret, and MediaWiki profile),
//   and invoke a callback with a user object.
passport.use(new MediaWikiStrategy({
    consumerKey: MEDIAWIKI_CONSUMER_KEY,
    consumerSecret: MEDIAWIKI_CONSUMER_SECRET,
    callbackURL: MEDIAWIKI_CALLBACK_URL
  },
  function(token, tokenSecret, profile, done) {
    // asynchronous verification, for effect...
    process.nextTick(function () {
      
      // To keep the example simple, the user's MediaWiki profile is returned to
      // represent the logged-in user.  In a typical application, you would want
      // to associate the MediaWiki account with a user record in your database,
      // and return that user instead.
      return done(null, profile);
    });
  }
));




var app = express();

// configure Express
app.configure(function() {
  app.set('views', __dirname + '/views');
  app.set('view engine', 'ejs');
  app.use(express.logger());
  app.use(express.cookieParser());
  app.use(express.bodyParser());
  app.use(express.methodOverride());
  app.use(express.session({ secret: 'keyboard cat' }));
  // Initialize Passport!  Also use passport.session() middleware, to support
  // persistent login sessions (recommended).
  app.use(passport.initialize());
  app.use(passport.session());
  app.use(app.router);
  // app.use(express.static(__dirname + '/public'));
});


app.get('/', function(req, res){
  res.render('index', { user: req.user });
});

app.get('/account', ensureAuthenticated, function(req, res){
  res.render('account', { user: req.user });
});

app.get('/login', function(req, res){
  res.render('login', { user: req.user });
});

// GET /login/meta_mw
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  The first step in MediaWiki authentication will involve redirecting
//   the user to mediawiki.  After authorization, MediaWiki will redirect the user
//   back to this application at /auth/meta_mw
app.get('/login/mediawiki',
  passport.authenticate('mediawiki'),
  function(req, res){
    // The request will be redirected to MediaWiki for authentication, so this
    // function will not be called.
  });

// GET /auth/meta_mw
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  If authentication fails, the user will be redirected back to the
//   login page.  Otherwise, the primary route function function will be called,
//   which, in this example, will redirect the user to the home page.
app.get('/auth/mediawiki/callback',
  passport.authenticate('mediawiki', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/');
  });

app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});

app.listen(5000);


// Simple route middleware to ensure user is authenticated.
//   Use this route middleware on any resource that needs to be protected.  If
//   the request is authenticated (typically via a persistent login session),
//   the request will proceed.  Otherwise, the user will be redirected to the
//   login page.
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { return next(); }
  res.redirect('/login');
}
