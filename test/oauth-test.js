var vows = require('vows');
var assert = require('assert');
var util = require('util');
var jwt = require('jwt-simple');
var MediaWikiStrategy = require('passport-mediawiki-oauth/oauth');


vows.describe('MediaWikiStrategy').addBatch({
  
  'strategy': {
    topic: function() {
      return new MediaWikiStrategy({
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      },
      function() {});
    },
    
    'should be named mediawiki': function (strategy) {
      assert.equal(strategy.name, 'mediawiki');
    }
  },
  
  'strategy request token params': {
    topic: function() {
      return new MediaWikiStrategy({
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      },
      function() {});
    }
  },
  
  'strategy when loading user profile': {
    topic: function() {
      
      var now = Math.round((new Date()).getTime() / 1000);
      var consumerKey = 'ABC123';
      var consumerSecret = 'secret';
      var strategy = new MediaWikiStrategy({
        consumerKey: consumerKey,
        consumerSecret: consumerSecret,
        baseURL: 'https://meta.wikimedia.org'
      },
      function() {});
      
      // mock
      strategy._oauth.post = function(url, token, tokenSecret, postBody, callback) {
      var body = '{"iss":"http://meta.wikimedia.org","sub":1234567,"aud":"'+consumerKey+'","exp":"'+(now+100)+'","iat":"'+now+'","nonce":"Nbw1q0S1ndwliuKbj0bH2CRTyddBUWo5","username":"DAndreescu","editcount":2,"confirmed_email":true,"blocked":false,"registered":"20120101000000","groups":["*","user","autoconfirmed"],"rights":["createaccount","read","edit","createpage","createtalk","writeapi","editmyusercss","editmyuserjs","viewmywatchlist","editmywatchlist","viewmyprivateinfo","editmyprivateinfo","editmyoptions","centralauth-merge","abusefilter-view","abusefilter-log","abusefilter-log-detail","translate","vipsscaler-test","move-rootuserpages","minoredit","purge","sendemail","translate-messagereview","translate-groupreview","mwoauthmanagemygrants","move","collectionsaveasuserpage","collectionsaveascommunitypage","autoconfirmed","editsemiprotected","movestable","transcode-reset","skipcaptcha","mwoauthproposeconsumer","mwoauthupdateownconsumer"]}';
        body = jwt.encode(body, consumerSecret);
        
        callback(null, body, undefined, [['oauth_nonce','Nbw1q0S1ndwliuKbj0bH2CRTyddBUWo5']]);
      };
      
      return strategy;
    },
    
    'when told to load user profile': {
      topic: function(strategy) {
        var self = this;
        function done(err, profile) {
          self.callback(err, profile);
        }
        
        process.nextTick(function () {
          strategy.userProfile('token', 'token-secret', {}, done);
        });
      },
      
      'should not error' : function(err, req) {
        assert.isNull(err);
      },
      'should load profile' : function(err, profile) {
        assert.equal(profile.provider, 'mediawiki');
        assert.equal(profile.id, '1234567');
        assert.equal(profile.displayName, 'DAndreescu');
      },
      'should set raw property' : function(err, profile) {
        assert.isString(profile._raw);
      },
      'should set json property' : function(err, profile) {
        assert.isObject(profile._json);
      }
    }
  },
  
  'strategy when loading user profile and encountering an error': {
    topic: function() {
      var strategy = new MediaWikiStrategy({
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      },
      function() {});
      
      // mock
      strategy._oauth.get = function(url, token, tokenSecret, callback) {
        callback(new Error('something went wrong'));
      };
      
      return strategy;
    },
    
    'when told to load user profile': {
      topic: function(strategy) {
        var self = this;
        function done(err, profile) {
          self.callback(err, profile);
        }
        
        process.nextTick(function () {
          strategy.userProfile('token', 'token-secret', {}, done);
        });
      },
      
      'should error' : function(err, req) {
        assert.isNotNull(err);
      },
      'should wrap error in InternalOAuthError' : function(err, req) {
        assert.equal(err.constructor.name, 'InternalOAuthError');
      },
      'should not load profile' : function(err, profile) {
        assert.isUndefined(profile);
      }
    }
  }

}).export(module);
