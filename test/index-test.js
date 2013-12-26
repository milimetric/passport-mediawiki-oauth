var vows = require('vows');
var assert = require('assert');
var util = require('util');
var mediawiki = require('passport-mediawiki-oauth');


vows.describe('passport-mediawiki-oauth').addBatch({
  
  'module': {
    'should report a version': function (x) {
      assert.isString(mediawiki.version);
    },
    'should export OAuth strategy': function (x) {
      assert.isFunction(mediawiki.Strategy);
      assert.isFunction(mediawiki.OAuthStrategy);
      assert.equal(mediawiki.Strategy, mediawiki.OAuthStrategy);
    }
  }
  
}).export(module);
