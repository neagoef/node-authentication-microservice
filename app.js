'use strict';

/*global Promise*/
var PromiseA = Promise;
try {
  PromiseA = require('bluebird').Promise;
} catch (e) {
  // ignore
}

var config = require('./config.test.js');
var getProofOfSecret = require('./lib/pbkdf2-utils').getProofOfSecret;
var sha256 = require('./lib/pbkdf2-utils').sha256;

var kdfMeta = {
  salt: null // assigned below
, kdf: 'pbkdf2'
, algo: 'sha256'
, iter: 678
};

function init(Logins) {
  var express = require('express');
  var app = express();

  app.use(function (req, res) {
    // fail because there's no recoverable

    var promise;
    var userId = 'coolaj86';
    var salt;

    salt = sha256(new Buffer(userId).toString('hex') + config.appId);
    promise = getProofOfSecret(salt, 'MY_SPECIAL_SECRET', kdfMeta.iter).then(function (proof) {
      return Logins.create({
        node: userId
      , type: 'username'
      , secret: proof.proof
      , salt: proof.salt
      , kdf: proof.kdf
      , algo: proof.algo
      , iter: proof.iter
      , recoveryNodes: [{ node: 'farmwood' }]
      });
    });

    promise.then(function () {
      res.send({ success: 'maybe' });
    }).error(function (err) {
      res.send({ error: { message: err.message } });
    }).catch(function (exc) {
      console.error('[EXCEPTION]');
      console.error(exc);
      res.send({ error: { message: "Unhandled exception" } });
    });
  });

  return PromiseA.resolve(app);
}

module.exports.create = function (server, DB) {
  return init(
    require('./lib/login-impl').create({}, require('authcodes').create(DB.Codes), DB)
  );
};
