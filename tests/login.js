'use strict';

/*global Promise*/
var PromiseA = Promise;
try {
  PromiseA = require('bluebird').Promise;
} catch (e) {
  // ignore
}

var config = require('../config.test.js');
var getProofOfSecret = require('../lib/pbkdf2-utils').getProofOfSecret;
var sha256 = require('../lib/pbkdf2-utils').sha256;

function dbsetup() {
  var sqlite3 = require('sqlite3-cluster');
  var wrap = require('dbwrap');

  var dir = [
    { tablename: 'codes'
    , idname: 'uuid'
    , indices: ['createdAt']
    }
  , { tablename: 'logins' // coolaj86, coolaj86@gmail.com, +1-317-426-6525
    , idname: 'hashId'
    //, relations: [{ tablename: 'secrets', id: 'hashid', fk: 'loginId' }]
    , indices: ['createdAt', 'type', 'node']
    //, immutable: false
    }
  , { tablename: 'verifications'
    , idname: 'hashId' // hash(date + node)
    //, relations: [{ tablename: 'secrets', id: 'hashid', fk: 'loginId' }]
    , indices: ['createdAt', 'nodeId']
    //, immutable: true
    }
  , { tablename: 'secrets'
    , idname: 'hashId' // hash(node + secret)
    , indices: ['createdAt']
    //, immutable: true
    }
  , { tablename: 'recoveryNodes' // just for 1st-party logins
    , idname: 'hashId' //
      // TODO how transmit that something should be deleted / disabled?
    , indices: ['createdAt', 'updatedAt', 'loginHash', 'recoveryNode', 'deleted']
    }
  ];

  var promise = sqlite3.create({
      standalone: true
    , bits: 128
    , filename: config.filename
    , verbose: false
  });

  return promise.then(function (db) {
    return db.init({ bits: 128, key: config.key });
  }).then(function (db) {
    return wrap.wrap(db, dir);
  });

  /*
  if (require.main === module) {
    create({
      key: '1892d335081d8d346e556c9c3c8ff2c3'
    , bits: 128
    , filename: '/tmp/authn.sqlcipher'
    }).then(function (DB) {
    });
  }
  */
}

function init(Logins) {
  var tests;
  var count = 0;
  var kdfMeta = {
    salt: null // assigned below
  , kdf: 'pbkdf2'
  , algo: 'sha256'
  , iter: 678
  };

  function setup() {
    return PromiseA.resolve();
  }

  function teardown() {
    return PromiseA.resolve();
  }

  // Test that success is successful
  tests = [
    function () {
      // test setup / teardown
      return PromiseA.resolve();
    }
  , function failUnknownType() {
      // fail because 'instagram' type is not implemented
      return Logins.create({
        node: '#coolaj86'
      , type: 'instagram'
      , secret: 'TODO_PROOF_OF_SECRET'
      }).then(function () {
        throw new Error("didn't fail to create unsupported type");
      }).error(function (err) {
        if ('E_UNKNOWN_TYPE' === err.code) {
          return;
        }

        throw err;
      });
    }
  , function failLowEntropy() {
      // fail because this layer doesn't manage password requirements
      return Logins.create({
        node: 'coolaj86@gmail.com'
      , type: 'email' // could be something like slack as well
      , secret: 'TODO_PROOF_OF_SECRET'
      }).then(function () {
        throw new Error("didn't fail to create unsupported type");
      }).error(function (err) {
        if ('E_LOW_ENTROPY' === err.code) {
          return;
        }

        throw err;
      });
    }
  , function passRecoverable() {
      var userId = 'coolaj86@gmail.com';
      var salt;

      // success because it's inherently recoverable
      salt = sha256(new Buffer(userId).toString('hex') + config.appId);
      return getProofOfSecret(salt, 'MY_SPECIAL_SECRET', kdfMeta.iter).then(function (proof) {
        return Logins.create({
          node: userId
        , type: 'email' // could be something like slack as well
        , secret: proof.proof
        , salt: proof.salt
        , kdf: proof.kdf || 'pbkdf2'
        , algo: proof.algo
        , iter: proof.iter
        });
      });
    }
  , function failUnrecoverable() {
      // fail because there's no recoverable

      var userId = 'coolaj86';
      var salt;

      salt = sha256(new Buffer(userId).toString('hex') + config.appId);
      return getProofOfSecret(salt, 'MY_SPECIAL_SECRET', kdfMeta.iter).then(function (proof) {
        return Logins.create({
          node: userId
        , type: 'username'
        , secret: proof.proof
        , salt: proof.salt
        , kdf: proof.kdf
        , algo: proof.algo
        , iter: proof.iter
        , recoveryNodes: [{ node: 'farmwood' }]
        }).then(function (err) {
          console.error('nofail', err);
          throw new Error("didn't fail to create unrecoverable account");
        }).error(function (err) {
          if ('E_NO_AUTHORITY' === err.code) {
            return;
          }

          throw err;
        });
      });
    }
  , function failUnsecured() {
      // fail because there's no secret
      return Logins.create({
        node: 'coolaj86'
      , type: 'username'
      , recoveryNodes: [{ node: 'john.doe@email.com' }]
      }).then(function () {
        throw new Error("didn't fail to create unsecured username account");
      }).error(function (err) {
        if ('E_LOW_ENTROPY' === err.code) {
          return;
        }

        throw err;
      });
    }
  /*
  , function passUnsecuredEmail() {
      // pass because we can login via login code to email

      return Logins.create({
        node: 'coolaj86@gmail.com'
      , type: 'email'
      });
    }
  */
  , function notVerified() {
      // return false
      return Logins.isVerified({
        type: 'email'
      , node: 'coolaj86@gmail.com'
      }).then(function (verified) {
        if (verified) {
          throw new Error('unverified email should not be verified');
        }
      });
    }
  , function verify() {
      // nothing to test here, actually, just setup for the next function
      return Logins.claim({
        type: 'email'
      , node: 'coolaj86@gmail.com'
      }).then(function (claim) {
        // Note: failing with a bad claim is tested in authcodes tests
        return Logins.validateClaim({
          type: 'email'
        , node: 'coolaj86@gmail.com'
          // soft expirey // TODO what was this for?
        , expiresIn: 180 * 24 * 60 * 60 * 1000
        , claim: claim
        });
      });
    }
  , function passVerified() {
      // returns true
      return Logins.isVerified({
        type: 'email'
      , node: 'coolaj86@gmail.com'
      }).then(function (verified) {
        if (!verified) {
          throw new Error('verified email should not be unverified');
        }
      });
    }
  , function createUsername() {
      // succeed with notice that account is verified recoverable
      var userId = 'coolaj86';

      kdfMeta.salt = sha256(new Buffer(userId).toString('hex') + config.appId);
      return getProofOfSecret(kdfMeta.salt, 'MY_SPECIAL_SECRET', kdfMeta.iter).then(function (proof) {
        return Logins.create({
          node: 'coolaj86'
        , type: 'username'
        , recoveryNodes: [{ node: 'coolaj86@gmail.com', type: 'email' }]

        , secret: proof.proof
        , salt: proof.salt
        , kdf: proof.kdf
        , algo: proof.algo
        , iter: proof.iter
        });
      });
    }
  , function passGetMeta() {
      return Logins.getKdf({
        node: 'coolaj86'
      , type: 'username'
      }).then(function (meta) {
        if (!meta) {
          throw new Error('missing meta');
        }

        if (meta.proof || meta.secret || meta.shadow) {
          throw new Error('shadow should not exist');
        }

        if (meta.kdf !== kdfMeta.kdf) {
          throw new Error('bad kdf');
        }
        if (meta.algo !== kdfMeta.algo) {
          throw new Error('bad algo');
        }
        if (meta.iter !== kdfMeta.iter) {
          throw new Error('bad iter');
        }
        if (meta.salt !== kdfMeta.salt) {
          throw new Error('bad salt');
        }
      });
    }
  , function failInvalidCreds() {
      var userId = 'coolaj86';

      return Logins.getKdf({
        node: userId
      , type: 'username'
      }).then(function (meta) {
        return getProofOfSecret(meta.salt, '__INVALID_SECRET__', meta.iter).then(function (proof) {

          return Logins.login({
            node: 'coolaj86'
          , type: 'username'
          , secret: proof.proof
          }).then(function () {
            throw new Error('should not pass with invalid credentials');
          }).error(function (err) {
            if ('E_INVALID_SECRET' === err.code) {
              return;
            }

            throw err;
          });
        });
      });
    }
  , function passValidCreds() {
      // Succeed

      var userId = 'coolaj86';

      return Logins.getKdf({
        node: userId
      , type: 'username'
      }).then(function (meta) {
        return getProofOfSecret(meta.salt, 'MY_SPECIAL_SECRET', meta.iter).then(function (proof) {
          return Logins.login({
            node: 'coolaj86'
          , type: 'username'
          , secret: proof.proof
          });
        });
      });
    }
  , function failChangePassword() {
      var userId = 'coolaj86';

      return getProofOfSecret(kdfMeta.salt, '__INVALID_SECRET__', kdfMeta.iter).then(function (prevProof) {
        var salt = sha256(new Buffer(userId).toString('hex') + config.appId);

        return getProofOfSecret(salt, 'MY-new-special-SECRET', kdfMeta.iter).then(function (nextProof) {
          return Logins.changePassword({
            node: userId
          , type: 'username'
          , secret: prevProof.proof
          , newSecret: {
              secret: nextProof.proof
            , salt: nextProof.salt
            , kdf: nextProof.kdf
            , algo: nextProof.algo
            , iter: nextProof.iter
            }
          });
        });
      }).then(function () {
        throw new Error("should not be able to change password with invalid password");
      }).error(function (err) {
        if ('E_INVALID_SECRET' === err.code) {
          return;
        }

        throw err;
      });
    }
  , function passChangePassword() {
      var userId = 'coolaj86';

      return getProofOfSecret(kdfMeta.salt, 'MY_SPECIAL_SECRET', kdfMeta.iter).then(function (prevProof) {
        var salt = sha256(new Buffer(userId).toString('hex') + config.appId);

        return getProofOfSecret(salt, 'MY-new-special-SECRET', kdfMeta.iter).then(function (nextProof) {
          return Logins.changePassword({
            node: userId
          , type: 'username'
          , secret: prevProof.proof
          , newSecret: {
              secret: nextProof.proof
            , salt: nextProof.salt
            , kdf: nextProof.kdf
            , algo: nextProof.algo
            , iter: nextProof.iter
            }
          });
        });
      });
    }
  , function passClaimResetPassword() {
      throw new Error('Not Implemented');
    }
  , function passVerifyResetPassword() {
      throw new Error('Not Implemented');
    }
  , function passLoginViaAuthCode() {
      throw new Error('Not Implemented');
    }
  , function failVerifyTotp() {
      throw new Error('Not Implemented');
    }
  , function passVerifyTotp() {
      throw new Error('Not Implemented');
    }
  // TODO test a valid claim against an invalid account
  ];

  var testsLen = tests.length;
  var curFn;

  function phase1() {
    return new PromiseA(function (resolve) {

      function callDoStuff() {
        curFn = tests.shift();

        return doStuff(curFn, testsLen - tests.length).catch(function (err) {
          return teardown().then(function () {
            throw err;
          });
        }).error(function (err) {
          return teardown().then(function () {
            throw err;
          });
        });
      }

      function doStuff(fn/*, i*/) {
        if (!fn) {
          return PromiseA.resolve();
        }

        //console.log('i1', i);
        return setup().then(fn).then(teardown).then(function () {
          //console.log('i2', i, count);
          count += 1;

          return callDoStuff();
        });
      }

      callDoStuff().then(function () {
        resolve();
      }).catch(function (err) {
        console.error('[ERROR] failure');
        console.error(err);
        console.error(curFn.toString());
        resolve();
      });
    });
  }

  phase1().then(function () {
    console.info('%d of %d tests complete', count, testsLen);
    process.exit();
  });
}

module.exports.create = function () {

  dbsetup().then(function (DB) {
    return init(
      require('../lib/login-impl').create({}, require('authcodes').create(DB.Codes), DB)
    );
  });
};

module.exports.create();
