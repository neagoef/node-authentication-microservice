'use strict';

var PromiseA = require('bluebird');

module.exports.create = function (config, AuthCodes, DB) {
  var otp = require('authenticator');
  var Validators = require('./contact-nodes.js').validators;
  var Formatters = require('./contact-nodes.js').formatters;
  var getType = require('./contact-nodes.js').getType;
  // TODO twitter is recoverable
  // TODO check for a validated username
  var recoveryTypes = ['email', 'phone'];
  var knownTypes = ['username'].concat(recoveryTypes);
  var secretutils = require('secret-utils');
  var getProofOfSecret = require('./pbkdf2-utils').getProofOfSecret;
  var sha256 = require('./pbkdf2-utils').sha256;

  var Rejection = {
    create: function (msg) {
      return { message: msg };
    }
  };

  function Logins() {
  }

  function genSalt() {
    return sha256(require('crypto').randomBytes(16).toString('hex'));
  }

  function genIter() {
    return (parseInt(require('crypto').randomBytes(1).toString('hex'), 16) * 10) + 1000;
  }

  Logins.isRecoverableType = function (type) {
    if (-1 === recoveryTypes.indexOf(type)) {
      return false;
    }

    return true;
  };

  Logins.notValidNode = function (node, type) {
    var err;

    if (!Formatters[type] || !Validators[type]) {
      err = Rejection.create("'" + type + "' could not be formatted / validated");
      err.code = 'E_UNKNOWN_TYPE';
      return err;
    }

    node = Formatters[type](node);
    if (!Validators[type](node)) {
      err = Rejection.create("node type does not validate");
      err.code = 'E_MALFORMED_NODE';
      return err;
    }

    return null;
  };

  Logins.notRecoverableNode = function (obj) {
    var nodeErr;
    var type = getType(obj.node, obj.type);
    if (-1 === knownTypes.indexOf(obj.type || type)) {
      nodeErr = Rejection.create("unknown type '" + obj.type + "'");
      nodeErr.code = 'E_UNKNOWN_TYPE';
      return nodeErr;
    }
    var recoverable = Logins.isRecoverableType(type);
    nodeErr = Logins.notValidNode(obj.node, type);

    if (nodeErr) {
      return nodeErr;
    }

    // TODO allow another validated user in DB as recovery node?
    if (recoverable) {
      if (Array.isArray(obj.recoveryNodes) && obj.recoveryNodes.length) {
        nodeErr = Rejection.create("a recoverable node may not have secondary recovery nodes");
        nodeErr.code = 'E_TOO_MANY_AUTHORITIES';
      }

      return nodeErr || null;
    }

    nodeErr = Rejection.create("non authoritative node");
    nodeErr.code = 'E_NO_AUTHORITY';
    return nodeErr;
  };

  Logins.notRecoverableNodes = function (obj) {
    var err;
    var errnode;

    if (!Array.isArray(obj.recoveryNodes)  || !obj.recoveryNodes.length) {
      err = Rejection.create("no recovery nodes specified");
      err.code = 'E_NO_AUTHORITY';
      return err;
    }

    if (!obj.recoveryNodes.every(function (r) {
      errnode = r;
      err = Logins.notRecoverableNode(r);

      if (!err) {
        return true;
      }

      errnode = r;
      return false;
    })) {
      return err;
    }

    return null;
  };

  Logins.notRecoverable = function (obj) {
    // TODO test instanceof Error instead of throwing it
    var err = Logins.notRecoverableNode(obj);

    if (err && 'E_NO_AUTHORITY' === err.code) {
      err = Logins.notRecoverableNodes(obj);
    }

    return err;
  };

  Logins.create = function (obj) {
    //console.log('Authn.create');
    return new PromiseA(function (resolve, reject) {
      var err;

      try {
        if (!obj.node) {
          reject(Rejection.create("no id (name, email, phone, etc) was specified"));
          return;
        }

        if (!obj.type) {
          reject(Rejection.create("no type (local, email, phone, etc) was specified"));
          return;
        }

        err = Logins.notRecoverable(obj);
        if (err) {
          reject(err);
          return;
        }
      } catch(e) {
        reject(e);
        return;
      }

      // if the root node isn't recoverable, it must have a valid password
      // if it is recoverable (email, phone), it may have a valid password
      if (Logins.notRecoverableNode(obj) || obj.secret) {
        // at least 128-bits (16-bytes, 32-hex chars) of entropy
        if (!/[a-f0-9]{32,}/i.test(obj.secret)) {
          err = Rejection.create("You must supply a secret with at least 128 bits of cryptographically secure entropy. TODO link to article showing how to use pbkdf2 with window.crypto");
          err.code = 'E_LOW_ENTROPY';
          reject(err);
          return;
        }
      }

      // TODO maybe these resolve / rejects should be in a sub function
      return Logins.unsafeGetLogin(obj).then(function (thing) {
        var salt;
        var iter;

        if (thing) {
          err = Rejection.create("user exists");
          err.code = 'E_ALREADY_EXISTS';
          reject(err);
          return;
        }

        salt = genSalt();
        iter = genIter();

        return getProofOfSecret(salt, obj.secret, iter).then(function (proof) {
          obj.secret = undefined;

          return DB.Logins.create({
            hashId: obj.hashId
          , salt: proof.salt
          , algo: proof.algo
          , iter: proof.iter
          , bits: proof.bits
          , shadow: proof.proof

          , totpKey: obj.mfa.totp || otp.generateKey()
          , totpEnabledAt: obj.mfa.totp && Math.floor(Date.now()/1000) || null

          , proof: {
              salt: obj.salt
            , kdf: obj.kdf
            , algo: obj.algo
            , iter: obj.iter
            , bits: obj.bits
            }

          , createdAt: Date.now()
          }).then(function (/*res*/) {
            //console.log('Authn.create [20]');
            resolve(null);
            return;
          }, function (err) {
            //console.log('Authn.create [21]');
            reject(err);
            return;
          });
        });
      });
    });
  };

  Logins.unsafeGetLogin = function (obj, opts) {
    if (!obj.type) {
      obj.type = getType(obj.node, obj.type);
    }
    obj.hashId = secretutils.sha1sum(obj.type + ':' + obj.node);

    if (!(opts && opts.error)) {
      return DB.Logins.get(obj.hashId);
    }

    return DB.Logins.get(obj.hashId).then(function (login) {
      var err;

      if (!login) {
        err = Rejection.create("user doesn't exist");
        err.code = 'E_NOT_EXIST';
        return PromiseA.reject(err);
      }

      return login;
    });
  };

  Logins.rawGet = function (hashId) {
    return DB.Logins.get(hashId);
  };

  Logins.loginHelper = function (obj) {
    return Logins.unsafeGetLogin(obj, { error: true }).then(function (thing) {
      return getProofOfSecret(thing.salt, obj.secret, thing.iter).then(function (proof) {
        var err;

        if (!proof.proof || !thing.shadow) {
          throw Rejection.create('missing proof.proof or thing.shadow');
        }

        // XXX
        // IMPORTANT don't compare undefined against undefined!
        // XXX
        if (proof.proof && thing.shadow && proof.proof === thing.shadow) {
          return thing;
        }

        // TODO rate limit attempts
        err = Rejection.create("The passphrase you provided is incorrect.");
        err.code = 'E_INVALID_SECRET';

        return PromiseA.reject(err);
      }).then(function (login) {
        var err;

        if (!login.totpEnabledAt || !login.totpKey) {
          return login;
        }

        if (obj.totp && require('authenticator').verifyToken(login.totpKey, obj.totp)) {
          return login;
        }

        // TODO rate limit attempts
        err = Rejection.create("The Authenticator Token you entered was either expired or incorrect.");
        err.code = 'E_INVALID_TOTP';

        return PromiseA.reject(err);
      });
    });
  };

  Logins.login = function (obj) {
    return Logins.loginHelper(obj);
  };

  Logins.credentialsAreValid = function (obj) {
    return Logins.loginHelper(obj).then(function (login) {
      return !!login;
    });
  };

  Logins.totpIsValid = function (obj) {
    return Logins.unsafeGetLogin(obj, { error: true }).then(function (login) {
      var err;

      if (!login.totpEnabledAt || !login.totpKey) {
        err = Rejection.create("totp is not enabled");
        err.code = 'E_NO_TOTP';
        return PromiseA.reject(err);
      }

      if (obj.totp && require('authenticator').verifyToken(login.totpKey, obj.totp)) {
        return true;
      }

      // TODO rate limit attempts
      err = Rejection.create("invalid token");
      err.code = 'E_INVALID_TOTP';

      return PromiseA.reject(err);
    });
  };

  Logins.getRecoverableNodes = function (obj) {
    var nodes = [];

    if (!Logins.notRecoverableNode(obj)) {
      nodes.push({ type: obj.type, node: obj.node });
    }

    if (!Array.isArray(obj.recoveryNodes)) {
      return nodes;
    }

    obj.recoveryNodes.reduce(function (r) {
      if (!Logins.notRecoverableNode(r)) {
        nodes.push({ type: r.type, node: r.node });
      }

      return nodes;
    }, nodes);

    return nodes;
  };

  // TODO getMeta
  Logins.getMeta = Logins.getKdf = function (obj) {
    return Logins.unsafeGetLogin(obj).then(function (login) {
      //var err;

      if (!login) {
        //err = Rejection.create("user doesn't exist");
        //err.code = 'E_NOT_EXIST';
        //throw err;
        return null;
      }

      login.proof.totpEnabledAt = login.totpEnabledAt;
      // TODO give hint instead of full node
      login.proof.recoverableNodes = Logins.getRecoverableNodes(login);
      return login.proof;
    });
  };

  Logins.isVerified = function (obj) {
    var err = Logins.notRecoverableNode(obj);
    var nodeId = secretutils.sha1sum(obj.type + ':' + obj.node);
    var fields;
    var params;

    if (err) {
      return new PromiseA(function (resolve, reject) {
        reject(err);
      });
    }

    fields = { nodeId: nodeId };
    params = { orderBy: 'createdAt', orderByDesc: true };
    // TODO sort and limit verifications
    return DB.Verifications.find(fields, params).then(function (things) {
      // TODO filter deleted verifications (and verifications that are too old?)
      return Array.isArray(things) && things.length >= 1;
    });
  };

  Logins.claim = function (obj) {
    var nodeId = secretutils.sha1sum(obj.type + ':' + obj.node);

    return AuthCodes.create({ checkId: nodeId, hri: 'email' === obj.type });
  };

  /*
   * type
   * node
   * claim: uuid, code
   *
   * @returns .then() success, .error() failure
   */
  Logins.validateClaim = function (obj) {
    // TODO what was obj.expiresIn for?
    var nodeId = secretutils.sha1sum(obj.type + ':' + obj.node);
    var claim = obj.claim;

    return AuthCodes.validate(claim.uuid, claim.code, { checkId: nodeId, destroy: true }).then(function (/*code*/) {
      // TODO how was hashId supposed to be deterministic for verifications?
      return DB.Verifications.create(secretutils.sha1sum(Date.now() + nodeId), { nodeId: nodeId });
    });
  };

  Logins.hasRecoverableNode = function (node, recoverable) {
    if (!recoverable) {
      return PromiseA.resolve(false);
    }

    return Logins.unsafeGetLogin(node).then(function (login) {
      var recoverables = Logins.getRecoverableNodes(login);

      if (recoverables.some(function (r) {
        return recoverable.type === r.type && recoverable.node === r.node;
      })) {
        return login;
      }

      return false;
    });
  };

  /*
   * obj.newSecret => { algo, kdf, iter, salt, secret }
   */
  Logins.unsafeResetPasswordHelper = function (obj) {
    return Logins.unsafeGetLogin(obj).then(function (login) {
      return Logins.changePasswordHelper(login, obj);
    });
  };

  Logins.changePasswordHelper = function (login, obj) {
    var err;
    var salt;
    var iter;

    if (!login) {
      err = Rejection.create("The passphrase you entered is not your current passphrase.");
      err.code = 'E_INVALID_SECRET';
      return PromiseA.reject(err);
    }

    salt = genSalt();
    iter = genIter();

    return getProofOfSecret(salt, obj.newSecret.secret, iter).then(function (proof) {
      obj.secret = undefined;

      if (!Array.isArray(login.oldSecrets)) {
        login.oldSecrets = [];
      }

      // we may want to be able to test if something is an old password
      login.oldSecrets.push({
        salt: login.salt
      , algo: login.algo
      , iter: login.iter
      , bits: login.bits
      , shadow: login.shadow

      , proof: login.proof

      , createdAt: login.createdAt
      , destroyedAt: Date.now()
      });

      /*
      , totpKey: login.totpKey
      , totpEnabledAt: null
      */
      login.salt = proof.salt;
      login.algo = proof.algo;
      login.iter = proof.iter;
      login.shadow = proof.proof;
      login.createdAt = Date.now();

      login.proof = {
        salt: obj.newSecret.salt
      , kdf: obj.newSecret.kdf
      , algo: obj.newSecret.algo
      , iter: obj.newSecret.iter
      , bits: obj.newSecret.bits
      };

      return DB.Logins.set(login.hashId, login);
    });
  };

  Logins.changePassword = function (obj) {
    // node
    // type
    // secret
    // oldSecret
    return Logins.loginHelper(obj).then(function (login) {
      return Logins.changePasswordHelper(login, obj);
    });
  };

  /*
   * obj.claim
   * obj.newSecret
   */
  Logins.loginViaClaim = function (obj) {
    return Logins.hasRecoverableNode(obj, obj.recoverableNode).then(function (login) {
      var err;

      if (!login) {
        err = Rejection.create("that claim is invalid for this account");
        err.code = 'E_INVALID_CLAIM';
        return PromiseA.reject(err);
      }

      return Logins.validateClaim({
        type: obj.recoverableNode.type
      , node: obj.recoverableNode.node
      , claim: obj.claim
      }).then(function () {
        return login;
      });
    });
  };

  /*
   * obj.claim
   * obj.newSecret
   */
  Logins.resetPasswordViaClaim = function (obj) {
    // Claim must be made against a recovery node
    // type
    // node
    // recoverableNode: { uuid, code }
    // claim: { uuid, code }
    // newSecret: { secret, algo, kdf, algo, iter }
    return Logins.loginViaClaim(obj).then(function (login) {
      return Logins.changePasswordHelper(login, obj);
    });
  };

  // turn on MFA without login (the parent service controls the session)
  Logins.unsafeTurnOnMfa = function (obj) {
    var err;

    if ('string' !== typeof obj.totpKey || !/\w{32}/.test(obj.totpKey.replace(/\s+/g, ''))) {
      err = Rejection.create("Invalid TOTP Key (expected 32 chars of 160-bit base32 key)");
      err.code = 'E_INVALID_TOTP_KEY';
      return PromiseA.reject(err);
    }

    if (!otp.verifyToken(obj.totpKey, obj.totpToken)) {
      err = Rejection.create("Invalid TOTP Token (expected to match key)");
      err.code = 'E_INVALID_TOTP_TOKEN';
      return PromiseA.reject(err);
    }

    return Logins.unsafeGetLogin(obj).then(function (login) {
      login.totpKey = obj.totpKey;
      login.totpEnabledAt = Date.now();

      return DB.Logins.save(login);
    });
  };

  Logins.verifyTotp = function (obj) {
    return Logins.unsafeGetLogin(obj).then(function (login) {
      return otp.verifyToken(login.totpKey, obj.token);
    });
  };

  // TODO Logins.exists

  /*
  return Logins.create({
    id: '#coolaj86'
  , type: 'instagram'
  , secret: 'TODO_PROOF_OF_SECRET'
  });
  */

  return Logins;
};
