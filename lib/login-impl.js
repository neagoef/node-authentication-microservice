'use strict';

var PromiseA = require('bluebird');

module.exports.create = function (config, AuthCodes, DB) {
  var Validators = require('./contact-nodes.js').validators;
  var Formatters = require('./contact-nodes.js').formatters;
  var getType = require('./contact-nodes.js').getType;
  // TODO twitter is recoverable
  // TODO check for a validated username
  var recoveryTypes = ['email', 'phone'];
  var knownTypes = ['username'].concat(recoveryTypes);
  var secretutils = require('secret-utils');

  function Logins() {
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
      err = new Error("'" + type + "' could not be formatted / validated");
      err.code = 'E_UNKNOWN_TYPE';
      return err;
    }

    node = Formatters[type](node);
    if (!Validators[type](node)) {
      err = new Error("node type does not validate");
      err.code = 'E_MALFORMED_NODE';
      return err;
    }

    return null;
  };

  Logins.notRecoverableNode = function (obj) {
    var nodeErr;
    var type = getType(obj.node, obj.type);
    if (-1 === knownTypes.indexOf(obj.type || type)) {
      nodeErr = new Error("unknown type '" + obj.type + "'");
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
        nodeErr = new Error("a recoverable node may not have secondary recovery nodes");
        nodeErr.code = 'E_TOO_MANY_AUTHORITIES';
      }

      return nodeErr || null;
    }

    nodeErr = new Error("non authoritative node");
    nodeErr.code = 'E_NO_AUTHORITY';
    return nodeErr;
  };

  Logins.notRecoverableNodes = function (obj) {
    var err;
    var errnode;

    if (!Array.isArray(obj.recoveryNodes)  || !obj.recoveryNodes.length) {
      err = new Error("no recovery nodes specified");
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
    return new PromiseA(function (resolve, reject) {
      var err;

      try {
        if (!obj.node) {
          reject(new Error("no id (name, email, phone, etc) was specified"));
          return;
        }

        if (!obj.type) {
          reject(new Error("no type (local, email, phone, etc) was specified"));
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
          err = new Error("You must supply a secret with at least 128 bits of cryptographically secure entropy. TODO link to article showing how to use pbkdf2 with window.crypto");
          err.code = 'E_LOW_ENTROPY';
          reject(err);
          return;
        }
      }

      // TODO maybe these resolve / rejects should be in a sub function
      obj.hashId = secretutils.sha1sum(obj.type + ':' + obj.node);

      return DB.Logins.get(obj.hashId).then(function (thing) {
        if (thing) {
          err = new Error("user exists");
          err.code = 'E_ALREADY_EXISTS';
          reject(err);
          return;
        }

        return DB.Logins.create(obj).then(function (/*res*/) {
          resolve(null);
          return;
        }, function (err) {
          reject(err);
          return;
        });
      });
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

  Logins.validateClaim = function (claim) {
    return AuthCodes.validate(claim.uuid, claim.token, { destroy: true }).then(function (code) {
      var nodeId = secretutils.sha1sum(claim.type + ':' + claim.node);
      var err;

      if (nodeId !== code.checkId) {
        err = new Error('this claim not valid for this account');
        err.code = 'E_FORGED_CLAIM';
        return PromiseA.reject();
      }

      return true;
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
