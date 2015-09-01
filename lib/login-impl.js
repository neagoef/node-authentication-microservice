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

  Logins.isRecoverableNode = function (node, type) {
    type = getType(node, type);

    // TODO check for validated user in DB
    if (-1 === recoveryTypes.indexOf(type)) {
      throw new Error("non-recoverable type '" + type + "' for '" + node + "'");
    }

    node = Formatters[type](node);
    if (!Validators[type](node)) {
      throw new Error("node type does not validate");
    }

    return true;
  };

  Logins.isRecoverable = function (obj) {
    var errnode;

    if (Logins.isRecoverableNode(obj.node, obj.type)) {
      if (Array.isArray(obj.recoveryNodes)) {
        throw new Error("a recoverable node may not have secondary recovery nodes");
      }
      return true;
    } else if (!Array.isArray(obj.recoveryNodes)) {
      throw new Error("no recovery nodes specified");
    }

    if (!obj.recoveryNodes.every(function (r) {
      if (Logins.isRecoverableNode(r.node, r.type)) {
        return true;
      }

      errnode = r;
    })) {
      throw new Error("node '" + errnode.type + ":" + errnode.node + "' is not a valid recovery node");
    }
  };

  Logins.create = function (obj) {
    return new PromiseA(function (resolve, reject) {
      try {
        if (!obj.node) {
          reject(new Error("no id (name, email, phone, etc) was specified"));
          return;
        }

        if (!obj.type) {
          reject(new Error("no type (local, email, phone, etc) was specified"));
          return;
        }

        if (-1 === knownTypes.indexOf(obj.type)) {
          reject(new Error("unknown type '" + obj.type + "'"));
          return;
        }

        if (!Validators[obj.type](obj.node)) {
          reject(new Error("'" + obj.node + "' is not of type '" + obj.type + "'"));
          return;
        }

        if (!Logins.isRecoverable(obj)) {
          reject(new Error("a login must have a recovery method"));
          return;
        }
      } catch(e) {
        reject(e);
      }

      // TODO maybe these resolve / rejects should be in a sub function
      obj.hashId = secretutils.sha1sum(obj.type + ':' + obj.node);

      console.log('blah1', obj.hashId);
      return DB.Logins.get(obj.hashId).then(function (thing) {
        console.log('blah2', thing);
        if (thing) {
          reject(new Error("user exists"));
          return;
        }

        return DB.Logins.create(obj).then(function (res) {
          console.log('yay', res);
          resolve(null);
          return;
        }, function (err) {
          console.log('nay', err);
          return reject(err);
        });
      });
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
