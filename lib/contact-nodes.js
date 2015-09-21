'use strict';

//var PromiseA = require('bluebird');
var secretutils = require('secret-utils');
  //, UUID = require('uuid')
  //, formatNumber = require('./comms/format-number').formatNumber
  //, validate = require('./st-validate').validate
var formatNumber = require('./format-number').formatNumber;
var validators = {
  phone: function (phone) {
    return formatNumber(phone);
  }
, email: function (email) {
    return email && /[^@ ]+@[^@ ]+\.[^@ ]+/.test(email);
  }
, username: function (username) {
    return username && /[\-\.a-z0-9_]+/.test(username);
  }
};
var formatters = {
  phone: function (phone) {
    // this also formats
    return validators.phone(phone) || undefined;
  }
, email: function (email) {
    return validators.email(email) && email.toLowerCase() || undefined;
  }
, username: function (username) {
    return validators.username(username) && username.toLowerCase() || null;
  }
};

function getType(node) {
  return (validators.phone(node) && 'phone')
    || (validators.email(node) && 'email')
    || (validators.username(node) && 'username')
    || null
    ;
}

module.exports.formatters = formatters;
module.exports.validators = validators;
module.exports.getType = getType;

module.exports.createController = function (config, CnDb) {
  function ContactNodes() {
  }

  ContactNodes.formatters = formatters;
  ContactNodes.validators = validators;

  ContactNodes.upsert = function (type, node) {
    type = type || ContactNodes.getNodeType(node);
    var fnode = ContactNodes.formatNode(type, node);
    var cnid = ContactNodes.getId(type, node);

    return CnDb.get(cnid).then(function (cn) {
      if (cn) { return cn; }

      return CnDb.upsert(cnid, { id: cnid, type: type, node: fnode });
    });
  };

  ContactNodes.getId = function (type, node) {
    if (!node) {
      return null;
    }

    type = type || ContactNodes.getNodeType(node);
    var fnode = ContactNodes.formatNode(type, node);
    var cnid = fnode && secretutils.sha1sum(type + ':' + fnode);

    return cnid;
  };

  ContactNodes.getType = getType;

  ContactNodes.getNodeType = function (node) {
    if (ContactNodes.formatters.email(node)) {
      return 'email';
    }

    if (ContactNodes.formatters.phone(node)) {
      return 'phone';
    }

    if (ContactNodes.formatters.username(node)) {
      return 'username';
    }

    return null;
  };

  ContactNodes.formatNode = function (type, node) {
    type = type || ContactNodes.getNodeType(node);
    if (!ContactNodes.validators[type]) {
      // PromiseA.reject(new Error("Did not understand " + type));
      return null;
    }
    /*
          ContactNodes.formatters.email(node)
          || ContactNodes.formatters.phone(node)
          || ContactNodes.formatters.username(node)
    */
    return ContactNodes.formatters[type](node);
  };

  return ContactNodes;
};

module.exports.createView = function (config, DB) {
  var ContactNodes = module.exports.createController(config, DB);

  return ContactNodes;
};

module.exports.create = function (config, DB) {
  var ContactNodes = module.exports.createView(config, DB);

  function route() {
  }

  return {
    route: route
  , ContactNodes: ContactNodes
  };
};
