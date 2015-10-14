'use strict';

var pbkdf2 = require('../lib/pbkdf2-utils');
// crypto.randomBytes(16).toString('hex');
var salt = '942c2db750b5f57f330226b2b498c6d3';
var iter = 1672;
var secret = 'Pizzas are like children';

pbkdf2.getProofOfSecret(salt, secret, iter).then(function (proof) {
  console.log('proof', proof);
});
