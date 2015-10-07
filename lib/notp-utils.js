'use strict';

var crypto = require('crypto');
var b32 = require('thirty-two');

// Generate a key
function generateOtpKey() {
  // 20 cryptographically random binary bytes (160-bit key)
  var key = crypto.randomBytes(20);

  return key;
}

// Text-encode the key as base32 (in the style of Google Authenticator - same as Facebook, Microsoft, etc)
function encodeGoogleAuthKey(bin) {
  // 32 ascii characters without trailing '='s
  var base32 = b32.encode(bin).toString('utf8').replace(/=/g, '');

  // lowercase with a space every 4 characters
  var key = base32.toLowerCase().replace(/(\w{4})/g, "$1 ").trim();

  return key;
}

// Binary-decode the key from base32 (Google Authenticator, FB, M$, etc)
function decodeGoogleAuthKey(key) {
  // decode base32 google auth key to binary
  var unformatted = key.replace(/\s+/g, '').toUpperCase();
  var bin = b32.decode(unformatted);

  return bin;
}

// Generate a Google Auth Token
function generateGoogleAuthToken(key) {
  var bin = decodeGoogleAuthKey(key);
  var notp = require('notp');

  return notp.totp.gen(bin);
}

// Verify a Google Auth Token
function verifyGoogleAuthToken(key, token) {
  var bin = decodeGoogleAuthKey(key);
  var notp = require('notp');

  token = token.replace(/\s+/g, '');

  // window is +/- 1 period of 30 seconds
  return notp.totp.verify(token, bin, { window: 1, time: 30 });
}

var ascii = encodeGoogleAuthKey(generateOtpKey());
var token = generateGoogleAuthToken(ascii);
console.log('[OTP] key', ascii);
console.log('[OTP] token', token);

console.log('[OTP] fail', verifyGoogleAuthToken(ascii, '000 000'));
console.log('[OTP] success', verifyGoogleAuthToken(ascii, token));
