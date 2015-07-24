'use strict';

/*
  // Workers can share any TCP connection
  // In this case its a HTTP server
  http.createServer(function(req, res) {
    res.writeHead(200);
    res.end("hello world\n");
  }).listen(8000);
*/

// This service is intended to be bound on 127.0.0.1,
// DO NOT expose it to the internet
module.exports = function () {
  var router = require('express').Router();
  var bodyParser = require('body-parser');
  var db;

  // if multiple cores, use http
  // if single core, require directly
  router.use('/', function (req, res, next) {
    if (!db) {
      res.send({ error: { code: 'E_NO_INIT', message: "database must be initialized" } });
      return;
    }

    next();
  });

  router.use('/', bodyParser.json());

  router.get('/init', function (req, res) {
    var authdb = require('./index');
    var conf = req.body;

    if (db) {
      res.send({ error: { code: 'E_INIT_COMPLETE', message: 'the initialization has already happened' } });
      return;
    }

    // TODO get ROOT on create
    // TOOD check key, bits, storage
    authdb.create({
      key: conf.key
    , bits: conf.bits
    , storage: conf.storage // './authn.sqlcipher'
    }).then(function (_db) {
      db = _db;
      // TODO send root user details?
      res.send({ success: true });
    }, function (err) {
      // it's safe to send the raw message because
      // this is an internal microservice
      res.send({ error: { message: err.message } });
    });
  });

  router.get('/values/:id', function (req, res) {
    var id = req.params.id;

    db.get(id).then(function (data) {
      res.send(data);
    }, function (err) {
      res.send({ error: { message: err.message } });
    });
  });

  /*
  router.post('/values/new', function (req, res) {
  });
  */

  router.post('/values/:id', function (req, res) {
    var id = req.params.id;
    var data = req.body;

    db.upsert(id, data).then(function () {
      res.send({ success: true });
    }, function (err) {
      res.send({ error: { message: err.message } });
    });
  });

  return router;
};
