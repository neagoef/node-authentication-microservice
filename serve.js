'use strict';

//var path = require('path');
var cluster = require('cluster');
var numCores = 2;
//var numCores = require('os').cpus().length;
var numWorkers = 0;
var sqlClient; // = require('./index');
var initComplete;
var workers = [];

function spawnWorkers(workers) {
  var worker;

  // Fork workers.
  while (numWorkers < numCores) {
    worker = cluster.fork();
    workers.push(worker);
    numWorkers += 1;

    if (initComplete) {
      worker.send({ init: true });
    }
  }

  return workers;
}

function createClient() {
  var config = require('./config.test.js');
  var sqlite3 = require('sqlite3-cluster');

  var promise = sqlite3.create({
      standalone: (1 === numCores)
    , serve: cluster.isMaster
    //, serve: (numCores > 1) && cluster.isMaster
    , connect: cluster.isWorker
    //, connect: (numCores > 1) && cluster.isWorker
    , bits: 128
    , filename: config.filename
    , verbose: false
  });

  if (!cluster.isMaster) {
    return promise;
  }

  return promise.then(function (db) {
    return db.init({ bits: 128, key: config.key }).then(function (db) {
      initComplete = true;

      workers.forEach(function (worker) {
        worker.send({ init: true });
      });

      return db;
    });
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

  /*
  var sqlite3 = require('sqlite3-cluster');

  return sqlite3.create({
      filename: path.join(require('./config.test.js').filename)
    , verbose: true

    , standalone: (1 === numCores)
    , serve: cluster.isMaster
    //, serve: (numCores > 1) && cluster.isMaster
    , connect: cluster.isWorker
    //, connect: (numCores > 1) && cluster.isWorker
    //
    , key: require('./config.test.js').key
    , bits: 128
  });
  */
}

function setupMaster() {
  spawnWorkers(workers);

  cluster.on('exit', function(worker, code, signal) {
    var j;
    workers.forEach(function (w, i) {
      if (worker.process.pid === w.pid) {
        j = i;
      }
    });
    workers.splice(j, 1);

    numWorkers -= 1;

    console.log('worker ' + worker.process.pid + ' died with ' + code + ':' + signal);
    spawnWorkers(workers);
  });
}

function setupWorker() {
  process.on('message', function (msg) {
    console.log('cluster.worker.id', cluster.worker.id);

    if (!msg.init) {
      console.warn('Unexpected Message');
      console.warn(msg);
      return;
    }

    if (initComplete) {
      return;
    }
    initComplete = true;

    sqlClient.then(function (db) {
      var http = require('http');
      var server = http.createServer();
      var port = 8088;
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

      return wrap.wrap(db, dir).then(function (DB) {
        return require('./app').create(server, DB).then(function (app) {
          server.on('request', app);
          server.listen(port);
        });
      });
    });
  });
}

if (cluster.isMaster) {
  setupMaster();
}

sqlClient = createClient();

if (cluster.isWorker) {
  setupWorker();
}

// The native Promise implementation ignores errors because... dumbness???
process.on('unhandledRejection', function (err) {
  console.error('Unhandled Promise Rejection');
  console.error(err);
  console.error(err.stack);

  process.exit(1);
});
