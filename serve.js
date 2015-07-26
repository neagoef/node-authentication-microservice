'use strict';

var path = require('path');
var cluster = require('cluster');
//var numCores = 2;
var numCores = require('os').cpus().length;
var numWorkers = 0;
var sqlClient; // = require('./index');

function spawnWorkers() {
  // Fork workers.
  while (numWorkers < numCores) {
    cluster.fork();
    numWorkers += 1;
  }
}

function createClient() {
  var sqlite3 = require('sqlite3-cluster');

  return sqlite3.create({
      filename: path.join('/tmp/authn.sqlcipher')
    , verbose: true

    , standalone: (1 === numCores)
    , serve: cluster.isMaster
    //, serve: (numCores > 1) && cluster.isMaster
    , connect: cluster.isWorker
    //, connect: (numCores > 1) && cluster.isWorker
    //
    , key: '1892d335081d8d346e556c9c3c8ff2c3'
    , bits: 128
  });
}

if (cluster.isMaster) {
  console.log(require('os').cpus());

  spawnWorkers();

  cluster.on('exit', function(worker, code, signal) {
    numWorkers -= 1;
    console.log('worker ' + worker.process.pid + ' died with ' + code + ':' + signal);
    spawnWorkers();
  });
}

sqlClient = createClient();
sqlClient.then(function (db) {
  console.log('[db]', !!db);
});

if (cluster.isWorker) {
  console.log('cluster.worker.id', cluster.worker.id);

  if (1 === cluster.worker.id) {
    var test = require('./index');
    //sqlClient.create(cluster.isMaster);

    setTimeout(function () {
      console.log('sqlClient promise weird');
      sqlClient.then(test.test, function (err) {
        console.error('unhandled rejection');
        console.error(err);
      });
      //sqlClient.create(cluster.isMaster);
    }, 100);
  }
}

// The native Promise implementation ignores errors because... dumbness???
process.on('unhandledPromiseRejection', function (err) {
  console.error('Unhandled Promise Rejection');
  console.error(err);
  console.error(err.stack);

  process.exit(1);
});
