'use strict';

var path = require('path');
var cluster = require('cluster');
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
  var sqlite3 = require('./sqlite3-server');

  return sqlite3.create({
      key: '1892d335081d8d346e556c9c3c8ff2c3'
    , bits: 128
    , filename: path.join('/tmp/authn.sqlcipher')
    , verbose: false
  });
}

if (cluster.isMaster) {
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
  console.log('cluster.worker.id');
  console.log(cluster.worker.id);

  if (1 === cluster.worker.id) {
    var test = require('./index');
    //sqlClient.create(cluster.isMaster);

    setTimeout(function () {
      sqlClient.then(test.test);
      //sqlClient.create(cluster.isMaster);
    }, 100);
  }
}
