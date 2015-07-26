'use strict';

function test(db) {
  // TODO if I put a failure right here,
  // why doesn't the unhandled promise rejection fire?
  //var sqlite3 = require('./sqlite3-server');
  var sqlite3 = require('sqlite3-cluster');
  var PromiseA = require('bluebird');
  var DB = {};
  var tablename = 'authn';

  db = PromiseA.promisifyAll(db);

  db.on('trace', function (str) {
    console.log('SQL:', str);
  });

  db.on('profile', function (sql, ms) {
    console.log('Profile:', ms);
  });

  DB.get = function (id) {
    return db.getAsync("SELECT * FROM authn WHERE id = ?", [id]);
  };

  DB.upsert = function (id, data) {
    return DB.set(id, data).then(function (result) {
      var success = result.changes >= 1;

      if (success) {
        return result;
      }

      return DB.create(id, data);
    });
  };

  DB.create = function (id, data) {
    var json = JSON.stringify(data);

    return new PromiseA(function (resolve, reject) {
      db.run("INSERT INTO authn (id, json) VALUES (?, ?)", [id, json], function (err) {
        if (err) {
          reject(err);
          return;
        }

        // NOTE changes is 1 even if the value of the updated record stays the same
        // (PostgreSQL would return 0 in that case)
        // thus if changes is 0 then it failed, otherwise it succeeded
        console.log(this); // sql, lastID, changes
        console.log(this.sql);
        console.log('insert lastID', this.lastID); // sqlite's internal rowId
        console.log('insert changes', this.changes);

        resolve(this);
      });
    });
  };

  DB.set = function (id, data) {
    var json = JSON.stringify(data);

    return new PromiseA(function (resolve, reject) {
      db.run("UPDATE authn SET json = ? WHERE id = ?", [json, id], function (err) {
        if (err) {
          reject(err);
          return;
        }

        // it isn't possible to tell if the update succeeded or failed
        // only if the update resulted in a change or not
        console.log(this); // sql, lastID, changes
        console.log(this.sql);
        console.log('update lastID', this.lastID); // always 0 (except on INSERT)
        console.log('update changes', this.changes);

        resolve(this);
      });
    });
  };

  return new PromiseA(function (resolve, reject) {
    db.runAsync("CREATE TABLE IF NOT EXISTS '" + sqlite3.sanitize(tablename)
      + "' (id TEXT, secret TEXT, json TEXT, PRIMARY KEY(id))"
    ).then(function () { resolve(DB); }, reject);
  }).then(function (DB) {
    var data = { secret: 'super secret', verifiedAt: 1437207288791 };
    //return DB.set('aj@the.dj', data)
    //return DB.set('coolaj86@gmail.com', data)
    // return DB.upsert('awesome@coolaj86.com', data)
    return DB.upsert('awesome@coolaj86.com', data).then(function () {
      console.log('added user');
    });

    /*
    return DB.create('coolaj86@gmail.com', data).then(function () {
      console.log('added user');
    });
    */

    // need to 'DELETE FROM authn;' first
    return DB.get('coolaj86@gmail.com').then(function (user) {
      if (user) {
        console.log('user', user);
        return;
      }

      //var data = { secret: 'super secret', verifiedAt: Date.now() };
      var data = { secret: 'super secret', verifiedAt: 1437207288790 };
      return DB.create('coolaj86@gmail.com', data).then(function () {
        console.log('added user');
      });

    });
  }).then(function () {}, function (err) {
    // code SQLITE_CONSTRAINT
    // errno 19

    console.error('[ERROR] during test');
    //console.error(Object.keys(err)); // errno, code
    console.error(err);

  });
}

function create(/*isMaster*/) {
  var path = require('path');
  var sqlite3 = require('./sqlite3-server');

  var promise = sqlite3.create({
      key: '1892d335081d8d346e556c9c3c8ff2c3'
    , bits: 128
    , filename: path.join('/tmp/authn.sqlcipher')
    , verbose: false
  });

  return promise;

  /*
  if (require.main === module) {
    // crypto.randomBytes(16).toString('hex');
    create({
      key: '1892d335081d8d346e556c9c3c8ff2c3'
    , bits: 128
    , filename: '/tmp/authn.sqlcipher'
    }).then(function (DB) {
    });
  }
  */
}

module.exports.create = create;
module.exports.test = test;
