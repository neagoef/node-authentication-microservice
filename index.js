'use strict';

function wrap(db, opts) {
  // TODO if I put a failure right here,
  // why doesn't the unhandled promise rejection fire?
  var PromiseA = require('bluebird');
  var DB = {};
  var tablename = db.escape('authn');
  var idname = db.escape('id');
  var UUID = require('node-uuid');

  db = PromiseA.promisifyAll(db);

  if (opts && opts.verbose || db.verbose) {
    console.log('Getting Verbose up in here');
    db.on('trace', function (str) {
      console.log('SQL:', str);
    });

    db.on('profile', function (sql, ms) {
      console.log('Profile:', ms);
    });
  }

  function simpleMap(rows) {
    if (!rows) {
      return [];
    }

    var results = rows.map(function (row, i) {
      // set up for garbage collection
      rows[i] = null;

      var obj;

      if (row.json) {
        obj = JSON.parse(row.json);
      } else {
        obj = {};
      }

      obj[idname] = row[idname];
    });
    // set up for garbage collection
    rows.length = 0;
    rows = null;

    return results;
  }

  DB.find = function (opts) {
    var sql = 'SELECT * FROM ' + tablename + ' WHERE ';
    Object.keys(opts).forEach(function (key, i) {
      if (i !== 0) {
        sql += 'AND ';
      }
      sql += db.escape(key) + ' ' + db.escape(opts[key]);
    });

    return db.getAsync("SELECT * FROM " + tablename + " " + sql, []).then(simpleMap);
  };

  DB.get = function (id) {
    return db.getAsync("SELECT * FROM " + tablename + " WHERE " + idname + " = ?", [id]).then(simpleMap);
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

  DB.save = function (data) {
    if (!data[idname]) {
      // NOTE saving the id both in the object and the id for now
      data[idname] = UUID.v4();
      return DB.create(data[idname], data).then(function (/*stats*/) {
        //data._rowid = stats.id;
        return data;
      });
    }

    return DB.set(data[idname], data).then(function (result) {
      var success = result.changes >= 1;

      if (success) {
        return result;
      }
    });
  };

  DB.create = function (id, data) {
    console.log('data');
    console.log(data);
    var json = JSON.stringify(data);

    return new PromiseA(function (resolve, reject) {
      db.run("INSERT INTO " + tablename + " (" + idname + ", json) VALUES (?, ?)", [id, json], function (err) {
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

        //this.id = id;
        resolve(this);
      });
    });
  };

  DB.set = function (id, data) {
    var json = JSON.stringify(data);

    return new PromiseA(function (resolve, reject) {
      db.run("UPDATE " + tablename + " SET json = ? WHERE " + idname + " = ?", [json, id], function (err) {
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

  DB.destroy = function (id) {
    if ('object' === typeof id) {
      id = id[idname];
    }
    return new PromiseA(function (resolve, reject) {
      db.run("DELETE FROM " + tablename + " WHERE " + idname + " = ?", [id], function (err) {
        if (err) {
          reject(err);
          return;
        }

        // it isn't possible to tell if the update succeeded or failed
        // only if the update resulted in a change or not
        console.log(this); // sql, lastID, changes
        console.log(this.sql);
        console.log('delete lastID', this.lastID); // always 0 (except on INSERT)
        console.log('delete changes', this.changes);

        resolve(this);
      });
    });
  };

  DB._db = db;

  return new PromiseA(function (resolve, reject) {
    db.runAsync("CREATE TABLE IF NOT EXISTS '" + tablename
      + "' (" + idname + " TEXT, secret TEXT, json TEXT, PRIMARY KEY(" + idname + "))"
    ).then(function () { resolve(DB); }, reject);
  });
}

module.exports.wrap = wrap;
