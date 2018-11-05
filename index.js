// file: index.js
var https = require("https");
var _ = require("lodash");
var express = require("express");

var bodyParser = require("body-parser");
var jwt = require('jsonwebtoken');
var jsonfile = require('jsonfile');
var passport = require("passport");
var passportJWT = require("passport-jwt");
const mongoose = require('mongoose');
var os = require("os");
var fs = require('fs');
const sysi = require('systeminformation');
var app = express();
const fkill = require('fkill');


const config = require('./db')
const users = require('./routes/user'); 
mongoose.connect(config.DB, { useNewUrlParser: true }).then(
    () => {console.log('Database is connected') },
    err => { console.log('Can not connect to the database'+ err)}
);



var Redis = require('ioredis');
var redis = new Redis({
  // This is the default value of `retryStrategy`
  retryStrategy: function (times) {
    var delay = Math.min(times * 50, 2000);
    console.log('reconnec t' + times);
    if (times > 3) return "stoop";
    return delay;
  }
});


// redis.get('foo', function (err, result) {
//  console.log(result);
// });

// Or using a promise if the last argument isn't a function
//redis.get('foo').then(function (result) {
//  console.log(result);
//});

// Arguments to commands are flattened, so the following are the same:
// redis.sadd('set', 1, 3, 5, 7);
// redis.sadd('set', [1, 3, 5, 7]);

// All arguments are passed directly to the redis server:
// redis.set('key', 100, 'EX', 10);
// redis.set('key', 100);
// const sqlite3 = require('sqlite3').verbose();

var psquid2 = '%{NUMBER:ts}\\s+%{NUMBER:duration} %{IPORHOST:client} %{WORD:result}/%{NUMBER:http_status_code} %{NUMBER:bytes} %{WORD:method} %{NOTSPACE:url} - %{WORD:hierarchy}/%{NOTSPACE:user}\\s+%{NOTSPACE:type}'
var sarray = fs.readFileSync('./rawlog/access.log').toString().split("\n")
var psquid = '%{NUMBER:timestamp}\\s+%{NUMBER:response_time}'
// define test input string


// var jsonSql = require('json-sql')();
var patterns = require('node-grok').loadDefaultSync();
var pattern = patterns.createPattern(psquid2);
var jsquid = []

for (i = 0; i < sarray.length; i++) {
  // console.log(sarray[i])
  if (sarray[i] != "")
    jsquid.push(pattern.parseSync(sarray[i]))
}

// var db = new sqlite3.Database('mamamu.db');
var knex = require('knex')({
  client: 'sqlite3',
  connection: {
    filename: "./mamamu.db"
  },useNullAsDefault: true
});





/*
db.serialize(function() {
 
  db.run("CREATE TABLE IF NOT EXISTS access (ts DATETIME, duration INTEGER, client TEXT, result TEXT, bytes INTEGER, method TEXT, url TEXT, user TEXT, hierarchy TEXT, type TEXT)");
  
  var stmt = db.prepare("INSERT INTO access VALUES (?,?,?,?,?,?,?,?,?,?)");
  for (var i = 0; i < jsquid.length; i++) {
      stmt.run( jsquid[i].ts, jsquid[i].duration, jsquid[i].client, jsquid[i].result, jsquid[i].bytes, jsquid[i].method, jsquid[i].url, jsquid[i].user, jsquid[i].hierarchy, jsquid[i].type);
  }
  stmt.finalize();

});
 */
// db.close();

var psTree = require('ps-tree');
var kill = function (pid, signal, callback) {
  signal = signal || 'SIGKILL';
  callback = callback || function () {};
  var killTree = true;
  if (killTree) {
    psTree(pid, function (err, children) {
      [pid].concat(
        children.map(function (p) {
          return p.PID;
        })
      ).forEach(function (tpid) {
        try {
          process.kill(tpid, signal)
        } catch (ex) {}
      });
      callback();
    });
  } else {
    try {
      process.kill(pid, signal)
    } catch (ex) {}
    callback();
  }
};

var exec = require('child_process').exec;
var spawn = require('child_process').spawn;
var run_it = function (cmd) {
  var child = exec('node ./commands/server.js');

  child.stdout.on('data', function (data) {
    console.log('stdout: ' + data);
  });
  child.stderr.on('data', function (data) {
    console.log('stdout: ' + data);
  });
  child.on('close', function (code) {
    console.log('closing code: ' + code);
  });
}

var ExtractJwt = passportJWT.ExtractJwt;
var JwtStrategy = passportJWT.Strategy;

var fakeusers = [{
    id: 1,
    name: 'jonathanmh',
    password: '%2yx4'
  },
  {
    id: 2,
    name: 'test',
    password: 'test'
  }
];

var jwtOptions = {}
jwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
jwtOptions.secretOrKey = 'tasmanianDevil';

var strategy = new JwtStrategy(jwtOptions, function (jwt_payload, next) {
  // console.log('payload received', jwt_payload);
  // usually this would be a database call:
  var user = fakeusers[_.findIndex(fakeusers, {
    id: jwt_payload.id
  })];
  if (user) {
    next(null, user);
  } else {
    next(null, false);
  }
});

// passport.use(strategy);

app.use(passport.initialize());
require('./passport')(passport);


// parse application/x-www-form-urlencoded
// for easier testing with Postman or plain HTML forms
app.use(bodyParser.urlencoded({
  extended: true
}));

// parse application/json
app.use(bodyParser.json())
app.use(function (req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
  next();
});



app.use(express.static('./dist'));
app.use('/settings/', express.static('settings'));
app.use('/api/users', users);
app.get("/", function (req, res) {
  res.json({
    message: "Express is up!"
  });
});

app.post("/api/run", function (req, res) {
  var xx = {}
  exec(req.body.cmd, (error, stdout, stderr) => {
    xx.return_code = 0
    if (error) {
      xx.return_code = error.code
      xx.error = error
       
    }

    xx.std_out = stdout
    xx.std_err = stderr
    res.json({
    message: "Done exec"
  });

  })
   
})

app.post("/api/kill", function (req, res) {
  var xx = {}
  fkill(req.body.cmd).then( ()  => {
    xx.return_code = 0
      res.json({
    message: "Success! You can not see this without a token"
  });
    } )
})

app.post("/api/regist", function (req, res) {


 res.json({
      message: "ok",

    });
});

app.post("/api/login", function (req, res) {

  if (req.body.name && req.body.password) {

    var name = req.body.name;
    var password = req.body.password;
  }
  // usually this would be a database call:
  var user = fakeusers[_.findIndex(fakeusers, {
    name: name
  })];
  if (!user) {
    res.status(401).json({
      message: "no such user found"
    });
  }

  if (user.password === req.body.password) {
    // from now on we'll identify the user by the id and the id is the only personalized value that goes into our token
    var payload = {
      id: user.id
    };
    var token = jwt.sign(payload, jwtOptions.secretOrKey);
    res.json({
      message: "ok",
      token: `Bearer ${token}`
    });
  } else {
    res.status(401).json({
      message: "passwords did not match"
    });
  }
});

app.get("/secret", passport.authenticate('jwt', {
  session: false
}), function (req, res) {
  res.json({
    message: "Success! You can not see this without a this koko token"
  });
  console.log("Express ss running");

});

app.get("/api/usertest", function (req, res) {
  res.json({
    message: "Success! You can not see this withofvfv ut a token"
  });
  console.log("Expressk s running");

});

app.get("/secretDebug",
  function (req, res, next) {
    console.log(req.get('Authorization'));
    next();
  },
  function (req, res) {
    res.json("debugging");
  });

app.get("/api/systeminformation",
  function (req, res, next) {


    var sysinfo = {};

    sysinfo.hostname = os.hostname();

    sysinfo.os = {};
    sysinfo.os.hostname = os.hostname();
    sysinfo.os.release = os.release();
    sysinfo.os.platform = os.platform();
    sysinfo.os.arch = os.arch();
    sysinfo.os.uptime = os.uptime();
    sysinfo.cpu = {};
    var cpu = os.cpus();
    var counter = 0;
    var total = 0;

    var idle = 0;
    var sys = 0;
    var user = 0;

    for (var i = 0; i < cpu.length; i++) {

      counter++;
      total = parseFloat(cpu[i].times.idle) + parseFloat(cpu[i].times.sys) + parseFloat(cpu[i].times.user) + parseFloat(cpu[i].times.irq) + parseFloat(cpu[i].times.nice);

      idle += 100 * (parseFloat(cpu[i].times.idle) / total);
      sys += 100 * (parseFloat(cpu[i].times.sys) / total);
      user += 100 * (parseFloat(cpu[i].times.user) / total);
    };

    sysinfo.cpu.user = (user / counter).toFixed(2);
    sysinfo.cpu.sys = (sys / counter).toFixed(2);
    sysinfo.cpu.idle = (idle / counter).toFixed(2);
    sysinfo.cpu.cpus = cpu.length;

    // sysinfo.cpu.loadavg_1_min     = os.loadavg()[0].toFixed(2);
    // sysinfo.cpu.loadavg_5_min     = os.loadavg()[1].toFixed(2);
    sysinfo.cpu.loadavg_15_min = os.loadavg()[2].toFixed(2);

    sysinfo.memory = {};
    sysinfo.memory.total = os.totalmem();
    sysinfo.memory.free = os.freemem();
    sysinfo.memory.used_perc = (100 - ((os.totalmem() - os.freemem()) / os.totalmem() * 100)).toFixed(2);

    sysinfo.disk = {};
    /* let info = disk.checkSync(path);
    sysinfo.disk.available
    sysinfo.disk.free
    sysinfo.disk.total */

    /**
     * Gets Swap info out of /proc/swaps on Linux systems.
     */


    // sysinfo.swap = getSwap();

    // console.log(sysinfo);

    res.json(sysinfo)
  });

function getSwap() {
  var swapinfo = [];

  fs.readFileSync('/proc/swaps').toString().split(os.EOL).forEach(function (line) {
    var lineArray = line.split(/\s+/);
    if (lineArray[0] != 'Filename') {
      var tempObject = {};
      tempObject.size = parseInt(lineArray[2]);
      tempObject.used = parseInt(lineArray[3]);
      tempObject.perc = (tempObject.used / tempObject.size * 100).toFixed(2);
      if (!isNaN(tempObject.size)) {
        swapinfo.push(tempObject);
      }
    }
  });

  return swapinfo;
};

app.get("/api/systemtopstat", async (req, res, next) => {
  try {

    const osinfo = await sysi.osInfo()
    const memstat = await sysi.mem()
    const fsstat = await sysi.fsStats()
    const load = await sysi.currentLoad()
    const fsinfo = await sysi.fsSize()
    const nwinfo = await sysi.networkStats('en0')
    const dsstat = await sysi.disksIO()

    for (i = 0; i < fsinfo.length; i++) {
      fsinfo[i].size = formatBytes(fsinfo[i].size)
      fsinfo[i].used = formatBytes(fsinfo[i].used)
      fsinfo[i].use = fsinfo[i].use
    }
    var sysinfo = {};
    //  sysinfo.os = {};
    //    sysinfo.os.hostname = osinfo.hostname;
    //    sysinfo.os.release = os.release();
    //    sysinfo.os.platform = os.platform();
    //    sysinfo.os.arch = os.arch();
    //    sysinfo.os.uptime = os.uptime();

    sysinfo.cpu = {};
    sysinfo.cpu.uptime = os.uptime();
    sysinfo.cpu.user = load.currentload_user.toFixed(2);;
    sysinfo.cpu.system = load.currentload_system.toFixed(2);;
    sysinfo.cpu.idle = Number(load.currentload_idle.toFixed(2));

    sysinfo.cpu.loadavg_15_min = os.loadavg()[2].toFixed(2);

    sysinfo.memory = {};
    sysinfo.memory.total = formatBytes(os.totalmem());
    // sysinfo.memory.free = os.freemem();
    //    sysinfo.memory.used = memstat.used;
    //    sysinfo.memory.buffercache = memstat.buffcache;
    sysinfo.memory.active = formatBytes(memstat.active);
    sysinfo.memory.avail = formatBytes(memstat.available);
    sysinfo.memory.used_perc = Number(((memstat.active / memstat.total) * 100).toFixed(2));

    sysinfo.network = {}
    sysinfo.network.interface = nwinfo.iface
    sysinfo.network.rx = formatBytes(nwinfo.rx)
    sysinfo.network.tx = formatBytes(nwinfo.tx)
    sysinfo.network.rx_sec = nwinfo.rx_sec.toFixed(1)
    sysinfo.network.tx_sec = nwinfo.tx_sec.toFixed(1)


    sysinfo.fsStat = {};
    sysinfo.fsStat.rx_bytes_sec = formatBytes(fsstat.rx_sec.toFixed(1))
    sysinfo.fsStat.wx_bytes_sec = formatBytes(fsstat.wx_sec.toFixed(1))

    sysinfo.diskIO = {};
    sysinfo.diskIO.rIOs_sec = dsstat.rIO_sec.toFixed(2)
    sysinfo.diskIO.wIOs_sec = dsstat.wIO_sec.toFixed(2)

    sysinfo.filesystems = {};
    sysinfo.filesystems.fsinfo = fsinfo;
    res.json(sysinfo)
  } catch (e) {

    next(e)
  }
});

app.get("/api/systemstat", async (req, res, next) => {
  try {

    const osinfo = await sysi.osInfo()
    const memstat = await sysi.mem()
    const fsstat = await sysi.fsStats()
    const load = await sysi.currentLoad()

    var sysinfo = {};

    sysinfo.os = {};
    sysinfo.os.hostname = osinfo.hostname;
    //    sysinfo.os.release = os.release();
    //    sysinfo.os.platform = os.platform();
    //    sysinfo.os.arch = os.arch();
    sysinfo.os.uptime = os.uptime();

    sysinfo.cpu = {};
    sysinfo.cpu.user = load.currentload_user.toFixed(2);;
    sysinfo.cpu.system = load.currentload_system.toFixed(2);;
    sysinfo.cpu.idle = load.currentload_idle.toFixed(2);;

    sysinfo.cpu.loadavg_15_min = os.loadavg()[2].toFixed(2);

    sysinfo.memory = {};
    sysinfo.memory.total = formatBytes(os.totalmem());
    // sysinfo.memory.free = os.freemem();
    //    sysinfo.memory.used = memstat.used;
    //    sysinfo.memory.buffercache = memstat.buffcache;
    sysinfo.memory.active = formatBytes(memstat.active);
    sysinfo.memory.avail = formatBytes(memstat.available);
    sysinfo.memory.used_perc = ((memstat.active / memstat.total) * 100).toFixed(2) + '%';

    res.json(sysinfo)
  } catch (e) {

    next(e)
  }
});

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + " Bytes";
  else if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
  else if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + " MB";
  else return (bytes / 1073741824).toFixed(1) + " GB";
};

app.get("/api/fsstat", passport.authenticate('jwt', {
  session: false
}), async (req, res, next) => {
  try {

    const fsinfo = await sysi.fsSize()

    var sysinfo = [];

    sysinfo = fsinfo
    for (i = 0; i < sysinfo.length; i++) {
      sysinfo[i].size = formatBytes(sysinfo[i].size)
      sysinfo[i].used = formatBytes(sysinfo[i].used)
      sysinfo[i].use = sysinfo[i].use + '%'
    }
    res.json(sysinfo)
  } catch (e) {

    next(e)
  }
});


app.get("/api/processess", async (req, res, next) => {
  try {

    const fsinfo = await sysi.processes()
    //  const fsinfo = await sysi.fsSize()
    var sysinfo = [];

    sysinfo = fsinfo.list

    res.json(sysinfo)
    // console.dir(sysinfo)
  } catch (e) {

    next(e)
  }
});

app.get("/api/services", async (req, res, next) => {
  try {

    const fsinfo = await sysi.services('sysmond, logd,node,mongod,redis-server')
    //  const fsinfo = await sysi.fsSize()
    var sysinfo = [];

    sysinfo = fsinfo

    res.json(sysinfo)
    // console.dir(sysinfo)
  } catch (e) {

    next(e)
  }
});



async function GetUserPoolEntry(result) {
  var sysinfo = [];

  for (const item of result) {
    var mama = item
    await redis.hgetall('user:' + mama, function (err, result1) {
      sysinfo.push(result1)
    })

  }

  return sysinfo

}

async function GetTaskPoolEntry(result) {
  var sysinfo = [];

  for (const item of result) {
    var mama = item
    await redis.hgetall('task:' + mama, function (err, result1) {
      sysinfo.push(result1)
    })

  }

  return sysinfo

}

async function GetUserRequestList(result) {
  var sysinfo = [];
  for (const item of result[0]) {
    var mama = item.toString()
    var papa = await redis.lrange(mama, '0', '-1')
    for (const its of papa) {
      await redis.hgetall('task:' + its, function (err, result1) {
        result1.owner = mama
        sysinfo.push(result1)
      })
    }
  }
  return sysinfo

}

async function GetUserApproveList(result) {
  var sysinfo = [];
  for (const item of result) {
    var mama = item
    await redis.lrange(mama, 0, -1, function (err, result1) {
      sysinfo.push(result1)
    })

  }
  return sysinfo

}

async function GetRequestEntry(result) {
  var sysinfo = [];
  for (const item of result) {
    var mama = item
    await redis.hgetall('task:' + mama, function (err, result1) {
      sysinfo.push(result1)
    })

  }
  return sysinfo

}

app.get("/api/redisuserpool", async (req, res, next) => {
  let sysinfo = [];
  const result = await redis.smembers('userpool')
  sysinfo = await GetUserPoolEntry(result)
  res.json(sysinfo)
  // redis.call('json.get', 'user', function (err, result) {
  // var sysinfo = [];
  // sysinfo.push({ 'user':result})
  // res.json(sysinfo)
  // console.dir(sysinfo)
  //})
})
app.get("/api/redismyuserpool", async (req, res, next) => {
  let sysinfo = [];
  const result = await redis.smembers('userpool')
  sysinfo = await GetUserPoolEntry(result)
  res.json(sysinfo)
  // redis.call('json.get', 'user', function (err, result) {
  // var sysinfo = [];
  // sysinfo.push({ 'user':result})
  // res.json(sysinfo)
  // console.dir(sysinfo)
  //})
})

app.get("/api/redistaskpool", async (req, res, next) => {
  let sysinfo = [];
  const result = await redis.smembers('taskpool')
  sysinfo = await GetTaskPoolEntry(result)
  res.json(sysinfo)
  // redis.call('json.get', 'user', function (err, result) {
  // var sysinfo = [];
  // sysinfo.push({ 'user':result})
  // res.json(sysinfo)
  // console.dir(sysinfo)
  //})
})

app.get("/api/redisapprovepool", async (req, res, next) => {
  let sysinfo = [];
  const result = await redis.scan(0, 'match', 'approve:*', 'count', 1000)
  if (result.shift()[0].toString() !== "") {
    sysinfo = await GetUserRequestList(result)
  }
  res.json(sysinfo)
})

app.get("/api/redisrequestpool", async (req, res, next) => {
  let sysinfo = [];
  const result = await redis.scan(0, 'match', 'request:*', 'count', 1000)
  if (result.shift()[0] !== "") {
    sysinfo = await GetUserRequestList(result)
  }
  res.json(sysinfo)

})

app.post("/api/redistransaction", async (req, res, next) => {
  let acti = req.body
  if (acti.action == "request") {
    const num = await redis.incr('id_num')
    await redis.sadd('taskpool', num)
    await redis.hmset("task:" + num, 'task', num, 'to', acti.to, 'note', acti.note, 'from', acti.from, 'state', 'wait for approval', 'instance', 'yes')
    await redis.lpush('request:' + acti.from, num)
    await redis.lpush('approve:' + acti.to, num)
    console.log(num)
  } else if (acti.action == "approve") {
    await redis.hset("task:" + acti.note, 'state', 'done')

  } else if (acti.action == "reject") {

  }

  res.json("")

})


app.get("/api/connectstatx", async (req, res, next) => {
  try {

    const fsinfo = await sysi.networkConnections()

    var sysinfo = [];

    sysinfo = fsinfo
    res.json(sysinfo)
    console.dir(sysinfo)
  } catch (e) {

    next(e)
  }
});




app.get("/api/netstat", async (req, res, next) => {
  try {

    const fsinfo = await sysi.networkStats('en0')

    var sysinfo = {};
    sysinfo.netstat = {}
    sysinfo.netstat = fsinfo
    sysinfo.netstat.rx = formatBytes(sysinfo.netstat.rx)
    sysinfo.netstat.tx = formatBytes(sysinfo.netstat.tx)
    sysinfo.netstat.rx_sec = sysinfo.netstat.rx_sec.toFixed(1)
    sysinfo.netstat.tx_sec = sysinfo.netstat.tx_sec.toFixed(1)
    res.json(sysinfo)
  } catch (e) {

    next(e)
  }
});

app.get("/api/connectstat",
  function (req, res, next) {
    sysi.networkConnections(function (data) {
      res.json(data)
      // console.dir( data)
    })
  });

app.get("/api/networkinterfaces",
  function (req, res, next) {
    sysi.networkInterfaces(function (data) {
      res.json(data)
      //  console.dir( data)
    })
  });

app.get("/api/networkinterfacesx",
  function (req, res, next) {
    /*
     data = [ {
              x: 10, y : 20 },
               { x:100, y:400 }]
     res.json( data)
     */
    sysi.networkInterfaces(function (data) {
      res.json(data)

    })
  });

app.get("/api/processx",
  function (req, res, next) {
    sysi.processes(function (data) {
      res.json(data.list)
      //   console.dir( "__"+data.list)
    })
  });


app.get("/api/getaccesslogqua_pre",
  function (req, res, next) {
    knex('access').count("rowid as CNT").then(rows => {
      return res.json(rows[0].CNT)
    })

  });

app.get("/api/getaccesslogqua_columns",
  function (req, res, next) {
    knex('access').columnInfo().then(columns => {
      return res.json(columns)
    })

  });

app.get("/api/getaccesslogqua",
  function (req, res, next) {
    var xx = req.query
    var cond = JSON.parse(xx.props)
    var page_num = cond.pagination.page - 1
    var page_size = cond.pagination.rowsPerPage

    knex('access').select().limit(page_size).offset(page_num * page_size).then(rows => {
      return res.json(rows)
    })

  });

/*
 app.get("/api/getaccesslog",  
  function (req, res, next) {
      var xx = req.query
      var page_num = xx.page -1
      var page_size = xx.page_size
      var type = xx.type
      if ( type == 'init' ) {
         db.all("SELECT rowid AS id, ts, duration  , client  , result  , bytes  , method  , url , user, hierarchy  , type  FROM access "+page_size.toString()+" OFFSET "+(page_num * page_size).toString(), function(err, row) {
         return res.json(row)
         })
      }
      else { 
        db.all("SELECT rowid AS id, ts, duration  , client  , result  , bytes  , method  , url , user, hierarchy  , type  FROM access LIMIT "+page_size.toString()+" OFFSET "+(page_num * page_size).toString(), function(err, row) {
         return res.json(row)
      });
      }
  
  });
  */

app.get("/api/getaccesslog1",
  function (req, res, next) {
    var xx = req.query
    var page_num = xx.page - 1
    var page_size = xx.page_size
    var type = xx.type
    var cond = ''
    var sql = ''
    if (xx.condition != null) {
      cond = JSON.parse(xx.condition)
      sql = jsonSql.build({
        type: 'select',
        table: 'users',
        fields: ['name', 'age'],
        condition: {
          name: 'Max',
          id: 6
        }
      })
    }
    if (type == 'init') {
      db.all("SELECT rowid AS id, ts, duration  , client  , result  , bytes  , method  , url , user, hierarchy  , type  FROM access LIMIT " + page_size.toString() + " OFFSET " + (page_num * page_size).toString(), function (err, row) {
        return res.json(row)
      })
    } else {
      db.all("SELECT rowid AS id, ts, duration  , client  , result  , bytes  , method  , url , user, hierarchy  , type  FROM access LIMIT " + page_size.toString() + " OFFSET " + (page_num * page_size).toString(), function (err, row) {
        return res.json(row)
      });
    }

  });

app.get("/api/getaccesslog",
  function (req, res, next) {
    var xx = req.query
    var page_num = xx.page - 1
    var page_size = xx.page_size
    var type = xx.type
    var sql = {}
    if (xx.condition != null) {
      var cond = JSON.parse(xx.condition)

      for (var cnt = 0; cnt < cond.children.length; cnt++) {
        sql[cond.children[cnt].query.selectedOperand] = cond.children[cnt].query.value
      }
    }
    var cinfo = ['rowid']
    knex('access').columnInfo().then(function (info) {
      Object.keys(info).forEach(key => {
        console.log('key', key)
        cinfo.push(key)
      })
      knex('access').where(sql).select(cinfo).limit(page_size).offset(page_num * page_size).then(rows => {
        return res.json(rows)
      })
    });
  });
app.get("/api/diskstat", async (req, res, next) => {
  try {

    const fstat = await sysi.fsStats()
    const dstat = await sysi.disksIO()

    var sysinfo = {};

    sysinfo.fsStat = {};
    sysinfo.fsStat.rx_bytes_sec = formatBytes(fstat.rx_sec.toFixed(1))
    sysinfo.fsStat.wx_bytes_sec = formatBytes(fstat.wx_sec.toFixed(1))

    sysinfo.diskIO = {};
    sysinfo.diskIO.rIOs_sec = dstat.rIO_sec.toFixed(2)
    sysinfo.diskIO.wIOs_sec = dstat.wIO_sec.toFixed(2)
    sysinfo.baba = "kimchi"


    res.json(sysinfo)
  } catch (e) {

    next(e)
  }
});

app.get("/api/redis", async (req, res, next) => {
  try {

    const fstat = await sysi.fsStats()
    const dstat = await sysi.disksIO()

    var sysinfo = {};

    sysinfo.fsStat = {};
    sysinfo.fsStat.rx_bytes_sec = formatBytes(fstat.rx_sec.toFixed(1))
    sysinfo.fsStat.wx_bytes_sec = formatBytes(fstat.wx_sec.toFixed(1))

    sysinfo.diskIO = {};
    sysinfo.diskIO.rIOs_sec = dstat.rIO_sec.toFixed(2)
    sysinfo.diskIO.wIOs_sec = dstat.wIO_sec.toFixed(2)
    sysinfo.baba = "kimchi"


    res.json(sysinfo)
  } catch (e) {

    next(e)
  }
});

app.get("/json/:config_name",
  function (req, res, next) {
    var file = req.params.config_name;
    var xx = jsonfile.readFile("./settings/" + file, function (err, obj) {
      res.send(obj)
      // console.dir(obj)

    })
  }
);

app.post("/json/:config_name",
  function (req, res, next) {
    var file = req.params.config_name
    var obj = req.body.data
    var xx = jsonfile.writeFile("./settings/" + file, obj, function (err, obj) {
      res.send(obj)
      // console.dir(obj)
    })
  });

app.get("/stat/:config_name",
  function (req, res, next) {
    var file = req.params.config_name;
    var xx = jsonfile.readFile("./settings/" + file, function (err, obj) {
      res.send(obj)
      // console.dir(obj)

    })
  }
);

app.get("/log/:config_name",
  function (req, res, next) {
    var file = req.params.config_name;
    var xx = jsonfile.readFile("./settings/" + file, function (err, obj) {
      res.send(obj)
      // console.dir(obj)

    })
  }
);
/*
https.createServer({
      key: fs.readFileSync('key.pem'),
      cert: fs.readFileSync('cert.pem'),
      ca   : fs.readFileSync('csr.pem'),
    }, app).listen( process.env.PORT || 3000);
 */

app.set('port', (process.env.PORT || 3030));

// app.listen(app.get('port'), function () {
//   console.log("Express running");
//});

var server = require('http').createServer(app);
var io = require('socket.io')(server);

var visitorsData = {};
// process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
var tails = {};

io.on('connection', (socket) => {
  console.log(`cliento connected ${socket.client.id}`);
  socket.on('disconnect', function () {
    console.log('usehr disconnected');
  });
  socket.on('tail', (data) => {
    socket.join(data.service);
    if (typeof tails[data.service] == "undefined") {
      //            tails[data.service] = spawn('ssh', ['root@' + 'quality-p.company.com', 'tail -f', 'data.service]', {
      tails[data.service] = spawn('tail', [' -f', '/var/log/system.log'], {
        shell: true
      });
      tails[data.service].stdout.on('data', (data) => {
        // console.log(`got new data ${data.toString()}`);
        io.emit('newLine', {
          line: data.toString().replace(/\n/g, '<br />')
        });
      });
    }
  });
});

/* 
io.on('connection', function(socket) {
   
  if (socket.handshake.headers.host === config.host
  && socket.handshake.headers.referer.indexOf(config.host + config.dashboardEndpoint) > -1) {

    // if someone visits '/dashboard' send them the computed visitor data
    io.emit('updated-stats', computeStats());

  }  

  // a user has visited our page - add them to the visitorsData object
  socket.on('visitor-data', function(data) {
    visitorsData[socket.id] = data;

    // compute and send visitor data to the dashboard when a new user visits our page
    io.emit('updated-stats', computeStats());
  });

  socket.on('disconnect', function() {
    // a user has left our page - remove them from the visitorsData object
    delete visitorsData[socket.id];

    // compute and send visitor data to the dashboard when a user leaves our page
    io.emit('updated-stats', computeStats());
  });
});
*/
server.listen(app.get('port'));

function computeStats() {
  return {
    pages: msg_page(),
    referrers: "navi",
    activeUsers: "gamja"
  };
}

function msg_page() {
  return "hello"
} 