// file: index.js

var _ = require("lodash");
var express = require("express");
var bodyParser = require("body-parser");
var jwt = require('jsonwebtoken');
var jsonfile = require('jsonfile');
var passport = require("passport");
var passportJWT = require("passport-jwt");
var os = require("os");
var fs = require('fs');
const sysi = require('systeminformation');
var ExtractJwt = passportJWT.ExtractJwt;
var JwtStrategy = passportJWT.Strategy;

var users = [{
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
jwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeader();
jwtOptions.secretOrKey = 'tasmanianDevil';

var strategy = new JwtStrategy(jwtOptions, function (jwt_payload, next) {
  console.log('payload received', jwt_payload);
  // usually this would be a database call:
  var user = users[_.findIndex(users, {
    id: jwt_payload.id
  })];
  if (user) {
    next(null, user);
  } else {
    next(null, false);
  }
});

passport.use(strategy);

var app = express();
app.use(passport.initialize());

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
app.get("/", function (req, res) {
  res.json({
    message: "Express is up!"
  });
});

app.post("/api/login", function (req, res) {

  if (req.body.name && req.body.password) {

    var name = req.body.name;
    var password = req.body.password;
  }
  // usually this would be a database call:
  var user = users[_.findIndex(users, {
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
      token: token
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
    message: "Success! You can not see this without a token"
  });
  console.log("Express ss running");

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

    console.log(sysinfo);

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
    sysinfo.memory.total = os.totalmem();
   // sysinfo.memory.free = os.freemem();
//    sysinfo.memory.used = memstat.used;
//    sysinfo.memory.buffercache = memstat.buffcache;
    sysinfo.memory.active = memstat.active;
    sysinfo.memory.avail = memstat.available;
    sysinfo.memory.used_perc = ((memstat.active / memstat.total )* 100).toFixed(2);

    res.json(sysinfo)
   } catch (e) {

    next(e)
  }
});

app.get("/api/fsstat", async (req, res, next) => {
   try {
     
    const fsinfo = await sysi.fsSize()

    var sysinfo = [];

    sysinfo = fsinfo
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
    console.dir(sysinfo)
   } catch (e) {

    next(e)
  }
});

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
    res.json(sysinfo)
   } catch (e) {

    next(e)
  }
});

app.get("/api/connectstat",  
  function (req, res, next) {
    sysi.networkConnections( function(data) {
       res.json( data)
       console.dir( data)
 })
  });

app.get("/api/networkinterfaces",  
  function (req, res, next) {
    sysi.networkInterfaces( function(data) {
       res.json( data)
       console.dir( data)
})
});

app.get("/api/processx",  
  function (req, res, next) {
    sysi.processes( function(data) {
       res.json( data.list)
       console.dir( "__"+data.list)
})
});
 

app.get("/api/diskstat", async (req, res, next) => {
   try {
     
    const fsinfo = await sysi.fsSize()
    const fstat = await sysi.fsStats()
    const dstat = await sysi.disksIO()

    var sysinfo = {};

    sysinfo.fsStat = {};
    sysinfo.fsStat.rx_bytes_sec = fstat.rx_sec.toFixed(2)
    sysinfo.fsStat.wx_bytes_sec = fstat.wx_sec.toFixed(2)
    
    sysinfo.diskIO = {};
    sysinfo.diskIO.rIOs_sec = dstat.rIO_sec.toFixed(2)
    sysinfo.diskIO.wIOs_sec = dstat.wIO_sec.toFixed(2)
 
    
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
      console.dir(obj)

    })
  }
);

app.post("/json/:config_name",
  function (req, res, next) {
    var file = req.params.config_name
    var obj = req.body
    var xx = jsonfile.writeFile("./settings/" + file, obj, function (err, obj) {
      res.send(obj)
      console.dir(obj)
    })
  });

app.get("/stat/:config_name",
  function (req, res, next) {
    var file = req.params.config_name;
    var xx = jsonfile.readFile("./settings/" + file, function (err, obj) {
      res.send(obj)
      console.dir(obj)

    })
  }
);

app.get("/log/:config_name",
  function (req, res, next) {
    var file = req.params.config_name;
    var xx = jsonfile.readFile("./settings/" + file, function (err, obj) {
      res.send(obj)
      console.dir(obj)

    })
  }
);


app.listen(process.env.PORT || 3000, function () {
  console.log("Express running");
});
