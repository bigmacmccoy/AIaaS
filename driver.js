var express = require('express');
var bodyParser = require('body-parser');
//var sys = require('sys');
var mysql = require('mysql');
var fs = require('fs');
var https = require('https');

var key = fs.readFileSync('./ssl/key.pem');
var cert = fs.readFileSync('./ssl/cert.pem');

var app = express();

var server = https.createServer({
    key: key,
    cert: cert
}, app).listen(process.env.PORT, process.env.IP);
// create application/json parser 
var jsonParser = bodyParser.json();
// create application/x-www-form-urlencoded parser 
var urlencodedParser = bodyParser.urlencoded({ extended: false });

var errorCode = 0;

//app.listen(process.env.PORT, process.env.IP);

//Static reply to requests
app.get('/', function(req, res){
  if(req.secure){
    res.send("Welcome to AI-as-a-Service!");
  }else{
    res.send("Your kind isn't welcome here!");
  }
});
// Get a username from an ID
app.post('/getUserName', jsonParser, function (req, res) {
  if (!req.body){
      errorCode = 1;
      return res.sendStatus(translateErrorCode(2));
  } else if(req.body.ID == null){
      errorCode = 2;
      return res.sendStatus(translateErrorCode(errorCode));
  }
  var connection = connect();
  if(connection){
    connection.query('SELECT * FROM `c9`.`Users` WHERE `id` = ?', [req.body.ID], function(err, results, fields) {
      if (err){
        console.log(err);
        errorCode = 1;
      }
      if(results[0] != null){
        console.log("Username for UserID " + req.body.ID + " is: " + results[0].username);
        errorCode = 0;
      }else{
        errorCode = 3;
      }
      disconnect(connection);
      return res.sendStatus(translateErrorCode(errorCode));
    });
  }
});
// Login function. Returns an auth token that the client stores and the submits with each query.
app.post('/login', jsonParser, function(req, res){
  if (!req.body){
      errorCode = 1;
      return res.sendStatus(translateErrorCode(2));
  } else if(req.body.ID == null){
      errorCode = 2;
      return res.sendStatus(translateErrorCode(errorCode));
  }
  var connection = connect();
  if(connection){
    connection.query('SELECT * FROM `c9`.`Users` WHERE `username` = ?', [req.body.username], function(err, results, fields) {
      if (err){
        console.log(err);
        errorCode = 1;
      }
      if(results[0] != null){
        
        errorCode = 0;
      }else{
        errorCode = 3;
      }
      disconnect(connection);
      return res.sendStatus(translateErrorCode(errorCode));
    });
  }
});

function translateErrorCode(errorCode){
  switch(errorCode){
    case 0: // Everything is copacetic.
      return 200;
    case 1: // Testing error or the code isn't written yet.
      return 418;
    case 2: // You tried to do something you shouldn't have
      return 400;
    case 3: // No response for you. Bad boy.
      return 403;
    default:
      return 200;
  }
}
function connect(){
  var connection = mysql.createConnection({
    host     : 'localhost',
    user     : 'bigmacmccoy',
    password : ''
  });

  connection.connect();
  return connection;
}
function disconnect(connection){
  connection.end();
}