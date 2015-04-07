var express = require('express');
var bodyParser = require('body-parser');
//var sys = require('sys');
var mysql = require('mysql');
var fs = require('fs');
var https = require('https');

var key = fs.readFileSync('./ssl/key.pem');
var cert = fs.readFileSync('./ssl/cert.pem');
var passport = require('passport');
var crypto = require("crypto");

var app = express();
/* Uncomment for HTTPS once that gets sorted.
var server = https.createServer({
    key: key,
    cert: cert
}, app).listen(process.env.PORT, process.env.IP);
*/
// Comment out the next line once HTTPS functions.
var server = app.listen(process.env.PORT, process.env.IP);

// create application/json parser 
var jsonParser = bodyParser.json();
// create application/x-www-form-urlencoded parser 
var urlencodedParser = bodyParser.urlencoded({ extended: false });

var errorCode = 0;

//app.listen(process.env.PORT, process.env.IP);


/*
Default: 
    Params:
    Function:
        Displays a message based on if HTTPS works or not.
    Returns:
        HTTP Response Code
        Message
*/
app.get('/', function(req, res){
    if(req.secure){
        res.send("Welcome to AI-as-a-Service!");
    }else{
        res.send("Your kind isn't welcome here!");
    }
});
/*
Get User Name: 
    Params:
        ID
    Function:
        Logs the Username for that ID.
    Returns:
        HTTP Response code
*/
app.post('/getUserName', jsonParser, function (req, res) {
    if(checkJSON(req.body, ["ID"])){ var connection = connect();
        var connection = connect();
        if(connection){
            connection.query('SELECT * FROM `c9`.`Users` WHERE `id` = ?', [req.body.ID], function(err, results, fields) {
                if (err){
                    console.log(err);
                    errorCode = 1;
                }
                if(results[0] != null){
                    console.log(results[0].username);
                    errorCode = 0;
                }else{
                    errorCode = 3;
                }
                disconnect(connection);
            });
        }
    }else{
        errorCode = 2;
    }
    return res.sendStatus(translateErrorCode(errorCode));
});
/*
Login:
    Params:
        Username
        Password
    Function:
        Checks username and password against DB.
    Returns:
        JSON containing the session token.
    TODO:
        Clean up how the app returns data. 
        Write Auth using session token.
*/
app.post('/login', jsonParser, function(req, res){
    if(checkJSON(req.body, ["username", "password"])){
        var connection = connect();
        if(connection){
            connection.query("SELECT * FROM `c9`.`Users` WHERE `username` = ?", [req.body.username], function(err, results, fields) {
                if (err){
                    console.log(err);
                    errorCode = 1;
                }
                if(results[0] != null){
                    if(req.body.password == results[0].password){
                        var currentTime = results[0].lastAccess;
                        var hmac = crypto.createHmac("sha1", currentTime.toString());
                        hmac.setEncoding("hex");
                        hmac.end(req.body.username, function(){
                            var newToken = hmac.read();
                            connection.query("UPDATE `c9`.`Users` SET `sessionToken` = ? WHERE `username` = ?", [newToken, req.body.username], function(err, results2, fields) {
                                if (err){
                                    console.log("1 " + err);
                                    errorCode = 1;
                                    return res.sendStatus(translateErrorCode(errorCode));
                                }
                            });
                            connection.query("SELECT sessionToken FROM `c9`.`Users` WHERE username = ?", [req.body.username], function(err, results3, fields) {
                                if (err){
                                    console.log("2 " + err);
                                    errorCode = 1;
                                    return res.sendStatus(translateErrorCode(errorCode));
                                }
                                if(results3[0] != null){
                                    errorCode = '{"SessionToken":"' + results3[0].sessionToken + '"}';
                                    res.json(errorCode);
                                }else{
                                    errorCode = 2;
                                    return res.sendStatus(translateErrorCode(errorCode));
                                }
                            });
                        });
                    }else{
                        errorCode = 2;
                        return res.sendStatus(translateErrorCode(errorCode));
                    }
                }else{
                    errorCode = 3;
                    return res.sendStatus(translateErrorCode(errorCode));
                }
            });
        }
        
    }else{
        errorCode = 2;
        return res.sendStatus(translateErrorCode(errorCode));
    }
});
/*
Create User: 
    Params:
        Username
        Password
        OS
    Function:
        Inserts the new user information into the DB
    Returns:
        HTTP Response code
*/
app.post("/createUser", jsonParser, function(req, res){
    if(checkJSON(req.body, ["username", "password", "os"])){
        var connection = connect();
        if(connection){
            connection.query("INSERT INTO `c9`.`Users`(`username`,`password`,`os`) VALUES(?,?,?)", [req.body.username, req.body.password, req.body.os], function(err, results, fields) {
                if (err){
                    console.log(err);
                    errorCode = 1;
                }
                if(results[0] != null){
                    console.log("Username: " + results[0].username);
                }else{
                    errorCode = 3;
                }
                disconnect(connection);
            });
        }
        
    }else{
        errorCode = 2;
    }
    return res.sendStatus(translateErrorCode(errorCode));
});
/*
Check JSON: 
    Params:
        Body
        Params
    Function:
        Checks that the required parameters are in the request.
    Returns:
        boolean value
*/
function checkJSON(body, params){
    if (!body){
        errorCode = 1;
        return false;
    } else {
        for(var param in params){
            var current = params[param];
            if(body[current] == null){
                errorCode = 2;
            return false;
            }
        }
        return true;
    }
}
/*
Translate Error Code: 
    Params:
        Error Code Value
    Function:
        Translates an error code value into an HTTP error code
    Returns:
        HTTP Response code number
    TODO:
        Do something better with how we return things. We need to support JSON return objects.
*/
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
        default: // You must be returning something else...
            return errorCode;
    }
}
/*
Connect: 
    Params:
        
    Function:
        Connects the app to the DB
    Returns:
        Connection object
*/
function connect(){
    var connection = mysql.createConnection({
        host     : 'localhost',
        user     : 'bigmacmccoy',
        password : ''
    });

    connection.connect();
    return connection;
}
/*
Disconnect: 
    Params:
        Connection object
    Function:
        Disconnects the app from the DB
    Returns:
    
*/
function disconnect(connection){
    connection.end();
}

function getMYSQLTime(){
    var currentTime = new Date();
    currentTime = currentTime.getUTCFullYear() + '-' +  ('00' + (currentTime.getUTCMonth()+1)).slice(-2) + '-' + ('00' + currentTime.getUTCDate()).slice(-2) + ' ' + ('00' + currentTime.getUTCHours()).slice(-2) + ':' + ('00' + currentTime.getUTCMinutes()).slice(-2) + ':' + ('00' + currentTime.getUTCSeconds()).slice(-2);
    return currentTime;
}