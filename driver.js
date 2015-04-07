var express = require('express');
var bodyParser = require('body-parser');
//var sys = require('sys');
var mysql = require('mysql');
var fs = require('fs');
var https = require('https');

var key = fs.readFileSync('./ssl/key.pem');
var cert = fs.readFileSync('./ssl/cert.pem');
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
	var returnObject = null;
	if(req.secure){
		 returnObject= {
		  "ResponseCode":200,
		  "Data":"Welcome to AI-as-a-Service!"
		};
	}else{
		returnObject = {
		  "ResponseCode":400,
		  "Data":"Your kind is not welcome here!"
		  };
	}
	res.status(returnObject.ResponseCode).send(returnObject.Data);
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
	var returnObject = null;
	if(checkJSON(req.body, ["ID"])){
		var connection = connect();
		if(connection){
			connection.query('SELECT * FROM `c9`.`Users` WHERE `id` = ?', [req.body.ID], function(err, results, fields) {
				if (err){
					console.log(err);
					returnObject = {
					  "ResponseCode":400,
					  "Data":"Error: " + err
					};
				}
				if(results[0] != null){
					console.log(results[0].username);
					returnObject = {
					  "ResponseCode":200,
					  "Data":"Username: " + results[0].username
					};
				}else{
					returnObject = {
					  "ResponseCode":400,
					  "Data":"No Results were returned."
					};
				}
				disconnect(connection);
				res.status(returnObject.ResponseCode).send(returnObject.Data);
			});
		}
	}else{
		returnObject = {
		  "ResponseCode":400,
		  "Data":"The necessary parameters were not sent."
		};
		res.status(returnObject.ResponseCode).send(returnObject.Data);
	}
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
	var returnObject = null;
	if(checkJSON(req.body, ["username", "password"])){
		var connection = connect();
		if(connection){
			connection.query("SELECT * FROM `c9`.`Users` WHERE `username` = ?", [req.body.username], function(err, results, fields) {
				if (err){
					console.log(err);
					returnObject = {
						"ResponseCode":400,
						"Data":"Error: " + err
					};
				}
				if(results[0] != null){
					if(req.body.password == results[0].password){
						var currentTime = results[0].lastAccess;
						var newToken = crypto.createHmac("sha1", currentTime.toString()).update(req.body.username).digest('hex');
						connection.query("UPDATE `c9`.`Users` SET `sessionToken` = ? WHERE `username` = ?", [newToken, req.body.username], function(err, results2, fields) {
							if (err){
								returnObject = {
									"ResponseCode":400,
									"Data":"Error (Login Update): " + err
								};
							}
						});
						connection.query("SELECT sessionToken FROM `c9`.`Users` WHERE username = ?", [req.body.username], function(err, results3, fields) {
							if (err){
								returnObject = {
									"ResponseCode":400,
									"Data":"Error (Login Select): " + err
								};
							}
							if(results3[0] != null){
								returnObject = {
									"ResponseCode":200,
									"Data": results3[0].sessionToken
								};
							}else{
								returnObject = {
									"ResponseCode":400,
									"Data":"Error: Select statement did not return anything."
								};
							}
							res.status(returnObject.ResponseCode).send(returnObject.Data);
						});
					}else{
						returnObject = {
							"ResponseCode":400,
							"Data":"Error: Passwords do not match!"
						};
						res.status(returnObject.ResponseCode).send(returnObject.Data);
					}
				}else{
					returnObject = {
						"ResponseCode":400,
						"Data":"Error: No results were returned from the DB."
					};
					res.status(returnObject.ResponseCode).send(returnObject.Data);
				}
			});
		}
		
	}else{
		returnObject = {
			"ResponseCode":400,
			"Data":"Could not connect to DB."
		};
		res.status(returnObject.ResponseCode).send(returnObject.Data);
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
	var returnObject = {};
	if(checkJSON(req.body, ["username", "password", "os"])){
		var connection = connect();
		if(connection){
			connection.query("INSERT INTO `c9`.`Users`(`username`,`password`,`os`) VALUES(?,?,?)", [req.body.username, req.body.password, req.body.os], function(err, results, fields) {
				if (err){
					console.log(err);
					returnObject = {
						"ResponseCode":400,
						"Data":"Error: " + err
					};
				}
				returnObject = {
					"ResponseCode":200,
					"Data":"User has been created."
				};
				disconnect(connection);
				res.status(returnObject.ResponseCode).send(returnObject.Data);
			});
		}
		
	}else{
		returnObject = {
			"ResponseObject":400,
			"Data":"Error: Required parameters were not included."
		};
		res.status(returnObject.ResponseCode).send(returnObject.Data);
	}
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
		return false;
	} else {
		for(var param in params){
			var current = params[param];
			if(body[current] == null){
				return false;
			}
		}
	}
	return true;
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