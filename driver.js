var express = require('express');
var bodyParser = require('body-parser');
//var sys = require('sys');
var mysql = require('mysql');
var fs = require('fs');
var https = require('https');

var key = fs.readFileSync('./ssl/key.pem');
var cert = fs.readFileSync('./ssl/cert.pem');
var crypto = require("crypto");
var async = require("async");

var app = express();
/* Uncomment for HTTPS once that gets sorted.
var server = https.createServer({
	key: key,
	cert: cert
}, app).listen(process.env.PORT, process.env.IP);
*/
// Comment out the next line once HTTPS functions.
var port = process.env.PORT || 1337;
var ip = process.env.IP || "localhost";
var server = app.listen(port, ip);

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
Login:
	Params:
		Username
		Password
	Function:
		Checks for an existing, valid token.
		If token,
			return valid token
		If no token,
			Check username and password against DB.
			Create new token
			return valid token
	Returns:
		JSON containing the session token.
*/
app.post('/login', jsonParser, function(req, res){
	var paramNames = ["username", "password"];
	var token = ((req.body.token) ? req.body.token : null);
	var query = "SELECT * FROM `c9`.`Users` WHERE `username` = ?";
	var obj = {
		"paramNames": paramNames,
		"validJSON":false,
		"params":req.body,
		"token":token,
		"validToken":undefined,
		"authorized":false,
		"query":query,
		"queryParams":[req.body.username],
		"queryResults":undefined,
		"responseCode":null,
		"responseData":null
	};
	var login = function(obj, callback){
		if(obj.authorized){
			obj.responseCode = 200;
			obj.responseData = {
				"username":obj.params.username,
				"status":"Logged In",
				"token":obj.token
			};
			callback(null, obj);
		}else{
			obj.responseCode = 420;
			obj.responseData = "An unexpected, impossible error occured. Dammit!";
			callback(obj);
		}
	};
	var process = async.seq(checkJSONAsync, validateTokenAsync, queryAsync, generateTokenAsync, updateTokenAsync, login);
	process(obj, function(err, result){
		if(err){
			res.status(err.ResponseCode).send(err.Data);
		}else{
			if((!obj.responseCode) && (!obj.responseData)){
				res.status(200).send(obj.queryResults);
			}else{
				res.status(obj.responseCode).send(obj.responseData);
			}
		}	
	});
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
	var paramNames = ["username", "password", "os"];
	var query = "INSERT INTO `c9`.`Users` (username, password, os) VALUES (?,?,?)";
	var queryParams = [req.body.username, req.body.password, req.body.os];
	var obj = {
		"paramNames": paramNames,
		"validJSON":false,
		"params":req.body,
		"token":null,
		"validToken":undefined,
		"authorized":false,
		"query":query,
		"queryParams":queryParams,
		"queryResults":undefined,
		"responseCode":null,
		"responseData":null
	};
	var createUser = function(obj, callback){
		obj.responseCode = 200;
		obj.responseData = "User created! Username is: " + obj.params.username;
		callback(null, obj);
	};
	var process = async.seq(checkJSONAsync, queryAsync, createUser);
	process(obj, function(err, result){
		if(err){
			res.status(err.ResponseCode).send(err.Data);
		}else{
			if((!obj.responseCode) && (!obj.responseData)){
				res.status(200).send(obj.queryResults);
			}else{
				res.status(obj.responseCode).send(obj.responseData);
			}
		}	
	});
	/*
	var resultObject = null;
	async.waterfall([
		function(callback){
			var hasUserPassOS = checkJSON(req.body, ["username", "password", "os"]);
			if(hasUserPassOS){
				callback(null, hasUserPassOS);
			}else{
				resultObject = {
					"ResponseObject":400,
					"Data":"Error: Required parameters were not included."
				};
				callback(resultObject);
			}
		},
		function(hasUserPassOS, callback){
			var connection = connect();
			if(connection){
				connection.query("SELECT * FROM `c9`.`Users` WHERE `sessionToken` = ?", [req.body.sessionToken], function(err, results, fields) {
					if (err){
						console.log(err);
						resultObject = {
							"ResponseCode":400,
							"Data":"Error: " + err
						};
						callback(resultObject);
					}
					disconnect(connection);
					callback(null, true)
				});
			}
		},
		function(userInserted, callback){
			if(userInserted){
				callback(null, true);
			}else{
				var responseObject = {
					"ResponseCode":400,
					"Data":"Error: User could not be created!"
				}
				callback(responseObject);
			}
		}
		], function(err, result){
			if(err){
				res.status(err.ResponseCode).send(err.Data);
			}else{
				res.status(result.ResponseCode).send(result.Data);
			}
	});
	*/
});
/*
RenewToken:
	Params:
		Username
		Password
		Old Token
	Function:
		Checks to see if the old token is valid, if it is, it returns that token.
		If the token isn't valid, it returns a new token
	Returns:
		Session Token
*/
app.post("/renewToken", jsonParser, function(req, res){
	var paramNames = ["username", "password", "sessionToken"];
	var token = req.body.sessionToken;
	var query = "SELECT * FROM `c9`.`Users` WHERE `sessionToken` = ?";
	var obj = {
		"paramNames": paramNames,
		"validJSON":false,
		"params":req.body,
		"token":token,
		"validToken":undefined,
		"authorized":false,
		"query":query,
		"queryParams":[req.body.sessionToken],
		"queryResults":undefined,
		"responseCode":null,
		"responseData":null
	};
	var renew = function(obj, callback){
		if(obj.authorized){
			obj.responseCode = 200;
			obj.responseData = {
				"username":obj.params.username,
				"token":obj.token
			};
			callback(null, obj);
		}else{
			obj.responseCode = 420;
			obj.responseData = "An unexpected, impossible error occured. Dammit!";
			callback(obj);
		}
	};
	var process = async.seq(checkJSONAsync, validateTokenAsync, queryAsync, generateTokenAsync, updateTokenAsync, renew);
	process(obj, function(err, result){
		if(err){
			res.status(err.ResponseCode).send(err.Data);
		}else{
			if((!obj.responseCode) && (!obj.responseData)){
				res.status(200).send(obj.queryResults);
			}else{
				res.status(obj.responseCode).send(obj.responseData);
			}
		}	
	});
});
/*
submitText:
	Params:
		sessionToken
		userText
	Function:
		Get text from a user
		Remove filler and useless words
		Pull remaining word weights out of DB
		Normalize word weights
		Use kNN to find most likely action
		Pull action information for OS out of DB
		Return pertinent action information
	Returns:
		Action information
*/
app.post("submitText", jsonParser, function(req, res){
	var paramNames = ["userText", "sessionToken"];
	var token = req.body.sessionToken;
	var query = "SELECT * FROM `c9`.`Commans` WHERE `text` = ?";
	var obj = {
		"paramNames": paramNames,
		"validJSON":false,
		"params":req.body,
		"token":token,
		"validToken":undefined,
		"authorized":false,
		"query":query,
		"queryParams":[req.body.sessionToken],
		"queryResults":undefined,
		"responseCode":null,
		"responseData":null
	};
	var submit = function(obj, callback){
		if(obj.authorized){
			var badWords = ["a", "the", "of", "me", "you", "and"];
			var splitText = obj.params.userText.split(" ");
			var goodWords = [];
			for (var i = 0; i < splitText.length; i++){
				var currentWord = splitText[i];
				if(badWords.indexOf(currentWord) == -1){
					goodWords.splice(goodWords.length, currentWord);
				}
			}
			if(goodWords.length > 0){
				obj.params = [];
				obj.query = "SELECT * FROM `c9`.`Inputs` WHERE ";
				for(var i = 0; i < goodWords.length; i++){
					obj.query = obj.query + "`text` = ? OR ";
					obj.params.push(goodWords[i]);
				}
				callback(null, obj);
			}else{
				obj.responseCode = 418;
				obj.responseData = "Error: The text submitted"
				console.log("No good words left.");
				callback(obj);
			}
		}else{
			obj.responseCode = 420;
			obj.responseData = "An unexpected, impossible error occured. Dammit!";
			callback(obj);
		}
	};
	var submit2 = function(obj, callback){
		obj.query = "SELECT * FROM `c9`.`Actions` WHERE ";
		obj.params = [];
		for(var i = 0; i < obj.queryResults.length; i++){
			obj.query = obj.query + "`id` = ? OR ";
			obj.params.push(obj.queryResults[i].actionID);
		}
		if(obj.params.length > 0){
			callback(null, obj);
		}else{
			obj.responseCode = 418;
			obj.responseData = "Error: No Actions assosiated with those inputs.";
			callback(obj);
		}
	};
	var submit3 = function(obj, callback){
		var highestChance = 0;
		var best = null;
		for(var i = 0; i < obj.queryResults.length; i++){
			var chance = ((obj.queryResults[i].correct / obj.queryResults[i].incorrect) * obj.queryResults[i].timesUsed);
			if(chance > highestChance){
				best = obj.queryResults[i];
			}
		}
		if(best){
			obj.responseCode = 200;
			obj.responseData = best;
			callback(null, obj);
		}else{
			obj.responseCode = 418;
			obj.responseData = "Error: Something went wrong figuring out which action to perform!";
			callback(obj);
		}
	};
	var process = async.seq(checkJSONAsync, validateTokenAsync, submit, queryAsync, submit2, queryAsync, submit3);
	process(obj, function(err, result){
		if(err){
			res.status(err.ResponseCode).send(err.Data);
		}else{
			if((!obj.responseCode) && (!obj.responseData)){
				res.status(200).send(obj.queryResults);
			}else{
				res.status(obj.responseCode).send(obj.responseData);
			}
		}
	});
});
/*
Test functions. Currently testing Async modularization.
*/
app.post("/test", jsonParser, function(req, res){

});
function updateTokenAsync(obj, callback){
	if((!obj.authorized) && (obj.validToken)){
		var connection = connect();
		if(connection){
			connection.query("UPDATE `c9`.`Users` SET `sessionToken` = ? WHERE `username` = ?", [obj.token, obj.params.username], function(err, results, fields) {
				if (err){
					obj.responseCode = 400;
					obj.responseData = "Error: Could not update the new token!";
					callback(obj);
				}else{
					console.log("Updated token.");
					obj.authorized = true;
					callback(null, obj);
				}
			});
		}
	}else{
		callback(null, obj);
	}
}
function generateTokenAsync(obj, callback){
	if(obj.validToken && obj.authorized){
		callback(null, obj);
	}else{
		if(obj.queryResults){
			if(obj.queryResults.password == obj.params.password){
				if((recentTimestamp(obj.queryResults[0].lastAccess)) && (obj.queryResults[0].sessionToken != "")){
					console.log("Token in DB still valid.");
					obj.validToken = true;
					obj.authorized = true;
					obj.token = obj.queryResults.sessionToken;
					callback(null, obj);
				}else{
					var currentTime = obj.queryResults[0].lastAccess;
					var newToken = crypto.createHmac("sha1", currentTime).update(obj.params[0].username).digest('hex');
					if(newToken != null){
						obj.validToken = true;
						obj.token = newToken;
						callback(null, obj);
					}else{
						obj.responseCode = 400;
						obj.responseData = "Error: Could not generate new token!";
						callback(obj);
					}
				}
			}
		}else{
			console.log("Error: No query results before token generation.");
			obj.responseCode = 400;
			obj.responseData = "Error: Could not generate new token!";
			callback(obj);
		}
	}
}
function validateTokenAsync(obj, callback){
	if(obj.token){
		var connection = connect();
		if(connection){
			connection.query('SELECT * FROM `c9`.`Users` WHERE `sessionToken` = ?', [obj.token], function(err, results, fields) {
				if (err){
					console.log(err);
					obj.responseCode = 418;
					obj.responseData = "Validate Token: Error with database!";
					callback(obj);
				}
				if(results[0] != null){
					if(recentTimestamp(results[0].lastAccess)){
						console.log("Valid token.");
						obj.validToken = true;
						obj.authorized = true;
						disconnect(connection);
						callback(null, obj);
					}else{
						console.log("Invalid token");
						obj.responseCode = 401;
						obj.responseData = "Invalid token!";
						obj.validToken = false;
						obj.authorized = false;
						disconnect(connection);
						callback(obj);
					}
				}else{
					console.log("No valid token in DB.");
					obj.responseCode = 401;
					obj.responseData = "Invalid token! (Not in Database!)";
					obj.validToken = false;
					obj.authorized = false;
					disconnect(connection);
					callback(obj);
				}
			});
		}
	}else{
		console.log("No token provided.")
		obj.validToken = false;
		obj.authorized = false;
		callback(null, obj);
	}
}
function queryAsync(obj, callback){
	var connection = connect();
	if(connection){
		connection.query(obj.query, obj.queryParams, function(err, results, fields) {
			if (err){
				console.log("Query DB Error");
				obj.responseCode = 418;
				obj.responseData = "Query: Error with database!";
				obj.queryResults = null;
				disconnect(connection);
				callback(obj);
			}else{
				console.log(JSON.stringify(results));
				obj.queryResults = results;
				disconnect(connection);
				callback(null, obj);
			}
		});
	}
}
function checkJSONAsync(obj, callback){
	if (!obj.params){
		obj.responseCode = 418;
		obj.responseData = "No params!";
		callback(obj);
	} else {
		for(var i = 0; i < obj.paramNames.length; i++){
			if(obj.params[obj.paramNames[i]] == null){
				obj.responseCode = 400;
				obj.responseData = "Error: The required parameters were not sent!";
				callback(obj);
			}
		}
	}
	obj.validJSON = true;
	callback(null, obj);
}
/*
Check JSON: 
	Params:
		Request Body
		Params
	Function:
		Checks that the required parameters are in the request.
	Returns:
		boolean value
*/
function checkJSON(body, params){
	var resultObject = null;
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
		password : '',
		dateStrings : true
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
	return;
}

function getMYSQLTime(){
	var currentTime = new Date();
	currentTime = currentTime.getUTCFullYear() + '-' +  ('00' + (currentTime.getUTCMonth()+1)).slice(-2) + '-' + ('00' + currentTime.getUTCDate()).slice(-2) + ' ' + ('00' + currentTime.getUTCHours()).slice(-2) + ':' + ('00' + currentTime.getUTCMinutes()).slice(-2) + ':' + ('00' + currentTime.getUTCSeconds()).slice(-2);
	return currentTime;
}
function recentTimestamp(timestamp){
	var converted = Date.parse(timestamp.replace(' ', 'T'));
	var currentTime = Date.now();
	var difference = currentTime - converted;
	if(difference > 3600*24*1000){
		console.log("Expired!");
		return false;
	}else{
		return true;
	}
}