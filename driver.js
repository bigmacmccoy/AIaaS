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
		Session Token
	Function:
		Logs the Username for that ID.
	Returns:
		HTTP Response code
*/
app.post('/getUsername', jsonParser, function(req, res){
	async.waterfall([
		function(callback){
			var params = ["ID", "sessionToken"];
			var validJSON = checkJSON(req.body, params);
			if(validJSON){
				callback(null, validJSON);
			}else{
				var responseObject = {
					"ResponseCode":400,
					"Data":"Error: Required parameters were not included."
				};
				console.log("Required parameters were not included.")
				callback(responseObject);
			}
		},
		function(validJSON, callback){
				var connection = connect();
				if(connection){
					connection.query('SELECT * FROM `c9`.`Users` WHERE `sessionToken` = ?', [req.body.sessionToken], function(err, results, fields) {
						if (err){
							console.log(err);
							callback(null, false);
						}
						if(results[0] != null){
							if((results[0].sessionToken == req.body.sessionToken) && (recentTimestamp(results[0].lastAccess))){
								console.log("Valid token.");
								callback(null, true);
							}else{
								console.log("Invalid token");
								var responseObject = {
									"ResponseCode":401,
									"Data":"Invalid Token!"
								};
								callback(responseObject);
							}
						}else{
							console.log("No valid token in DB.");
							var responseObject = {
								"ResponseCode":401,
								"Data":"Invalid Token!"
							};
							callback(responseObject);
						}
					});
				}
				disconnect(connection);
		}
	], function (err, result){
		if(err){
			res.status(err.ResponseCode).send(err.Data);
		}else{
			res.status(result.ResponseCode).send(result.Data);
		}
		
	});
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
	async.waterfall([
		function(callback){ // CheckJSON for username and password
			var hasUserPass = checkJSON(req.body, ["username", "password"]);
			callback(null, hasUserPass);
		},
		function(hasUserPass, callback){ // Check for user token
			var hasToken = checkJSON(req.body, ["sessionToken"]);
			callback(null, hasUserPass, hasToken);
		},
		function(hasUserPass, hasToken, callback){ //If the user has a token, check if the token in valid.
			if(hasToken){
				var connection = connect();
				if(connection){
					connection.query('SELECT * FROM `c9`.`Users` WHERE `sessionToken` = ?', [req.body.sessionToken], function(err, results, fields) {
						if (err){
							console.log(err);
							callback(null, hasUserPass, hasToken, false);
						}
						if(results[0] != null){
							if((results[0].sessionToken == req.body.sessionToken) && (recentTimestamp(results[0].lastAccess))){
								console.log("Valid token.");
								callback(null, hasUserPass, hasToken, true);
							}else{
								console.log("Invalid token");
								if(hasUserPass){
									callback(null, hasUserPass, hasToken, false);
								}else{
									var responseObject = {
										"ResponseCode":401,
										"Data":"Login Failed!"
									};
									console.log("Invalid token and no Username and Password.")
									callback(responseObject);
								}
							}
						}else{
							console.log("No valid token in DB.");
							if(hasUserPass){
								callback(null, hasUserPass, hasToken, false);
							}else{
								var responseObject = {
									"ResponseCode":401,
									"Data":"Login Failed!"
								};
								console.log("No existing token and no Username and Password.")
								callback(responseObject);
							}
						}
					});
				}
				disconnect(connection);
			}else{
				if(hasUserPass){
					callback(null, hasUserPass, hasToken, false);
				}else{
					var responseObject = {
						"ResponseCode":401,
						"Data":"Login Failed!"
					};
					console.log("No token or Username and Password.")
					callback(responseObject);
				}
			}
		},
		function(hasUserPass, hasToken, authorized, callback){ // If not authorized, validate user and password, then generate auth token.
			if(!authorized){
				async.waterfall([
					function(callback2){
						var connection = connect();
						if(connection){
							connection.query("SELECT * FROM `c9`.`Users` WHERE `username` = ?", [req.body.username], function(err, userObj, fields) {
								if (err){
									console.log(err);
									var responseObject = {
										"ResponseCode":400,
										"Data":"Error: " + err
									};
									callback2(responseObject);
								}
								callback2(null, userObj[0]);
							});
						}
						disconnect(connection);
					},
					function(userObj, callback2){ // Check if passwords match and get current time.
						if(req.body.password == userObj.password){
							if((recentTimestamp(userObj.lastAccess)) && (userObj.sessionToken != null)){
								callback2(null, userObj, userObj.lastAccess, userObj.sessionToken);
							}else{
								var currentTime = userObj.lastAccess;
								callback2(null, userObj, currentTime, null);
							}
						}else{
							var responseObject = {
								"ResponseCode":401,
								"Data":"Error: Passwords do not match!"
							};
							callback2(responseObject);
						}
					},
					function(userObj, currentTime, validToken, callback2){ // Generate token.
						if(validToken != null){
							callback2(null, userObj, validToken, true);
						}
						var newToken = crypto.createHmac("sha1", currentTime).update(userObj.username).digest('hex');
						if(newToken != null){
							callback2(null, userObj, newToken, false);
						}else{
							var responseObject = {
								"ResponseCode":400,
								"Data":"Error: Could not generate new token!"
							};
							callback2(responseObject);
						}
					},
					function(userObj, token, existingToken, callback2){ //Load new token into DB
						if(existingToken){
							var responseObject = {
								"ResponseCode":200,
								"Data":'{"sessionToken":"' + token + '"}'
							};
							callback2(null, responseObject);
						}
						var connection = connect();
						if(connection){
							connection.query("UPDATE `c9`.`Users` SET `sessionToken` = ? WHERE `username` = ?", [token, userObj.username], function(err, results2, fields) {
								if (err){
									var responseObject = {
										"ResponseCode":400,
										"Data":"Error: Could Not Update Token."
									};
									callback2(responseObject);
								}else{
									var responseObject = {
										"ResponseCode":200,
										"Data":'{"sessionToken":"' + token + '"}'
									};
									callback2(null, responseObject);
								}
							});
						}
						disconnect(connection);
					}
				], function(err, result){
					if(err){
						callback(err);
					}else{
						callback(null, result);
					}
				});
			}else{
				var result = {
					"ResponseCode":200,
					"Data":'{"sessionToken":' + req.body.sessionToken + '"}'
				};
				callback(null, result);
			}
		}
	], function(err, result){
		if(err){
			res.status(err.ResponseCode).send(err.Data);
		}else{
			res.status(result.ResponseCode).send(result.Data);
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
	async.waterfall([
		function(callback){
			var params = ["username", "password", "sessionToken"];
			var validJSON = checkJSON(req.body, params);
			if(validJSON){
				callback(null, validJSON);
			}else{
				var responseObject = {
					"ResponseCode":400,
					"Data":"Error: Required parameters were not included."
				};
				console.log("Required parameters were not included.")
				callback(responseObject);
			}
		},
		function(validJSON, callback){
				var connection = connect();
				if(connection){
					connection.query('SELECT * FROM `c9`.`Users` WHERE `sessionToken` = ?', [req.body.sessionToken], function(err, results, fields) {
						if (err){
							console.log(err);
							callback(null, false);
						}
						if(results[0] != null){
							if((results[0].sessionToken == req.body.sessionToken) && (recentTimestamp(results[0].lastAccess))){
								console.log("Valid token.");
								callback(null, true);
							}else{
								console.log("Invalid token");
								callback(null, false);
							}
						}else{
							console.log("No valid token in DB.");
								callback(null, false);
							
						}
					});
				}
				disconnect(connection);
		},
		function(authorized, callback){ // If not authorized, validate user and password, then generate auth token.
			if(!authorized){
				async.waterfall([
					function(callback2){
						var connection = connect();
						if(connection){
							connection.query("SELECT * FROM `c9`.`Users` WHERE `username` = ?", [req.body.username], function(err, userObj, fields) {
								if (err){
									console.log(err);
									var responseObject = {
										"ResponseCode":400,
										"Data":"Error: " + err
									};
									callback2(responseObject);
								}
								callback2(null, userObj[0]);
							});
						}
						disconnect(connection);
					},
					function(userObj, callback2){ // Check if passwords match and get current time.
						if(req.body.password == userObj.password){
							if((recentTimestamp(userObj.lastAccess)) && (userObj.sessionToken != null)){
								callback2(null, userObj, userObj.lastAccess, userObj.sessionToken);
							}else{
								var currentTime = userObj.lastAccess;
								callback2(null, userObj, currentTime, null);
							}
						}else{
							var responseObject = {
								"ResponseCode":401,
								"Data":"Error: Passwords do not match!"
							};
							callback2(responseObject);
						}
					},
					function(userObj, currentTime, validToken, callback2){ // Generate token.
						if(validToken != null){
							callback2(null, userObj, validToken, true);
						}
						var newToken = crypto.createHmac("sha1", currentTime).update(userObj.username).digest('hex');
						if(newToken != null){
							callback2(null, userObj, newToken, false);
						}else{
							var responseObject = {
								"ResponseCode":400,
								"Data":"Error: Could not generate new token!"
							};
							callback2(responseObject);
						}
					},
					function(userObj, token, existingToken, callback2){ //Load new token into DB
						if(existingToken){
							var responseObject = {
								"ResponseCode":200,
								"Data":'{"sessionToken":"' + token + '"}'
							};
							callback2(null, responseObject);
						}
						var connection = connect();
						if(connection){
							connection.query("UPDATE `c9`.`Users` SET `sessionToken` = ? WHERE `username` = ?", [token, userObj.username], function(err, results2, fields) {
								if (err){
									var responseObject = {
										"ResponseCode":400,
										"Data":"Error: Could Not Update Token."
									};
									callback2(responseObject);
								}else{
									var responseObject = {
										"ResponseCode":200,
										"Data":'{"sessionToken":"' + token + '"}'
									};
									callback2(null, responseObject);
								}
							});
						}
						disconnect(connection);
					}
				], function(err, result){
					if(err){
						callback(err);
					}else{
						callback(null, result);
					}
				});
			}else{
				var result = {
					"ResponseCode":200,
					"Data":'{"sessionToken":' + req.body.sessionToken + '"}'
				};
				callback(null, result);
			}
		}
	], function (err, result){
		if(err){
			res.status(err.ResponseCode).send(err.Data);
		}else{
			res.status(result.ResponseCode).send(result.Data);
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
	async.waterfall([
		function(callback){
			var params = ["sessionToken", "userText"];
			var validJSON = checkJSON(req.body, params);
			if(validJSON){
				callback(null, validJSON);
			}else{
				var responseObject = {
					"ResponseCode":400,
					"Data":"Error: Required parameters were not included."
				};
				console.log("Required parameters were not included.");
				callback(responseObject);
			}
		},
		function(validJSON, callback){
				var connection = connect();
				if(connection){
					connection.query('SELECT * FROM `c9`.`Users` WHERE `sessionToken` = ?', [req.body.sessionToken], function(err, results, fields) {
						if (err){
							console.log(err);
							callback(null, false);
						}
						if(results[0] != null){
							if((results[0].sessionToken == req.body.sessionToken) && (recentTimestamp(results[0].lastAccess))){
								console.log("Valid token.");
								callback(null, true);
							}else{
								console.log("Invalid token");
								callback(null, false);
							}
						}else{
							console.log("No valid token in DB.");
								callback(null, false);
							
						}
					});
				}
				disconnect(connection);
		},
		function(authorized, callback){ // If authorized, filter the input text, 
			if(authorized){
				async.waterfall([
					function(callback2){ // Filter the user Text and only keep the important words.
						var badWords = ["a", "the", "of", "me", "you", "and"];
						var splitText = req.body.userText.split(" ");
						var goodWords = [];
						for (var i = 0; i < splitText.length; i++){
							var currentWord = splitText[i];
							if(badWords.indexOf(currentWord) == -1){
								goodWords.splice(goodWords.length, currentWord);
							}
						}
						if(goodWords.length > 0){
							callback2(null, goodWords);
						}else{
							var responseObject = {
								"ResponseCode":400,
								"Data":"Error: Command was not viable."
							};
							console.log("No good words left.");
							callback2(responseObject);
						}
					},
					function(goodWords, callback2){
						var pool  = mysql.createPool({
							connectionLimit : 10,
							host     : 'localhost',
							user     : 'bigmacmccoy',
							password : '',
						});
						var wordWeights = [];
						pool.getConnection(function(err, connection) {
							if(err){
								console.log("Error: Pool Errors.");
									var responseObject = {
										"ResponseCode":400,
										"Data":"Error: " + err
									};
									callback2(responseObject);
							}
							for(var i = 0; i < goodWords.length; i++){
								connection.query( 'SELECT * FROM Commands WHERE `word` = ?', [goodWords[i]], function(err, results, fields) {
									if(err){
										console.log("Error: Pool select error.");
										var responseObject = {
											"ResponseCode":400,
											"Data":"Error: " + err
										};
										callback2(responseObject);
									}else{
										if(results[0] != null){
											var weight = results[0].correct / results[0].incorrect;
											wordWeights.push({
												"Word": results[0].word,
												"Weight": weight,
												"numberTimesUsed":results[0].numberTimesUsed,
												"Action":results[0].action
											});
										}else{
											console.log("Result not in DB.");
										}
									}
									connection.release();
								});
							}
							callback2(null, wordWeights);
						});
					},
					function(wordWeights, callback2){
						var mostLikely = wordWeights[0];
						for(var i = 0; i < wordWeights.length; i++){
							if(wordWeights[i].weight > mostLikely.weight){
								mostLikely = wordWeights[i];
							}
						}
						var responseObject = {
							"ResponseCode":200,
							"Data":mostLikely
						}
						callback2(null, responseObject);
					}
				], function(err, result){
					if(err){
						callback(err);
					}else{
						callback(null, result);
					}
				});
			}else{
				var result = {
					"ResponseCode":401,
					"Data":"Error: sessionToken is not valid!"
				};
				callback(null, result);
			}
		}
	], function(err, result){
		if(err){
			res.status(err.ResponseCode).send(err.Data);
		}else{
			res.status(result.ResponseCode).send(result.Data);
		}
	});
});
/*
Test functions. Currently testing Async modularization.
*/
app.post("/test", jsonParser, function(req, res){
	var paramNames = ["Test", "Test2"];
	var query = "SELECT * FROM `c9`.`Users` WHERE `username` = ?";
	var obj = {
		"paramNames": paramNames,
		"validJSON":false,
		"params":req.body,
		"authorized":false,
		"query":query,
		"queryResults":undefined,
		"responseCode":null,
		"responseData":null
	};
	var process = async.seq(checkJSONAsync, AuthorizeAsync, QueryAsync);
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
function AuthorizeAsync(obj, callback){
	console.log("Authorized In Test");
	obj.authorized = true;
	callback(null, obj);
}
function QueryAsync(obj, callback){
	console.log("Test Query Run!");
	obj.queryResults = "BigMacMcCoy_TEST";
	callback(null, obj);
}
function checkJSONAsync(obj, callback){
	if (!obj.params){
		obj.responseCode = 418;
		obj.responseData = "No params!"
		callback(obj);
	} else {
		for(var param in obj.params){
			var current = obj.params[param];
			if(obj.params[current] == null){
				obj.responseCode = 418;
				obj.responseData = "Params are not correct"
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