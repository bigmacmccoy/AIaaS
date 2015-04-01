var express = require('express')
var bodyParser = require('body-parser')
 
var app = express()
 
// create application/json parser 
var jsonParser = bodyParser.json()
 
// create application/x-www-form-urlencoded parser 
var urlencodedParser = bodyParser.urlencoded({ extended: false })

// POST /api/users gets JSON bodies 
app.post('/getUserName', jsonParser, function (req, res) {
  if (!req.body){
      return res.sendStatus(400);
  }
  console.log(req.body.ID);
  return res.sendStatus(200);
})
app.listen(process.env.PORT, process.env.IP);