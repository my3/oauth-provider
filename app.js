var uuid = require('node-uuid');
var express = require('express');
var crypto = require('crypto');
var app = express();
var AWS = require('aws-sdk');
AWS.config.loadFromPath('./config/aws.json');
var s3 = new AWS.S3.Client();
var dynamo = new AWS.DynamoDB.Client() ;

app.set('view engine', 'ejs');
app.set('view options', {
    layout: false
});

function customHeaders( req, res, next ){
 app.disable('x-powered-by');
 res.header("Server", "edeadlock OAuth Server v1.0");
 next();
}
app.use(customHeaders);
app.use("/html", express.static(__dirname + '/public'));

/*  Need to enable for oauth
app.use(function(req, res, next){
	var auth_header = req.headers['authorization'];
	if(!auth_header) {
		res.status(401);
		res.end('Authorization header not found');
		return;
	}
	next();
});
*/
app.use(express.cookieParser());
app.use(express.session({secret: '3ea8c28773fd47d7be77b5e398542ba9'}));
app.use(app.router);

app.get('/oauth/register', function(req, res){

	var app_name = req.query["app_name"];
	if(app_name!=null) {
		
		var app_desc = req.query["app_desc"];
		var app_callback = req.query["app_callback"]
		var consumer_key = uuid.v4().replace(/-/g,"")
		var consumer_secret = crypto.randomBytes(32).toString('hex')
		var user_id = "mythrikiran@yahoo.com"
		
		var params = {TableName : 'oauth_consumer', "Item":{
				"consumer_key":{"S":consumer_key},
				"consumer_secret":{"S":consumer_secret},
				"user_id":{"S":user_id},
				"app_name":{"S":app_name},
				"app_desc":{"S":app_desc},
				"callback_url":{"S":app_callback}
			} 
		};

		dynamo.putItem(params, function(err, data) {
			if (err)
			  console.log(err)
			else
			  console.log(data.Item.S('consumer_key')); 
		});
		
		var params = {TableName : 'oauth_key_user', "Item":{
				"consumer_key":{"S":consumer_key},
				"user_id":{"S":user_id}
			} 
		};

		dynamo.putItem(params, function(err, data) {
			if (err)
			  console.log(err)
			else
			  console.log(data.Item.S('consumer_key')); 
		});
	}

	var AttributesToGet = new Array("user_id", "app_name", "app_desc","consumer_key","consumer_secret");
	var params = {"TableName" : "oauth_consumer", "ScanFilter":{ "user_id": { "AttributeValueList":[{"S" : "mythrikiran@yahoo.com"}], "ComparisonOperator": "EQ"} }, "AttributesToGet": AttributesToGet };

	dynamo.scan(params, function(err, data) {
		if (err)
		  console.log(err)
		else { 
		  var token = crypto.randomBytes(32);
			res.render('register', {
				apps: data.Items
			});	
		}
	});
});

app.get('/oauth/authorize', function(req, res){
	var welcome = 'Welcome';
	if (req.session.logged) {
		req.session.userId = req.query["user"];
		console.log(req.query["user"]);
		res.render('home', {
			welcome: 'Welcome back! '+req.query["user"],
			body : 'Mythri Pericharla'
		});
	}
    else {
		req.session.logged = true;
		res.render('login', {
			welcome: 'Welcome',
			body : 'Mythri Pericharla'
		});
	}	
});


app.get('/oauth/request_token', function(req, res){

/*
	//Auth header
	console.log(req.headers['authorization'])
	var auth_header = req.headers['authorization']
	if(typeof auth_header !== 'undefined') {
		var auth_header_req = auth_header.split(" ")
		var oauth_header = auth_header_req[0]
		if(oauth_header === 'OAuth') {
			var auth_headers = auth_header_req[1].split(",")
			console.log("type = "+oauth_header)
			console.log("elements = "+auth_headers[0])
		}
	}
	
	//POST body
	var content_type = req.headers['content-type']
	if(typeof content_type !== 'undefined') {
		if(content_type === 'application/x-www-form-urlencoded') {
			console.log('check POST body')
		}
	}
	
*/
	
	//query params
	request_token(req, res);
});

app.get('/oauth/auth_token', function(req, res){
	res.render('token', {
		body : uuid.v4().replace(/-/g,"")
	});
});

app.get('/oauth/test', function(req, res){
	var fruits = ["Banana", "Orange", "Apple", "Mango"];
	fruits.sort();
	res.write(req.method + ' ' + req.protocol + '://' + req.host + req.url);
	res.end('\r\n'+fruits[0]);
});


function request_token(req, res) {
	
	var required = ['oauth_consumer_key','oauth_signature_method','oauth_signature','oauth_timestamp','oauth_nonce','oauth_callback'];
	var required_value = [];
	var required_ordered = [];
	var required_tosign;
	required_tosign = req.method + '&' + encodeURIComponent(req.protocol + '://' + req.host + req.route.path) + '&'
	for(x in required) {
		if(typeof req.query[required[x]] === 'undefined') {res.end("query params missing: "+required[x]); return;}
		required_value[x] = req.query[required[x]];
		//console.log(required[x] +" = "+ required_value[x])
		required_ordered[x]=required[x] +'='+ required_value[x]
	}
	required_ordered.sort()
	for(x in required_ordered) {
		required_tosign = required_tosign + encodeURIComponent(required_ordered[x]);
	}
	console.log(required_tosign)
	

	var signatureMethod = required_value[required.indexOf('oauth_signature_method')];
	if( signatureMethod.toUpperCase() != "PLAINTEXT" && signatureMethod.toUpperCase() != "HMAC-SHA1") { res.end("signature type not allowed: use 'PLAINTEXT' or 'HMAC-SHA1'"); return; }
	
	var version = required_value[required.indexOf('oauth_version')];
	if( version != "1.0" ) { res.end("versions allowed: 1.0"); return; }
	
	var AttributesToGet = new Array("consumer_key", "user_id");
	var params = {"TableName" : "oauth_key_user", "Key":{ "HashKeyElement": {"S" : String(required_value[required.indexOf('oauth_consumer_key')]) }}, "AttributesToGet": AttributesToGet };

	dynamo.getItem(params, function(err, data) {
		if (err) {
		  console.log(err)
		  res.end("Invalid request."); return;
		}
		else {
		  if(Object.keys(data).length == 1) {
			res.end("Invalid request. Error Code: 1"); return;
		  }
		  else {
		    var response = data.Item.user_id.S
		  }
		}
	});
	var oauth_token = uuid.v4().replace(/-/g,"")
	var oauth_token_secret = crypto.randomBytes(32).toString('hex')
	var oauth_callback_confirmed = "true"
	var oauth_expires_in = 3600
	res.redirect(String(required_value[required.indexOf('oauth_callback')])
			+"?oauth_token=" + oauth_token + 
			"&oauth_token_secret=" + oauth_token_secret +
			"&oauth_callback_confirmed=" + oauth_callback_confirmed +
			"&oauth_expires_in=" + oauth_expires_in)
	
}


function access_token(req, res) {
	
	var required = ['oauth_consumer_key','oauth_token','oauth_signature_method','oauth_signature','oauth_timestamp',
			'oauth_nonce','oauth_version','oauth_verifier'];
	var required_value = [];
	for(x in required) {
		if(typeof req.query[required[x]] === 'undefined') {res.end("query params missing: "+required[x]); return;}
		required_value[x] = req.query[required[x]];
		console.log(required[x] +" = "+ required_value[x])
	}

	var signatureMethod = required_value[required.indexOf('oauth_signature_method')];
	if( signatureMethod.toUpperCase() != "PLAINTEXT" && signatureMethod.toUpperCase() != "HMAC-SHA1") { res.end("signature type not allowed: use 'PLAINTEXT' or 'HMAC-SHA1'"); return; }
	
	var version = required_value[required.indexOf('oauth_version')];
	if( version != "1.0" ) { res.end("versions allowed: 1.0"); return; }
	
	var AttributesToGet = new Array("consumer_key", "user_id");
	var params = {"TableName" : "oauth_key_user", "Key":{ "HashKeyElement": {"S" : String(required_value[required.indexOf('oauth_consumer_key')]) }}, "AttributesToGet": AttributesToGet };

	dynamo.getItem(params, function(err, data) {
		if (err) {
		  console.log(err)
		  res.end("Invalid request."); return;
		}
		else {
		  if(Object.keys(data).length == 1) {
			res.end("Invalid request. Error Code: 1"); return;
		  }
		  else {
		    var response = data.Item.user_id.S
		  }
		}
	});
	var oauth_token = uuid.v4().replace(/-/g,"")
	var oauth_token_secret = crypto.randomBytes(32).toString('hex')
	res.redirect("oauth_token=" + oauth_token + 
			"&oauth_token_secret=" + oauth_token_secret)
	
}


app.listen(80);
console.log('Server listening on port 80...');