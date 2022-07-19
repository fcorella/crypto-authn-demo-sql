#!/usr/bin/env node

import mysql2 from 'mysql2';
import fs from 'fs'; 
import express from 'express';
import { engine } from 'express-handlebars';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import http from 'http';
import https from 'https';
import {
    pjclHex2BitArray,
    pjclBitArray2Hex,
    pjclHex2BigInt,
    pjclRBG128Instantiate,
    pjclRBG128Reseed,
    pjclRBGGen,
    pjclCurve_P256,
    pjclECDSAValidatePublicKey,
    pjclECDSAVerifyMsg
} from 'pjcl';

let pjclCopiedToStatic = false;
let browserEntropyCopiedToStatic = false;

fs.copyFile("./node_modules/pjcl/pjcl.js", "./static/pjcl.js", function(err) {
    if (err) throw new Error(err);
    pjclCopiedToStatic = true;
});

fs.copyFile("./node_modules/pjcl/browser-entropy.js", "./static/browser-entropy.js", function(err) {
    if (err) throw new Error(err);
    browserEntropyCopiedToStatic = true;
});

const rbgStateObject = new Object();
const rbgSecurityStrength = 128;
const reseedPeriod = 604093; // a little over 10 minutes

function getDevRandomBits(bitLength, f) {
    const byteLength = bitLength / 8;
    const buf = Buffer.alloc(byteLength); 
    (function fillBuf(bufPos) {
        let remaining = byteLength - bufPos;
        if (remaining == 0) {
            f(buf.toString('hex'));
            return;
        }
        fs.open('/dev/random', 'r', function(err, fd) {
            if (err) throw new Error(err);
            fs.read(fd, buf, bufPos, remaining, 0, function(err, bytesRead) {
                if (err) throw new Error(err);
                bufPos += bytesRead;
                fs.close(fd, function(err) {
                    if (err) throw new Error(err);
                    fillBuf(bufPos);
                });
            });
        });
    })(0);
}

let rbgStateInitialized = false;

getDevRandomBits(rbgSecurityStrength, function(hex) {
    pjclRBG128Instantiate(rbgStateObject, pjclHex2BitArray(hex));
    rbgStateInitialized = true;            
    reseedPeriodically(reseedPeriod);
});

function reseedPeriodically(period) {
    setTimeout(getDevRandomBits, period, rbgSecurityStrength, function(hex) {
        pjclRBG128Reseed(rbgStateObject, pjclHex2BitArray(hex));
        reseedPeriodically(period);
    });
}

const connection = mysql2.createConnection({
    socketPath: '/var/lib/mysql/mysql.sock'
});
connection.query('CREATE DATABASE IF NOT EXISTS demo', function(err) {
    if (err) throw new Error(err);
});
connection.query('USE demo', function(err) {
    if (err) throw new Error(err);
});
connection.query('CREATE TABLE IF NOT EXISTS users (' +
    'email VARCHAR(255) NOT NULL, ' +
    'firstname VARCHAR(255), ' +
    'lastname VARCHAR(255), ' +
    'credentialCreationTimeStamp BIGINT, ' +
    'keyConfirmationChallengeHex CHAR(32), ' +
    'emailVerifCodeHex CHAR(32), ' +
    'loginTimeStamp BIGINT, ' +
    'loginChallenge CHAR(32), ' +
    'PRIMARY KEY (email)' +
');', function(err) {
    if (err) throw new Error(err);
});
connection.query('CREATE TABLE IF NOT EXISTS credentials (' +
    'email VARCHAR(255) NOT NULL, ' +
    'pubKeyHex_Q_x VARCHAR(255) NOT NULL, ' +
    'pubKeyHex_Q_y VARCHAR(255) NOT NULL,' +
    'INDEX (email, pubKeyHex_Q_x, pubKeyHex_Q_y)' +
    // not a UNIQUE INDEX, to allow for
    // using the same credential in different browsers in future use cases
');', function(err) {
    if (err) throw new Error(err);
});
connection.query('CREATE TABLE IF NOT EXISTS sessions (' +
    'sessionId VARCHAR(255) NOT NULL, ' +
    'email VARCHAR(255) NOT NULL, ' +
    'sessionTimeStamp BIGINT NOT NULL, ' +
    'PRIMARY KEY (sessionId)' +
    // sessionId is generated at random with high entropy 
    // and should be probabilistically unique;
    // something must be wrong if it isn't
');', function(err) {
    if (err) throw new Error(err);
});
connection.end();

const linkTimeout = 300000; // 5 minutes
const credentialRedirectionTimeout = 300000; // 5 minutes
const loginRedirectionTimeout = 30000; // 30 seconds
const sessionTimeout = 3600000; // 1 hour

const app = express();
app.engine("handlebars", engine());
app.set("view engine", "handlebars");
app.set('views', './views');

http.createServer(app).listen(80);
console.log("listening on port 80");

const tlsCertificate = fs.readFileSync("self-signed-demo-cert/cert.pem");
const tlsPrivateKey = fs.readFileSync("self-signed-demo-cert/key.pem");
const options = {
    cert: tlsCertificate,
    key: tlsPrivateKey
}
https.createServer(options, app).listen(443);
console.log("listening on port 443");

app.use(function(req,res,next) {
    if (!req.secure) {
        res.redirect(301,'https://' + req.headers.host + req.url);
    }
    else {
        next();
    }
});

app.use(function(req,res,next) {
    if (
        !pjclCopiedToStatic ||
        !browserEntropyCopiedToStatic
    ) {
        res.status(503).send('SERVER BUSY, TRY AGAIN LATER');
    }
    else {
        next();
    }
});

// error messages
//
app.get('/email-taken.html',function(req,res) {
    res.render("error.handlebars", {
        msg: "Email taken"
    });
});
app.get('/registration-failure.html',function(req,res) {
    res.render("error.handlebars", {
        msg: "Registration failure"
    });
});
app.get('/link-expiration.html',function(req,res) {
    res.render("error.handlebars", {
        msg: "The link you used has expired"
    });
});
app.get('/invalid-verification-code.html',function(req,res) {
    res.render("error.handlebars", {
        msg: "Invalid verification code"
    });
});
app.get('/credential-creation-failure.html',function(req,res) {
    res.render("error.handlebars", {
        msg: "Credential creation failure"
    });
});
app.get('/email-address-not-found.html',function(req,res) {
    res.render("error.handlebars", {
        msg: "Email address not found"
    });
});
app.get('/authentication-failure.html',function(req,res) {
    res.render("error.handlebars", {
        msg: "Authentication failure"
    });
});
app.get('/authentication-failure1.html',function(req,res) {
    res.render("error.handlebars", {
        msg: "Authentication failure"
    });
});
app.get('/authentication-failure2.html',function(req,res) {
    res.render("error.handlebars", {
        msg: "Authentication failure"
    });
});
app.get('/authentication-failure3.html',function(req,res) {
    res.render("error.handlebars", {
        msg: "Authentication failure"
    });
});
app.get('/authentication-failure4.html',function(req,res) {
    res.render("error.handlebars", {
        msg: "Authentication failure"
    });
});
app.get('/authentication-failure5.html',function(req,res) {
    res.render("error.handlebars", {
        msg: "Authentication failure"
    });
});
app.get('/invalid-link.html',function(req,res) {
    res.render("error.handlebars", {
        msg: "Invalid link"
    });
});
app.get('/invalid-link-request.html',function(req,res) {
    res.render("error.handlebars", {
        msg: "Invalid link request"
    });
});
//
// end of error messages

app.get('/',function(req,res) {
    res.redirect(303, "/public-page-1.html");
});

app.get('/register.html',function(req,res) {
    res.render("register.handlebars", {});
});

app.get('/please-log-in.html',function(req,res) {
    const destination = req.query.destination;
    // input validation
    if (destination.search(/^[-A-Za-z0-9]+$/) == -1) {
        res.redirect(303, "/authentication-failure.html");
        return;
    }
    res.render("please-log-in.handlebars", {
        destination: destination
    });
});

app.use(express.static('static'));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

app.post('/register-user',function(req,res) {
    const email = req.body.email;
    const firstname = req.body.firstname;
    const lastname = req.body.lastname;
    if (
        email.search(/^[A-Za-z0-9]+@[A-Za-z0-9]+\.[A-Za-z]+$/) == -1 ||
        firstname.search(/^[A-Za-z]+$/) == -1 ||
        lastname.search(/^[A-Za-z]+$/) == -1
    ) {
        // input validation
        // the above errors should have been caught by the frontend
        res.redirect(303, "/registration-failure.html");
        return;
    };

    // for the creation of the first key pair credential in a browser;
    // credentials in additional browsers may be created later as needed
    //
    const credentialCreationTimeStamp = (new Date()).getTime();
    const keyConfirmationChallengeHex = pjclBitArray2Hex(pjclRBGGen(rbgStateObject,rbgSecurityStrength,rbgSecurityStrength));
    const emailVerifCodeHex = pjclBitArray2Hex(pjclRBGGen(rbgStateObject,rbgSecurityStrength,rbgSecurityStrength));

    const connection = mysql2.createConnection({
        socketPath: '/var/lib/mysql/mysql.sock',
	database: 'demo'
    });
    const queryString = 
	"INSERT INTO users" +
	"(email, firstname, lastname, credentialCreationTimeStamp, emailVerifCodeHex, keyConfirmationChallengeHex)" +
        " VALUES (?, ?, ?, ?, ?, ?)";
    const values = [email, firstname, lastname, credentialCreationTimeStamp, emailVerifCodeHex, keyConfirmationChallengeHex];
    connection.query(queryString, values, function(err) {
	if (err) {
	    res.redirect(303, "/email-taken.html");
	}
	else {
	    res.render("message-sent", {
		email: email,
		emailVerifCodeHex: emailVerifCodeHex,
		keyConfirmationChallengeHex: keyConfirmationChallengeHex
	    });
	};
    });
});

//  response to user clicking on the email-verification-and-credential-creation link
//  for the first or subsequent cryptographic credentails
//
app.get('/create-credential',function(req,res) {
    const email = req.query.email;
    const emailVerifCodeHex = req.query.emailVerifCodeHex;
    const keyConfirmationChallengeHex = req.query.keyConfirmationChallengeHex;
    if (
	// input validation
        email.search(/^[A-Za-z0-9]+@[A-Za-z0-9]+\.[A-Za-z]+$/) == -1 ||
        emailVerifCodeHex.search(/^[A-Fa-f0-9]+$/) == -1 ||
        keyConfirmationChallengeHex.search(/^[A-Fa-z0-9]+$/) == -1
    ) {
        res.redirect(303, "/invalid-link.html"); // 
        return;
    }
    const entropyHex = pjclBitArray2Hex(pjclRBGGen(rbgStateObject,rbgSecurityStrength,rbgSecurityStrength));
    res.render("credential-redirection.handlebars", {
        email: email,
	emailVerifCodeHex: emailVerifCodeHex,
        keyConfirmationChallengeHex: keyConfirmationChallengeHex,
        entropyHex: entropyHex
    });
});
    
// response to the http post redirection by views/credential-redirection.handlebars
// conveying the public key and the key confirmation signature
//
app.post('/register-credential',function(req,res) {    
    const email = req.body.email;
    const emailVerifCodeHex = req.body.emailVerifCodeHex;
    const pubKeyHex_Q_x = req.body.pubKeyHex_Q_x;
    const pubKeyHex_Q_y = req.body.pubKeyHex_Q_y;
    const sigHex_r = req.body.sigHex_r;
    const sigHex_s = req.body.sigHex_s;
    if (
	// input validation
        email.search(/^[A-Za-z0-9]+@[A-Za-z0-9]+\.[A-Za-z]+$/) == -1 ||
        emailVerifCodeHex.search(/^[A-Fa-f0-9]+$/) == -1 ||
        pubKeyHex_Q_x.search(/^[A-Fa-z0-9]+$/) == -1 ||
        pubKeyHex_Q_y.search(/^[A-Fa-z0-9]+$/) == -1 ||
        sigHex_r.search(/^[A-Fa-f0-9]+$/) == -1 ||
        sigHex_s.search(/^[A-Fa-f0-9]+$/) == -1
    ) {
        res.redirect(303, "/credential-creation-failure.html"); // 
        return;
    }

    const connection = mysql2.createConnection({
        socketPath: '/var/lib/mysql/mysql.sock',
	database: 'demo'
    });
    const queryString =
	"SELECT credentialCreationTimeStamp, emailVerifCodeHex, keyConfirmationChallengeHex FROM users WHERE email=?";
    const values = [email];
    connection.query(queryString, values, function(err, results) {
        if (err) throw new Error(err);
        if (results.length == 0) {
            res.redirect(303, "/email-address-not-found.html");
            return;
        }
	const user = results[0];

	// consistency check
	//
	if (
	    !user.credentialCreationTimeStamp ||
		!user.emailVerifCodeHex ||
		!user.keyConfirmationChallengeHex
	) {
            res.redirect(303, "/credential-creation-failure.html");
            return;
	}
	
	// link expiration check
	//
	const now = (new Date()).getTime();
	if (now - user.credentialCreationTimeStamp > linkTimeout + credentialRedirectionTimeout) { 
            res.redirect(303, "/link-expiration.html");
            return;
	}
	
	// verification code check
	//
	if (emailVerifCodeHex != user.emailVerifCodeHex) {
	    res.redirect(303, "/invalid-verification-code.html");
	    return;
	}
	
	// public key validation
	//
	const x = pjclHex2BigInt(pubKeyHex_Q_x);
	const y = pjclHex2BigInt(pubKeyHex_Q_y);
	const Q = {x:x, y:y, z:[1]};
	if (!pjclECDSAValidatePublicKey(Q,pjclCurve_P256)) {
            res.redirect(303, "/credential-creation-failure.html");
            return;
	}
	
	// verification of the key confirmation signature
	//
	const challengeHex = user.keyConfirmationChallengeHex;
	const challengeBitArray = pjclHex2BitArray(challengeHex);
	const r = pjclHex2BigInt(sigHex_r);
	const s = pjclHex2BigInt(sigHex_s);
	if (!pjclECDSAVerifyMsg(pjclCurve_P256, Q, challengeBitArray, r, s)) {
            res.redirect(303, "/credential-creation-failure.html");
            return;
	}

	// registration of the credential created by the browser
	//
	const connection = mysql2.createConnection({
            socketPath: '/var/lib/mysql/mysql.sock',
	    database: 'demo'
	});
	const queryString = "INSERT INTO credentials (email, pubKeyHex_Q_x, pubKeyHex_Q_y) VALUES (?, ?, ?)";
	const values = [email, pubKeyHex_Q_x, pubKeyHex_Q_y];
	connection.query(queryString, values, function(err) {
	    if (err) throw new Error(err);

	    // login session creation
	    //
	    const connection = mysql2.createConnection({
		socketPath: '/var/lib/mysql/mysql.sock',
		database: 'demo'
	    });
	    const queryString = "INSERT INTO sessions (sessionId, email, sessionTimeStamp) VALUES (?, ?, ?)";
	    const sessionId = pjclBitArray2Hex(pjclRBGGen(rbgStateObject,rbgSecurityStrength,rbgSecurityStrength));
	    const sessionTimeStamp = new Date().getTime();
	    const values = [sessionId, email, sessionTimeStamp];
	    connection.query(queryString, values, function (err) {
		if (err) throw new Error(err);
		res.cookie('session', sessionId, {httpOnly: true, secure: true});
		res.redirect(303, "/private-page-1.html");
	    });
	});
    });

});

//  logging in the user, when he/she uses the page-top login form or
//  tries to navigate to a private page without being logged-in
//  ("on-the-fly login"); in the former case, the user is taken to
//  private-page-1 after the login; in the latter, the user is taken to
//  the desired destination; (except, for simplicity, if a credential
//  has to be created on the fly)
//
app.post('/log-in',function(req,res) {
    const destination = req.body.destination || "private-page-1";
    const email = req.body.email;

    // input validation
    //
    if (destination.search(/^[-A-Za-z0-9]+$/) == -1) {
        res.redirect(303, "/authentication-failure.html");
        return;
    }

    // input validation
    // the error should have been caught by the frontend
    //
    if (email.search(/^[A-Za-z0-9]+@[A-Za-z0-9]+\.[A-Za-z]+$/) == -1) {
        res.redirect(303, "/email-address-not-found.html");
        return;
    }

    const connection = mysql2.createConnection({
        socketPath: '/var/lib/mysql/mysql.sock',
	database: 'demo'
    });
    const queryString = "UPDATE users SET loginChallenge = ?, loginTimeStamp = ? WHERE email = ?";
    const entropyHex = pjclBitArray2Hex(pjclRBGGen(rbgStateObject,rbgSecurityStrength,rbgSecurityStrength));
    const challengeHex = pjclBitArray2Hex(pjclRBGGen(rbgStateObject,rbgSecurityStrength,rbgSecurityStrength));
    const loginTimeStamp = new Date().getTime();
    const values = [challengeHex, loginTimeStamp, email];
    connection.query(queryString, values, function(err, results) {
        if (err) throw new Error(err);
        if (results.affectedRows == 0) {
            res.redirect(303, "/email-address-not-found.html");
            return;
        }
        res.render("login-redirection.handlebars", {
            entropyHex: entropyHex, 
            challengeHex: challengeHex,
            email: email,
            destination: destination
        });
    });
});

app.post('/verify-signature-or-offer-link',function(req,res) { 
    const email = req.body.email; // input validation below
    const credentialFound = req.body.credentialFound;
    if (credentialFound == "yes") {
	verifySignature(email, req, res);
    }
    else {
	offerCredentialCreationLink(email, req, res);
    }
});

function verifySignature(email, req, res) {
    const pubKeyHex_Q_x = req.body.pubKeyHex_Q_x;
    const pubKeyHex_Q_y = req.body.pubKeyHex_Q_y;
    const sigHex_r = req.body.sigHex_r;
    const sigHex_s = req.body.sigHex_s;
    const destination = req.body.destination;
    if (
  	// input validation
        email.search(/^[A-Za-z0-9]+@[A-Za-z0-9]+\.[A-Za-z]+$/) == -1 ||
        pubKeyHex_Q_x.search(/^[A-Fa-f0-9]+$/) == -1 ||
        pubKeyHex_Q_y.search(/^[A-Fa-f0-9]+$/) == -1 ||
        sigHex_r.search(/^[A-Fa-f0-9]+$/) == -1 ||
        sigHex_s.search(/^[A-Fa-f0-9]+$/) == -1 ||
        destination.search(/^[-A-Za-z0-9]+$/) == -1
    ) {
        res.redirect(303, "/authentication-failure1.html");
        return;
    }

    const connection = mysql2.createConnection({
        socketPath: '/var/lib/mysql/mysql.sock',
	database: 'demo'
    });
    const queryString =
	  "SELECT u.loginTimeStamp AS loginTimeStamp, u.loginChallenge AS loginChallenge " +
	  "FROM users u INNER JOIN credentials c ON u.email = c.email " +
	  "WHERE c.email = ? AND c.pubKeyHex_Q_x = ? AND c.pubKeyHex_Q_y = ?";
    const values = [email, pubKeyHex_Q_x, pubKeyHex_Q_y];
    connection.query(queryString, values, function(err, results) {
        if (err) throw new Error(err);
        if (results.length == 0) {
            // the credential was found by the browser, so something is wrong
            res.redirect(303, "/authentication-failure2.html");
            return;
        }
        const user = results[0];
        const now = (new Date()).getTime();
        if (!user.loginTimeStamp || (now - user.loginTimeStamp > loginRedirectionTimeout)) { 
            res.redirect(303, "/authentication-failure3.html");
            return;
        }
        const challengeHex = user.loginChallenge;
        if (!challengeHex) {
            res.redirect(303, "/authentication-failure4.html");
            return;
        }
	
        // verification of the authentication signature
        //
        const x = pjclHex2BigInt(pubKeyHex_Q_x);
        const y = pjclHex2BigInt(pubKeyHex_Q_y);
        const Q = {x:x, y:y, z:[1]};
        const r = pjclHex2BigInt(sigHex_r);
        const s = pjclHex2BigInt(sigHex_s);
        const challengeBitArray = pjclHex2BitArray(challengeHex);
        if (!pjclECDSAVerifyMsg(pjclCurve_P256, Q, challengeBitArray, r, s)) {
	    res.redirect(303, "/invalid-credential.html");
	    return;
        }

	// login session creation
	//
	const connection = mysql2.createConnection({
            socketPath: '/var/lib/mysql/mysql.sock',
	    database: 'demo'
	});
	const queryString = "INSERT INTO sessions (sessionId, email, sessionTimeStamp) VALUES (?, ?, ?)";
	const sessionId = pjclBitArray2Hex(pjclRBGGen(rbgStateObject,rbgSecurityStrength,rbgSecurityStrength));
	const sessionTimeStamp = new Date().getTime();
	const values = [sessionId, email, sessionTimeStamp];
	connection.query(queryString, values, function (err) {
            if (err) throw new Error(err);
	    res.cookie('session', sessionId, {httpOnly: true, secure: true});
	    res.redirect(303, `/${destination}.html`);
	});
    });
}

function offerCredentialCreationLink(email, req, res) {
    if (
  	// input validation
        email.search(/^[A-Za-z0-9]+@[A-Za-z0-9]+\.[A-Za-z]+$/) == -1
    ) {
        res.redirect(303, "/authentication-failure5.html");
        return;
    }
    res.render("no-credential-in-browser", {
	email: email
    });
}

app.get('/send-link',function(req,res) {
    const email = req.query.email;
    if (
  	// input validation
	// the link request must have been tampered with
        email.search(/^[A-Za-z0-9]+@[A-Za-z0-9]+\.[A-Za-z]+$/) == -1
    ) {
        res.redirect(303, "/invalid-link-request.html");
        return;
    }

    // as in the response to /register-user, now
    // for the creation of a key pair credential in an additional browser
    //
    const credentialCreationTimeStamp = (new Date()).getTime();
    const keyConfirmationChallengeHex = pjclBitArray2Hex(pjclRBGGen(rbgStateObject,rbgSecurityStrength,rbgSecurityStrength));
    const emailVerifCodeHex = pjclBitArray2Hex(pjclRBGGen(rbgStateObject,rbgSecurityStrength,rbgSecurityStrength));

    const connection = mysql2.createConnection({
        socketPath: '/var/lib/mysql/mysql.sock',
	database: 'demo'
    });
    const queryString =
	"UPDATE users SET credentialCreationTimeStamp = ?, keyConfirmationChallengeHex = ?, emailVerifCodeHex = ? WHERE email = ?";
    const values = [credentialCreationTimeStamp, keyConfirmationChallengeHex, emailVerifCodeHex, email];
    connection.query(queryString, values, function(err, results) {
        if (err) throw new Error(err);
        if (results.AffectedRows == 0) {
            res.redirect(303, "/email-address-not-found.html");
        }
	else {
	    res.render("message-sent", {
		email: email,
		emailVerifCodeHex: emailVerifCodeHex,
		keyConfirmationChallengeHex: keyConfirmationChallengeHex
	    });
	};
    });
});

app.get('/logout',function(req,res) {
    const sessionId = req.cookies.session;
    if (sessionId) {
        res.clearCookie('session');

	const connection = mysql2.createConnection({
            socketPath: '/var/lib/mysql/mysql.sock',
	    database: 'demo'
	});
	const queryString = "DELETE FROM sessions WHERE sessionId = ?";
	const values = [sessionId];
	connection.query(queryString, values, function(err) {
            if (err) throw new Error(err);
            res.redirect(303, "/");
        });
    }
});

function checkIfLoggedIn(req,res,next) {
    const sessionId = req.cookies.session;
    if (
        !sessionId ||
        sessionId.search(/^[A-Fa-f0-9]+$/) == -1
    ) {
        res.locals.loggedIn = false;
        next();
        return;
    }   
    const connection = mysql2.createConnection({
        socketPath: '/var/lib/mysql/mysql.sock',
	database: 'demo'
    });
    const queryString =
	"SELECT u.email AS email, u.firstname AS firstname, u.lastname AS lastname FROM " +
	"users u INNER JOIN sessions s " +
	"ON u.email = s.email " +
	"WHERE s.sessionId = ? " +
	"AND ? - s.sessionTimeStamp < ?";
    const now = (new Date()).getTime();
    const values = [sessionId, now, sessionTimeout];
    connection.query(queryString, values, function(err, results) {
        if (err) throw new Error(err);
        if (results.length == 0) {
            res.locals.loggedIn = false;
            next();
        }
	else {
	    const user = results[0];
            res.locals.loggedIn = true;
            res.locals.email = user.email;
            res.locals.fullName = `${user.firstname} ${user.lastname}`;
            next();
	}
    });
}

app.use(checkIfLoggedIn);

const publicPageNames = [
    "public-page-1",
    "public-page-2",
    "public-page-3"
];
publicPageNames.forEach(function(pageName) {
    app.get(`/${pageName}.html`,function(req,res) {
        res.render(`${pageName}.handlebars`);
    });
});
const privatePageNames = [
    "private-page-1",
    "private-page-2",
    "private-page-3"
];
privatePageNames.forEach(function(pageName) {
    app.get(`/${pageName}.html`,function(req,res) {
        if (res.locals.loggedIn) {
            res.render(`${pageName}.handlebars`);
        }
        else {
            res.redirect(303,`/please-log-in.html?destination=${pageName}`);
        }
    });
});
app.use(function(req,res) {
    res.status(404).send('NOT FOUND');
});
app.use(function(err,req,res,next) {
    console.log("Error: " + err.stack);
    res.status(500).send('INTERNAL ERROR');
});
