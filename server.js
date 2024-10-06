const express = require('express');
const app = express();

const jwt = require('jsonwebtoken');
const { expressjwt } = require('express-jwt');
const bodyParser = require('body-parser');
const path = require('path');
const { verify } = require('crypto');
const bcrypt = require('bcrypt');
const saltRounds = 10;

var verifyToken = function(req,res,next){
    var tokenData = req.header('authorization').split(" ")[1];
    if(!tokenData){
        return res.status(400).send({data: "Token NOT found"});
    }

    var authValue = req.header('authorization').split(" ")[1];
    if(authValue){
        tokenCheck = authValue;
        try {
            tokenStatus = jwt.verify(tokenCheck, secretKey);
            if(!tokenStatus){
                return res.status(400).send("No token available to decode");
            }
            if(!tokenStatus.username){
                return res.status(400).send("Unauthorized User");
            }
            next();
          } catch(err) {
            res.json({
                success: false,
                myContent: err.toString() + " Please login again!"
            });
          }
    }
    else {
        return res.status(400).send("No header present");
    }

};




app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000');
    res.setHeader('Access-Control-Allow-Headers', 'Content-type,Authorization');
    next();
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const PORT = 3000;

const secretKey = 'My super secret key';
const jwtMW = expressjwt({
    secret: secretKey,
    algorithms: ['HS256']
});

let users = [
    { id: 1, username: 'Mrinal', password: bcrypt.hashSync('1414@Hx', saltRounds) },
    { id: 2, username: 'HW7', password: bcrypt.hashSync('100', saltRounds) }
];

let loginStatus = false;

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    
    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ id: user.id, username: user.username }, secretKey, { expiresIn: '70s' });
        res.json({
            success: true,
            err: null,
            token
        });
    } else {
        res.status(401).json({
            success: false,
            token: null,
            err: 'Either username or password is incorrect'
        });
    }
});

app.get('/api/dashboard', verifyToken, (req, res) => {
    res.json({
        success: true,
        myContent: 'Secret content can only be accesed by login candidates !!!'
    });
});

app.get('/api/prices', verifyToken, (req, res) => {
    res.json({
        success: true,
        myContent: 'This is the price $X.**'
    });
});

app.get('/api/settings', verifyToken, (req, res) => {
    res.json({
        success: true,
        myContent: 'Settings page'
    });
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.use(function (err, req, res, next) {
    console.log(err.name === 'UnauthorizedError');
    console.log(err);
    if(err.name === 'UnauthorizedError') {
        res.status(401).json({
            success: false,
            officialError: err,
            err: 'Username or password is incorrect 2'
        });
    }
    else {
        next(err);
    }
});

app.listen(PORT, () => {
    console.log(`Serving on post ${PORT}`);
});