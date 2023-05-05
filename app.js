const express = require('express')
const bodyParser = require('body-parser')
const path = require('path');
const logger = require('morgan')
const cors = require('cors')
const https = require("https");
const http = require('http')
const fs = require("fs");




const app = express()
const port = process.env.PORT || 8000
const portHTTPS = process.env.PORTSSL || 8443


app.use(logger('dev'))
app.use(cors())
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))


app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', '/index.html'));
})

app.post('/data', (req, res) => {
    const {body} = req
    const {password} = body
    console.log(`This is the password: ${password}`)
    res.sendFile(path.join(__dirname, 'public', '/response.html'));
})


// This line is from the Node.js HTTPS documentation.
var options = {
  key: fs.readFileSync("key.pem"),
  cert: fs.readFileSync("cert.pem")
};

// Create an HTTP service.
http.createServer(app).listen(port, ()=>{
  console.log(`HTTP listening on ${port}`)
});
// Create an HTTPS service identical to the HTTP service.
https.createServer(options, app).listen(portHTTPS, ()=>{
  console.log(`HTTPS listening on ${portHTTPS}`)
});