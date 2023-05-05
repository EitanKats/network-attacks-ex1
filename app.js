const express = require('express')
const bodyParser = require('body-parser')
const path = require('path');
const logger = require('morgan')
const cors = require('cors')
const https = require("https");
const fs = require("fs");




const app = express()
const port = process.env.PORT || 8000


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


https
  .createServer(
		// Provide the private and public key to the server by reading each
		// file's content with the readFileSync() method.
    {
      key: fs.readFileSync("key.pem"),
      cert: fs.readFileSync("cert.pem"),
    },
    app
  )
  .listen(port, () => {
    console.log(`Example app listening on port ${port}`)
  });

// app.listen(port, () => {
//   console.log(`Example app listening on port ${port}`)
// })