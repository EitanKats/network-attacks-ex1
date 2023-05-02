const express = require('express')
const bodyParser = require('body-parser')
const path = require('path');
const logger = require('morgan')

const app = express()
const port = process.env.PORT || 8000


app.use(logger('dev'))

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

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})