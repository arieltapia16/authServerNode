const express = require('express');
const http = require( 'http');
const bodyParser = require( 'body-parser');
const morgan = require( 'morgan');
const app = express();
const router = require('./router');
const mongoose = require('mongoose');

// DB setup
mongoose.Promise = require('bluebird');
mongoose.connect('mongodb://localhost/auth', {
  useMongoClient: true,
  /* other options */
});

// APP setup

app.use(morgan('combined'));
app.use(bodyParser.json({type: '*/*' }))
router(app);

// Server setup

const port = process.env.PORT || 3090;

const server = http.createServer(app);

server.listen(port);

console.log(`Server listen on port: ${port}`)