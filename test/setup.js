/* Copyright 2014 Open Ag Data Alliance
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

const fs = require('fs');
const express = require('express');
const https = require('https');
const cors = require('cors');

const jwkSet = require('./jwk_set.json');

const app = express();

app.use(cors());

app.get('/jwks_uri', function(req, res) {
    res.json(jwkSet);
});

app.get('/jwks_uri_broken', function(req, res) {
    res.send('');
});

app.get('/jwks_uri_invalid', function(req, res) {
    res.json({});
});

app.get('/jwks_uri_slow', function() {
    // Never responds, only test using timeouts on the request side
});

// For testing cache failures:
let isdead = false;
app.get('/jwks_uri_dies_after_first_request', function(req,res) {
  if (isdead) {
    res.status(404).send('Not Found');
    return;
  }
  isdead = true;
  res.json(jwkSet);
});
app.get('/reset_jwks_uri_dies_after_first_request', function(req,res) {
  isdead = false;
  res.json({});
});

const options = {
    key: fs.readFileSync('./test/server.key', 'utf8'),
    cert: fs.readFileSync('./test/server.crt', 'utf8'),
    ca: fs.readFileSync('./test/ca.crt', 'utf8'),
    requestCrt: true,
    rejectUnauthorized: false
};

https.createServer(options, app).listen(3000);
