/**
 * @license
 * Copyright 2014 Open Ag Data Alliance
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

import fs from 'node:fs';
import https from 'node:https';
import { once } from 'node:events';

import cors from 'cors';
import express from 'express';

import jwkSet from './jwk_set.js';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const app = express();

app.use(cors());

app.get('/jwks_uri', (_request, response) => {
  response.json(jwkSet);
});

app.get('/jwks_uri_broken', (_request, response) => {
  response.send('');
});

app.get('/jwks_uri_invalid', (_request, response) => {
  response.json({});
});

app.get('/jwks_uri_slow', () => {
  // Never responds, only test using timeouts on the request side
});

// For testing cache failures:
let isDead = false;
app.get('/jwks_uri_dies_after_first_request', (_request, response) => {
  if (isDead) {
    response.status(404).send('Not Found');
  } else {
    response.json(jwkSet);
  }

  isDead = true;
});
app.get('/reset_jwks_uri_dies_after_first_request', (_request, response) => {
  isDead = false;
  response.json({});
});

const options = {
  key: fs.readFileSync('./test/server.key', 'utf8'),
  cert: fs.readFileSync('./test/server.crt', 'utf8'),
  ca: fs.readFileSync('./test/ca.crt', 'utf8'),
  requestCrt: true,
  rejectUnauthorized: false,
};

const server = https.createServer(options, app);
// eslint-disable-next-line github/no-then
const uri = once(server, 'listening').then(() => {
  const address = server.address();
  if (!address) {
    throw new Error('Server did not start');
  }

  return typeof address === 'string'
    ? address
    : `https://localhost:${address.port}`;
});
server.listen();

export default uri;
