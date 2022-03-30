/**
 * @license
 * Copyright 2015 Open Ag Data Alliance
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

import test from 'ava';

import cloneDeep from 'clone-deep';
import jose from 'node-jose';

// The module to be "checked" (i.e. under test)
import type { JOSEHeader, JWK } from '../../src/jwks-utils.js';
import { sign } from '../../dist/sign.js';

// Keypair used for signing in the tests:
import privJwk from '../private.jwk.js';

// We will mock a server for the tests that use this URL:
let pubJwk: JWK;
let pubKey: jose.JWK.Key;
test.before(async () => {
  const jwk = await jose.JWK.asKey(privJwk);
  // If you do not pass true to this function, it gives back only the public key
  pubJwk = jwk.toJSON();
  pubKey = await jose.JWK.asKey(pubJwk);
});

// ------------------------------------------------------------------------------------------
// Testing generating keys (most of the generation tests are actually during validation)
// ------------------------------------------------------------------------------------------
const testpayload = 'DEAD BEEF';
const key = cloneDeep(privJwk);
test('should create a signature that verifies successfully with jose.JWS', async (t) => {
  const sig = await sign(testpayload, key);
  const { header, payload } = (await jose.JWS.createVerify(pubKey).verify(
    sig
  )) as { header: JOSEHeader; payload: Buffer };
  t.deepEqual(header.jwk, pubJwk);
  // Payload from jose.JWS is a buffer, have to convert to string, then JSON.parse to get back to original because sign() stringifies it
  t.deepEqual(testpayload, JSON.parse(payload.toString()));
});

test('should create a signature that verifies successfully with jose.JWS using an object as a payload', async (t) => {
  const pld = { key1: testpayload };
  const sig = await sign(pld, key);
  const { header, payload } = (await jose.JWS.createVerify(pubKey).verify(
    sig
  )) as { header: JOSEHeader; payload: Buffer };
  t.deepEqual(header.jwk, pubJwk);
  // Payload from jose.JWS is a buffer, have to convert to string, then JSON.parse to get back to original because sign() stringifies it
  t.deepEqual(pld, JSON.parse(payload.toString()));
});

test('should create a signature that includes the jwk in the header even if there is a jku', async (t) => {
  const jku = 'https://some.url';
  const { kid } = pubJwk;
  const sig = await sign(testpayload, key, { header: { jku, kid } });
  const { header } = (await jose.JWS.createVerify(pubKey).verify(sig)) as {
    header: JOSEHeader;
  };
  t.deepEqual(header.jwk, pubJwk);
  t.is(header.jku, jku);
  t.is(header.kid, kid);
});

test('should override the kid on a jwk if we pass one in the header', async (t) => {
  const jku = 'https://some.url';
  const kid = 'nottherealkid';
  const jwk = cloneDeep(pubJwk);
  jwk.kid = kid;
  const sig = await sign(testpayload, key, { header: { jku, kid } });
  const { header } = (await jose.JWS.createVerify(pubKey).verify(sig)) as {
    header: JOSEHeader;
  };
  t.deepEqual(header.jwk, jwk);
  t.is(header.jku, jku);
  t.is(header.kid, kid);
});
