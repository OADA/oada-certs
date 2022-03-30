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

import { format, parse } from 'node:url';

import test from 'ava';

import { JWS, JWK as jose_JWK } from 'node-jose';
import nock from 'nock';

// The module to be "checked" (i.e. under test)
import { TRUSTED_LIST_URI, validate } from '../../dist/validate.js';
import type { JWK } from '../../src/jwks-utils.js';
import { sign } from '../../dist/sign.js';

// Keypair used for signing in the tests:
import privJwk from '../private.jwk.js';

// We will mock a server for the tests that use this URL:
const TEST_ROOT = 'https://test.example.org/';
const CUSTOM_TRUSTED_LIST = 'https://custom.trusted.list.com/';
let pubJwk: JWK;
test.before(async () => {
  const jwk = await jose_JWK.asKey(privJwk);
  // If you do not pass true to this function, it gives back only the public key
  pubJwk = jwk.toJSON() as JWK;
});

// ------------------------------------------------------------------------------------------
// Testing validating keys
// ------------------------------------------------------------------------------------------
const payload = 'DEAD BEEF';

// Setup the mock server to serve a trusted list with a URL for it's own jwk set
// When the main function tries to get the Trusted List, this will respond instead of github:
test.beforeEach(() => {
  const uri = parse(TRUSTED_LIST_URI);
  nock(format({ protocol: uri.protocol, host: uri.host }))
    // .log(log)
    .get(uri.path!)
    .reply(200, {
      version: '2',
      jkus: [TEST_ROOT],
      jwks: { keys: [] },
    });

  // Also host another identical one at a custom domain to test customizable trusted lists:
  const customUri = parse(CUSTOM_TRUSTED_LIST);
  nock(
    format({
      protocol: customUri.protocol,
      host: customUri.host,
    })
  )
    .get(customUri.path!)
    .reply(200, {
      version: '2',
      jkus: [TEST_ROOT],
      jwks: { keys: [] },
    });
  // This is what version 1 trusted list looked like: .reply(200, [TEST_ROOT]);
});

// Setup the mock server to serve it's jwk set at the URL given in the mocked list above
test.beforeEach(() => {
  // Setup the correct "trusted" one that's in mocked trusted list above:
  nock(TEST_ROOT)
    .get('/')
    .reply(200, { keys: [pubJwk] })
    // Also, host this one as the same list, but not considered trusted
    .get('/untrusted')
    .reply(200, { keys: [pubJwk] });
});

test('for invalid signature', async (t) => {
  // Create a signature with private key = "FOO"
  const sig = await sign(payload, privJwk, {
    header: {
      kid: privJwk.kid,
      jku: TEST_ROOT,
    },
  });
  const parts = sig.split('.');
  parts[2] = 'INVALIDSIGNATURE'; // The third item separated by periods is the signature in a JWT
  const invalid = parts.join('.');
  const result = await validate(invalid);
  t.false(result.trusted);
  t.false(result.valid);
  t.deepEqual(result.payload, payload);
});

// --------------------------------------------------------------------
test('for untrusted signatures', async (t) => {
  const sig1 = await sign(payload, privJwk, {
    header: {
      kid: privJwk.kid,
      jku: `${TEST_ROOT}untrusted`,
    },
  });
  const result1 = await validate(sig1);
  t.like(
    result1,
    { trusted: false, valid: true },
    'should return trusted=false, valid=true if signature uses jku (but does have JWK in its headers) to avoid pinging maliciously'
  );
  t.deepEqual(
    result1.payload,
    payload,
    'should return the signature payload even though untrusted'
  );

  const sig2 = await JWS.createSign({
    // @ts-expect-error types are off here
    key: await jose_JWK.asKey(privJwk),
    header: {
      kid: privJwk.kid,
      jku: `${TEST_ROOT}untrusted`,
    },
  })
    .update(payload)
    .final();
  const result2 = await validate(sig2 as unknown as string);
  t.like(
    result2,
    { trusted: false, valid: false },
    'should return trusted=false, valid=false if signature uses jku (and does NOT have JWK in its headers) to avoid pinging maliciously'
  );

  const sig3 = await sign(payload, privJwk, {
    header: {
      jwk: pubJwk,
    },
  });
  const result3 = await validate(sig3);
  t.like(
    result3,
    { trusted: false, valid: true },
    'should return trusted=false, valid=true if signature uses valid jwk'
  );
});

// --------------------------------------------------------------------
test('for valid trusted signature', async (t) => {
  const sig = await sign(payload, privJwk, {
    header: {
      kid: privJwk.kid,
      jku: TEST_ROOT,
    },
  });
  const result = await validate(sig);
  t.true(result.trusted);
  t.true(result.valid);
  t.deepEqual(result.payload, payload);
  t.assert(typeof result.header === 'object');
  t.is(result.header?.kid, privJwk.kid);
  t.is(result.header?.jku, TEST_ROOT);

  const pld = { key1: payload };
  const objectSig = await sign(pld, privJwk, {
    header: {
      kid: privJwk.kid,
      jku: TEST_ROOT,
    },
  });
  const objectResult = await validate(objectSig);
  t.deepEqual(
    objectResult.payload,
    pld,
    'should return a matching signature payload for an object payload'
  );
});

test('for customized set of trusted lists', async (t) => {
  const sig1 = await sign(payload, privJwk, {
    header: {
      kid: privJwk.kid,
      jku: TEST_ROOT, // This would be considered trusted if trusted list was available
    },
  });
  // Disable default trusted list, and don't supply any others:
  const result1 = await validate(sig1, {
    disableDefaultTrustedListURI: true,
  });
  t.like(
    result1,
    { trusted: false, valid: true },
    'should work for signature validation and be untrusted if no trusted lists exist: trusted is false and valid is true (because JWK is in header)'
  );

  const sig2 = await sign(payload, privJwk, {
    header: {
      kid: privJwk.kid,
      jku: TEST_ROOT, // This would be considered trusted if trusted list was available
    },
  });
  // Disable trusted list, and add a bad (down) trusted list:
  // t.timeout(2000);
  const result2 = await validate(sig2, {
    disableDefaultTrustedListURI: true,
    additionalTrustedListURIs: [
      'https://fakelist.is.down.and.never.will.return',
    ],
  });
  t.like(
    result2,
    { trusted: false, valid: true },
    'should work for customized trusted list that is down, returning false for trusted and true for valid (using JWK from header) because no public key can be found'
  );

  const sig3 = await sign(payload, privJwk, {
    header: {
      kid: privJwk.kid,
      jku: TEST_ROOT, // The new custom trusted list has this listed as trusted JKU
    },
  });
  // Disable default list, and use our custom one only:
  const result3 = await validate(sig3, {
    disableDefaultTrustedListURI: true,
    additionalTrustedListURIs: [CUSTOM_TRUSTED_LIST],
  });
  t.like(
    result3,
    { trusted: true, valid: true },
    'should work for customized trusted list that is up'
  );
});
