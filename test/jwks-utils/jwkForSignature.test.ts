/**
 * @license
 * Copyright 2014 Open Ag Data Alliance
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import test from 'ava';

import { JWS, JWK as jose_JWK } from 'node-jose';
import request from 'superagent';

import { JWK, jwkForSignature } from '../../dist/jwks-utils.js';

import jwkSet from '../jwk_set.js';
import jwkSetPriv from '../jwk_set_priv.js';
import server from '../setup.js';

let testServer: string;
let jku: string;
const [jwk, jwk2] = jwkSet.keys;
let key: JWK;

test.before(async () => {
  // Setup a couple of keys and a keystore to use:
  key = await jose_JWK.asKey(jwkSetPriv.keys[0]);
  testServer = `${await server}`;
  jku = `${testServer}/jwks_uri`;
});

const options = { format: 'compact' };

test('should work with "jwk" JOSE header', async (t) => {
  const sig = await JWS.createSign(
    // @ts-expect-error types are off
    options,
    { key, header: { jwk } }
  )
    .update('FOO BAR')
    .final();
  const result = await jwkForSignature(sig as unknown as string, false);
  t.deepEqual(result, jwk);
});

test('should NOT work with "jku" JOSE header if hint is false (untrusted)', async (t) => {
  const sig = await JWS.createSign(
    // @ts-expect-error types are off
    options,
    {
      key,
      header: {
        jku,
        kid: jwk.kid,
      },
    }
  )
    .update('FOO BAR')
    .final();

  await t.throwsAsync(jwkForSignature(sig as unknown as string, false));
});

test('should work with "jku" JOSE header if hint is a string and is the same as the jku header', async (t) => {
  const sig = await JWS.createSign(
    // @ts-expect-error types are off
    options,
    {
      key,
      header: {
        jku,
        kid: jwk.kid,
      },
    }
  )
    .update('FOO BAR')
    .final();
  const result = await jwkForSignature(sig as unknown as string, jku);
  t.deepEqual(result, jwk);
});

test('should by default use the hint string to fetch the jwks instead of the jku on the header if they do not match', async (t) => {
  const sig = await JWS.createSign(
    // @ts-expect-error types are off
    options,
    {
      key,
      header: {
        jku: `${testServer}/does_not_exist`,
        kid: jwk.kid,
      },
    }
  )
    .update('FOO BAR')
    .final();
  const result = await jwkForSignature(sig as unknown as string, jku);
  t.deepEqual(result, jwk);
});

test('should work with URI hint', async (t) => {
  const sig = await JWS.createSign(
    // @ts-expect-error types are off
    options,
    {
      key,
      header: {
        kid: jwk.kid,
      },
    }
  )
    .update('FOO BAR')
    .final();
  const result = await jwkForSignature(sig as unknown as string, jku);
  t.deepEqual(result, jwk);
});

test('should work with jwk hint', async (t) => {
  const sig = await JWS.createSign(
    // @ts-expect-error types are off
    options,
    {
      key,
      header: {
        kid: jwk.kid,
      },
    }
  )
    .update('FOO BAR')
    .final();
  const result = await jwkForSignature(sig as unknown as string, jwk);
  t.deepEqual(result, jwk);
});

test('should work with jwks hint', async (t) => {
  const sig = await JWS.createSign(
    // @ts-expect-error types are off
    options,
    {
      key,
      header: {
        kid: jwk.kid,
      },
    }
  )
    .update('FOO BAR')
    .final();
  const result = await jwkForSignature(sig as unknown as string, jwkSet);
  t.deepEqual(result, jwk);
});

test('should fail for invalid jwk/jwks hint', async (t) => {
  const sig = await JWS.createSign(
    // @ts-expect-error types are off
    options,
    {
      key,
      header: {
        kid: jwk.kid,
      },
    }
  )
    .update('FOO BAR')
    .final();
  await t.throwsAsync(
    jwkForSignature(
      sig as unknown as string,
      // @ts-expect-error intentionally wrong type
      {}
    )
  );
});

test('should fail for invalid hints', async (t) => {
  const sig = await JWS.createSign(
    // @ts-expect-error types are off
    options,
    { key }
  )
    .update('FOO BAR')
    .final();
  await t.throwsAsync(
    jwkForSignature(
      sig as unknown as string,
      // @ts-expect-error intentionally wrong type
      true
    )
  );
});

test('should fail when JWKS URI can not be parsed', async (t) => {
  const sig = await JWS.createSign(
    // @ts-expect-error types are off
    options,
    { key }
  )
    .update('FOO BAR')
    .final();
  await t.throwsAsync(
    jwkForSignature(sig as unknown as string, `${testServer}/jwks_uri_broken`)
  );
});

test('should fail when JWKS URI hosts an invalid JWK', async (t) => {
  const sig = await JWS.createSign(
    // @ts-expect-error types are off
    options,
    { key }
  )
    .update('FOO BAR')
    .final();
  await t.throwsAsync(
    jwkForSignature(sig as unknown as string, `${testServer}/jwks_uri_invalid`)
  );
});

test('should timeout', async (t) => {
  const sig = await JWS.createSign(
    // @ts-expect-error types are off
    options,
    {
      key,
      header: { kid: jwk.kid },
    }
  )
    .update('FOO BAR')
    .final();
  await t.throwsAsync(
    jwkForSignature(sig as unknown as string, `${testServer}/jwks_uri_slow`, {
      timeout: 1,
    })
  );
});

test('with both "jku" and "jwk" JOSE headers', async (t) => {
  const sig1 = await JWS.createSign(
    // @ts-expect-error types are off
    options,
    {
      key,
      header: {
        jku,
        kid: jwk.kid,
        jwk,
      },
    }
  )
    .update('FOO BAR')
    .final();
  const result1 = await jwkForSignature(sig1 as unknown as string, jku);
  t.deepEqual(result1, jwk, 'should work when they agree');

  const sig2 = await JWS.createSign(
    // @ts-expect-error types are off
    options,
    {
      key,
      header: {
        jku,
        kid: jwk.kid,
        jwk: jwk2,
      },
    }
  )
    .update('FOO BAR')
    .final();
  await t.throwsAsync(
    jwkForSignature(sig2 as unknown as string, jku),
    // FIXME: Check rejection reason
    undefined,
    'should error when they disagree'
  );
});

test('should work with jku from cache when jku fails after first get', async (t) => {
  const jkuThatDies = `${testServer}/jwks_uri_dies_after_first_request`;
  const resurrectJku = `${testServer}/reset_jwks_uri_dies_after_first_request`;
  await request.get(resurrectJku);
  const sig = await JWS.createSign(
    // @ts-expect-error types are off
    options,
    {
      key,
      header: {
        jku: jkuThatDies,
        kid: jwk.kid,
      },
    }
  )
    .update('FOO BAR')
    .final();

  // First request should be fine
  const key1 = await jwkForSignature(sig as unknown as string, jkuThatDies);
  t.deepEqual(key1, jwk);

  const key2 = await jwkForSignature(sig as unknown as string, jkuThatDies);
  t.deepEqual(key2, jwk);
});
